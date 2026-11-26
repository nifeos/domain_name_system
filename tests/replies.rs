//! `Query::accept` against real replies and against the replies a forger or a broken server sends.
//!
//! The three `REAL_*` fixtures (`tests/fixtures/*.dns`, one raw reply each, which the crate's fuzz target also
//! takes as seeds) were captured on 2026-10-04 (UTC) from
//! 1.1.1.1 with a short Python script sending exactly the query `Query::request` writes (`tests/fixtures/README.md` has it and the id each carries), so they carry what a recursive
//! server really does: compression pointers into the question, a canonical name pointing into its own owner,
//! time to live values that differ along a chain. The rest are built by hand below, one per check, because nobody
//! captures a forgery.

use core::net::Ipv4Addr;

use domain_name_system::{
    CLASS_IN, Error, FLAG_TRUNCATED, Header, MAXIMUM_CHAIN, MAXIMUM_IPV4_ADDRESSES,
    MAXIMUM_POINTERS, Name, Query, Reader, Reject, TcpReply, canonical_name_target, decode_name,
    record_type,
};

/// `example.com` A, id 0x1111: two A records, owners compressed to the question.
const REAL_EXAMPLE: &[u8] = include_bytes!("fixtures/example.com.dns");
/// `www.github.com` A, id 0x2222: a canonical name to `github.com` (a pointer into the question's own name)
/// with `TTL` 1952, then github.com's A with `TTL` 33.
const REAL_GITHUB: &[u8] = include_bytes!("fixtures/www.github.com.dns");
/// `nosuch.invalid` A, id 0x3333: `NXDOMAIN`, no records.
const REAL_NXDOMAIN: &[u8] = include_bytes!("fixtures/nosuch.invalid.dns");

#[test]
fn a_real_reply_with_two_ipv4_addresses_gives_both_in_order() {
    let query = Query::new(0x1111, "example.com").unwrap();
    let answer = query.accept(REAL_EXAMPLE).unwrap();
    assert_eq!(
        answer.ipv4_addresses(),
        &[Ipv4Addr::new(104, 20, 23, 154), Ipv4Addr::new(172, 66, 147, 243)]
    );
    assert_eq!(answer.ttl_seconds(), 0x31);
    assert_eq!(
        answer.canonical(),
        &Name::from_dotted("example.com").unwrap()
    );
}

#[test]
fn a_real_canonical_name_is_followed_and_the_shortest_time_to_live_wins() {
    let query = Query::new(0x2222, "www.github.com").unwrap();
    let answer = query.accept(REAL_GITHUB).unwrap();
    assert_eq!(answer.ipv4_addresses(), &[Ipv4Addr::new(140, 82, 116, 3)]);
    assert_eq!(
        answer.canonical(),
        &Name::from_dotted("github.com").unwrap()
    );
    assert_eq!(
        answer.ttl_seconds(),
        33,
        "the A's 33 seconds, not the canonical name's 1952"
    );
}

#[test]
fn a_real_name_error_is_no_such_name() {
    let query = Query::new(0x3333, "nosuch.invalid").unwrap();
    assert_eq!(query.accept(REAL_NXDOMAIN), Err(Reject::NoSuchName));
}

#[test]
fn the_request_is_byte_for_byte_what_a_real_server_echoed() {
    // The server echoes header id and question verbatim, so our request must equal the reply's first
    // bytes with the reply's flags and counts put back to a query's.
    let reply = REAL_GITHUB;
    let query = Query::new(0x2222, "www.github.com").unwrap();
    let mut out = [0u8; 512];
    let n = query.request(&mut out).unwrap();
    let mut expected = reply[..n].to_vec();
    expected[2..4].copy_from_slice(&[0x01, 0x00]); // RD only
    expected[6..8].copy_from_slice(&[0, 0]); // no answers
    assert_eq!(&out[..n], &expected[..]);
}

// =================================================================================================
// A hand builder for the replies nobody captures.
// =================================================================================================

const OUR_ID: u16 = 0xbeef;
const OURS: &str = "packages.zone.test";

fn wire(name: &str) -> Vec<u8> {
    Name::from_dotted(name).unwrap().as_bytes().to_vec()
}

struct Reply {
    bytes: Vec<u8>,
}

impl Reply {
    /// A successful response to our query, no records yet.
    fn to(name: &str) -> Reply {
        let mut bytes = vec![0u8; 12];
        Header {
            id: OUR_ID,
            flags: 0x8180,
            question_count: 1,
            ..Header::default()
        }
        .write(&mut bytes)
        .unwrap();
        bytes.extend(wire(name));
        bytes.extend(record_type::IPV4_ADDRESS.to_be_bytes());
        bytes.extend(CLASS_IN.to_be_bytes());
        Reply { bytes }
    }

    fn header(&self) -> Header {
        Header::parse(&self.bytes).unwrap()
    }

    fn set_header(mut self, f: impl FnOnce(&mut Header)) -> Reply {
        let mut h = self.header();
        f(&mut h);
        h.write(&mut self.bytes).unwrap();
        self
    }

    fn record(
        mut self,
        owner: &[u8],
        record_type: u16,
        class: u16,
        ttl_seconds: u32,
        data: &[u8],
    ) -> Reply {
        self.bytes.extend(owner);
        self.bytes.extend(record_type.to_be_bytes());
        self.bytes.extend(class.to_be_bytes());
        self.bytes.extend(ttl_seconds.to_be_bytes());
        self.bytes.extend((data.len() as u16).to_be_bytes());
        self.bytes.extend(data);
        self.set_header(|h| h.answer_count += 1)
    }

    fn a(self, owner: &str, ipv4_address: [u8; 4]) -> Reply {
        self.record(
            &wire(owner),
            record_type::IPV4_ADDRESS,
            CLASS_IN,
            60,
            &ipv4_address,
        )
    }

    fn canonical_name(self, owner: &str, target: &str) -> Reply {
        self.record(
            &wire(owner),
            record_type::CANONICAL_NAME,
            CLASS_IN,
            60,
            &wire(target),
        )
    }

    fn judged(&self) -> Result<Vec<[u8; 4]>, Reject> {
        Query::new(OUR_ID, OURS)
            .unwrap()
            .accept(&self.bytes)
            .map(|a| a.ipv4_addresses().iter().map(Ipv4Addr::octets).collect())
    }
}

#[test]
fn the_hand_builder_agrees_with_the_real_replies() {
    assert_eq!(
        Reply::to(OURS).a(OURS, [10, 0, 2, 9]).judged(),
        Ok(vec![[10, 0, 2, 9]])
    );
}

#[test]
fn another_transaction_id_is_not_our_answer() {
    let r = Reply::to(OURS)
        .a(OURS, [10, 0, 2, 9])
        .set_header(|h| h.id ^= 0x0100);
    assert_eq!(r.judged(), Err(Reject::IdMismatch));
}

#[test]
fn a_query_or_another_opcode_is_not_a_response() {
    let query = Reply::to(OURS)
        .a(OURS, [10, 0, 2, 9])
        .set_header(|h| h.flags &= !0x8000);
    assert_eq!(query.judged(), Err(Reject::NotAResponse));
    let notify = Reply::to(OURS)
        .a(OURS, [10, 0, 2, 9])
        .set_header(|h| h.flags |= 4 << 11);
    assert_eq!(notify.judged(), Err(Reject::NotAResponse));
}

#[test]
fn a_truncated_reply_says_so_rather_than_answering_from_half() {
    let r = Reply::to(OURS)
        .a(OURS, [10, 0, 2, 9])
        .set_header(|h| h.flags |= FLAG_TRUNCATED);
    assert_eq!(r.judged(), Err(Reject::Truncated));
}

#[test]
fn a_reply_to_some_other_question_is_refused() {
    let other_name = Reply::to("mirror.zone.test").a("mirror.zone.test", [10, 0, 2, 9]);
    assert_eq!(other_name.judged(), Err(Reject::QuestionMismatch));

    let mut other_type = Reply::to(OURS).a(OURS, [10, 0, 2, 9]);
    let question_type_at = 12 + wire(OURS).len();
    other_type.bytes[question_type_at + 1] = 28; // AAAA
    assert_eq!(other_type.judged(), Err(Reject::QuestionMismatch));

    let mut other_class = Reply::to(OURS).a(OURS, [10, 0, 2, 9]);
    other_class.bytes[question_type_at + 3] = 3; // CHAOS
    assert_eq!(other_class.judged(), Err(Reject::QuestionMismatch));

    let two_questions = Reply::to(OURS).set_header(|h| h.question_count = 2);
    assert_eq!(two_questions.judged(), Err(Reject::QuestionMismatch));

    let no_question = Reply::to(OURS).set_header(|h| h.question_count = 0);
    assert_eq!(no_question.judged(), Err(Reject::QuestionMismatch));
}

#[test]
fn a_question_echoed_in_another_case_is_still_ours() {
    let r = Reply::to("Packages.ZONE.test").a("PACKAGES.zone.TEST", [10, 0, 2, 9]);
    assert_eq!(r.judged(), Ok(vec![[10, 0, 2, 9]]));
}

#[test]
fn response_codes_are_named_and_carried() {
    let servfail = Reply::to(OURS).set_header(|h| h.flags |= 2);
    assert_eq!(servfail.judged(), Err(Reject::ServerError(2)));
    let refused = Reply::to(OURS).set_header(|h| h.flags |= 5);
    assert_eq!(refused.judged(), Err(Reject::ServerError(5)));
    let nxdomain = Reply::to(OURS).set_header(|h| h.flags |= 3);
    assert_eq!(nxdomain.judged(), Err(Reject::NoSuchName));
    // A server that could not read the query at all may send back no question, only a code.
    let formerr = Reply::to(OURS).set_header(|h| {
        h.question_count = 0;
        h.flags |= 1;
    });
    assert_eq!(formerr.judged(), Err(Reject::ServerError(1)));
    let header = formerr.header();
    assert_eq!(header.response_code(), 1);
}

#[test]
fn an_ipv4_address_for_another_name_is_never_taken() {
    // The cache-poisoning shape: a reply about our name that also "helpfully" carries an address
    // for somebody else's. Only ours comes out, and a reply carrying only theirs gives nothing.
    let mixed = Reply::to(OURS)
        .a("bank.test", [6, 6, 6, 6])
        .a(OURS, [10, 0, 2, 9]);
    assert_eq!(mixed.judged(), Ok(vec![[10, 0, 2, 9]]));
    let theirs_only = Reply::to(OURS).a("bank.test", [6, 6, 6, 6]);
    assert_eq!(theirs_only.judged(), Err(Reject::NoIpv4Address));
}

#[test]
fn an_empty_answer_section_is_no_ipv4_address() {
    assert_eq!(Reply::to(OURS).judged(), Err(Reject::NoIpv4Address));
}

#[test]
fn a_chain_is_followed_in_any_order_and_only_from_our_name() {
    // Records out of order, as some servers send them, and a stray canonical name for a name not on the chain.
    let r = Reply::to(OURS)
        .a("origin.zone.test", [10, 0, 2, 9])
        .canonical_name("cdn.zone.test", "origin.zone.test")
        .canonical_name("elsewhere.test", "bank.test")
        .a("bank.test", [6, 6, 6, 6])
        .canonical_name(OURS, "cdn.zone.test");
    let answer = Query::new(OUR_ID, OURS).unwrap().accept(&r.bytes).unwrap();
    assert_eq!(answer.ipv4_addresses(), &[Ipv4Addr::new(10, 0, 2, 9)]);
    assert_eq!(
        answer.canonical(),
        &Name::from_dotted("origin.zone.test").unwrap()
    );
}

#[test]
fn an_ipv4_address_for_our_name_beside_its_canonical_name_is_not_taken() {
    // A name with a canonical name has no other data (RFC 1034 section 3.6.2), so the chain's end is what counts.
    let r = Reply::to(OURS)
        .a(OURS, [6, 6, 6, 6])
        .canonical_name(OURS, "origin.zone.test")
        .a("origin.zone.test", [10, 0, 2, 9]);
    assert_eq!(r.judged(), Ok(vec![[10, 0, 2, 9]]));
}

#[test]
fn a_canonical_name_loop_stops_at_the_chain_limit() {
    let r = Reply::to(OURS)
        .canonical_name(OURS, "b.zone.test")
        .canonical_name("b.zone.test", OURS);
    assert_eq!(r.judged(), Err(Reject::ChainTooLong));
}

#[test]
fn the_chain_limit_is_exactly_maximum_chain_links() {
    let names: Vec<String> = (0..=MAXIMUM_CHAIN + 1)
        .map(|i| {
            if i == 0 {
                OURS.to_string()
            } else {
                format!("hop{i}.zone.test")
            }
        })
        .collect();
    let chain = |links: usize| {
        let mut r = Reply::to(OURS);
        for i in 0..links {
            r = r.canonical_name(&names[i], &names[i + 1]);
        }
        r.a(&names[links], [10, 0, 2, 9])
    };
    assert_eq!(chain(MAXIMUM_CHAIN).judged(), Ok(vec![[10, 0, 2, 9]]));
    assert_eq!(chain(MAXIMUM_CHAIN + 1).judged(), Err(Reject::ChainTooLong));
}

#[test]
fn records_in_another_class_are_ignored() {
    let r = Reply::to(OURS)
        .record(&wire(OURS), record_type::IPV4_ADDRESS, 3, 60, &[6, 6, 6, 6])
        .record(
            &wire(OURS),
            record_type::CANONICAL_NAME,
            3,
            60,
            &wire("bank.test"),
        )
        .a(OURS, [10, 0, 2, 9]);
    assert_eq!(r.judged(), Ok(vec![[10, 0, 2, 9]]));
}

#[test]
fn other_record_types_are_ignored() {
    let r = Reply::to(OURS)
        .record(&wire(OURS), 16, CLASS_IN, 60, b"\x05hello")
        .a(OURS, [10, 0, 2, 9]);
    assert_eq!(r.judged(), Ok(vec![[10, 0, 2, 9]]));
}

#[test]
fn ipv4_addresses_past_the_limit_are_dropped_and_the_rest_kept() {
    let mut r = Reply::to(OURS);
    for i in 0..(MAXIMUM_IPV4_ADDRESSES as u8 + 2) {
        r = r.a(OURS, [10, 0, 2, i]);
    }
    let got = r.judged().unwrap();
    assert_eq!(got.len(), MAXIMUM_IPV4_ADDRESSES);
    assert_eq!(
        got[MAXIMUM_IPV4_ADDRESSES - 1],
        [10, 0, 2, MAXIMUM_IPV4_ADDRESSES as u8 - 1]
    );
}

/// `RFC 2181` section 8: a `TTL` with its most significant bit set is read as zero. An answer is good
/// for the shortest of its records' lifetimes, so one such record on the chain or among the
/// addresses makes the whole answer good for no time at all, rather than for about 136 years.
#[test]
fn a_time_to_live_with_the_high_bit_set_is_zero() {
    for high in [0x8000_0000u32, 0xffff_ffff] {
        let ipv4_address_only = Reply::to(OURS)
            .record(
                &wire(OURS),
                record_type::IPV4_ADDRESS,
                CLASS_IN,
                high,
                &[10, 0, 2, 9],
            )
            .bytes;
        let answer = Query::new(OUR_ID, OURS)
            .unwrap()
            .accept(&ipv4_address_only)
            .unwrap();
        assert_eq!(answer.ttl_seconds(), 0, "{high:#x} on the address");

        let on_the_chain = Reply::to(OURS)
            .record(
                &wire(OURS),
                record_type::CANONICAL_NAME,
                CLASS_IN,
                high,
                &wire("o.zone.test"),
            )
            .record(
                &wire("o.zone.test"),
                record_type::IPV4_ADDRESS,
                CLASS_IN,
                300,
                &[10, 0, 2, 9],
            )
            .bytes;
        let answer = Query::new(OUR_ID, OURS)
            .unwrap()
            .accept(&on_the_chain)
            .unwrap();
        assert_eq!(answer.ttl_seconds(), 0, "{high:#x} on the canonical name");
    }

    // The control: the largest TTL with the bit clear is believed as written.
    let largest = Reply::to(OURS)
        .record(
            &wire(OURS),
            record_type::IPV4_ADDRESS,
            CLASS_IN,
            0x7fff_ffff,
            &[10, 0, 2, 9],
        )
        .bytes;
    let answer = Query::new(OUR_ID, OURS).unwrap().accept(&largest).unwrap();
    assert_eq!(answer.ttl_seconds(), 0x7fff_ffff);
}

#[test]
fn the_time_to_live_is_the_smallest_on_the_chain_and_among_the_ipv4_addresses() {
    let r = Reply::to(OURS)
        .record(
            &wire(OURS),
            record_type::CANONICAL_NAME,
            CLASS_IN,
            500,
            &wire("o.zone.test"),
        )
        .record(
            &wire("o.zone.test"),
            record_type::IPV4_ADDRESS,
            CLASS_IN,
            90,
            &[10, 0, 2, 9],
        )
        .record(
            &wire("o.zone.test"),
            record_type::IPV4_ADDRESS,
            CLASS_IN,
            70,
            &[10, 0, 2, 8],
        );
    let answer = Query::new(OUR_ID, OURS).unwrap().accept(&r.bytes).unwrap();
    assert_eq!(answer.ttl_seconds(), 70);
    let short_chain = Reply::to(OURS)
        .record(
            &wire(OURS),
            record_type::CANONICAL_NAME,
            CLASS_IN,
            5,
            &wire("o.zone.test"),
        )
        .record(
            &wire("o.zone.test"),
            record_type::IPV4_ADDRESS,
            CLASS_IN,
            90,
            &[10, 0, 2, 9],
        );
    let answer = Query::new(OUR_ID, OURS)
        .unwrap()
        .accept(&short_chain.bytes)
        .unwrap();
    assert_eq!(answer.ttl_seconds(), 5);
}

#[test]
fn one_malformed_answer_refuses_the_whole_reply() {
    let long_a = Reply::to(OURS).a(OURS, [10, 0, 2, 9]).record(
        &wire(OURS),
        record_type::IPV4_ADDRESS,
        CLASS_IN,
        60,
        &[1, 2, 3, 4, 5],
    );
    assert_eq!(
        long_a.judged(),
        Err(Reject::Malformed(Error::BadRecordData))
    );

    // A canonical name whose name runs past its own record's data.
    let mut spill = wire("o.zone.test");
    spill.truncate(3);
    let spilling = Reply::to(OURS).a(OURS, [10, 0, 2, 9]).record(
        &wire("x.test"),
        record_type::CANONICAL_NAME,
        CLASS_IN,
        60,
        &spill,
    );
    assert!(matches!(spilling.judged(), Err(Reject::Malformed(_))));

    // An answer count that promises one more record than the bytes hold.
    let short = Reply::to(OURS)
        .a(OURS, [10, 0, 2, 9])
        .set_header(|h| h.answer_count += 1);
    assert_eq!(short.judged(), Err(Reject::Malformed(Error::Truncated)));
}

#[test]
fn a_pointer_loop_in_an_answer_is_malformed_not_a_hang() {
    // The owner is a pointer to itself.
    let at = Reply::to(OURS).bytes.len() as u16;
    let pointer = (0xc000 | at).to_be_bytes();
    let r = Reply::to(OURS).record(
        &pointer,
        record_type::IPV4_ADDRESS,
        CLASS_IN,
        60,
        &[10, 0, 2, 9],
    );
    assert_eq!(r.judged(), Err(Reject::Malformed(Error::PointerForward)));
}

#[test]
fn a_reply_shorter_than_a_header_is_malformed() {
    let q = Query::new(OUR_ID, OURS).unwrap();
    assert_eq!(q.accept(&[0xbe]), Err(Reject::Malformed(Error::Truncated)));
    let mut cut = Reply::to(OURS).bytes;
    cut.truncate(14);
    assert_eq!(q.accept(&cut), Err(Reject::Malformed(Error::Truncated)));
}

// =================================================================================================
// Names.
// =================================================================================================

#[test]
fn dotted_names_encode_and_refuse() {
    assert_eq!(Name::from_dotted("").unwrap().as_bytes(), b"\0");
    assert_eq!(Name::from_dotted(".").unwrap(), Name::root());
    assert_eq!(
        Name::from_dotted("a-b_c.d9").unwrap().as_bytes(),
        b"\x05a-b_c\x02d9\0"
    );
    let label63 = "a".repeat(63);
    assert!(Name::from_dotted(&label63).is_ok());
    assert_eq!(Name::from_dotted(&"a".repeat(64)), Err(Error::LabelTooLong));
    assert_eq!(Name::from_dotted(".zone"), Err(Error::BadLabel));
    assert_eq!(Name::from_dotted("zone.."), Err(Error::BadLabel));
    assert_eq!(Name::from_dotted("ni/fe"), Err(Error::BadCharacter));
    assert_eq!(Name::from_dotted("nifé"), Err(Error::BadCharacter));

    // 255 bytes in wire form is the most there is: four 63-byte labels and the root is 257.
    let fits = format!("{l}.{l}.{l}.{}", "a".repeat(61), l = label63);
    assert_eq!(Name::from_dotted(&fits).unwrap().as_bytes().len(), 255);
    let over = format!("{l}.{l}.{l}.{}", "a".repeat(62), l = label63);
    assert_eq!(Name::from_dotted(&over), Err(Error::NameTooLong));
}

#[test]
fn a_name_prints_dotted_and_escapes_what_is_not_text() {
    assert_eq!(
        format!("{:?}", Name::from_dotted("zone.test").unwrap()),
        "zone.test"
    );
    assert_eq!(format!("{:?}", Name::root()), ".");
    let (odd, _) = decode_name(b"\x03a.b\x00", 0).unwrap();
    assert_eq!(format!("{odd:?}"), "a\\046b");
}

#[test]
fn within_is_label_by_label() {
    let zone = Name::from_dotted("zone.test").unwrap();
    let n = |s| Name::from_dotted(s).unwrap();
    assert!(n("zone.test").is_within(&zone));
    assert!(n("a.b.ZONE.TEST").is_within(&zone));
    assert!(!n("evilzone.test").is_within(&zone));
    assert!(!n("test").is_within(&zone));
    assert!(!n("zone.test.evil").is_within(&zone));
    assert!(!n("x.zone.text").is_within(&zone));
    assert!(n("anything.at.all").is_within(&Name::root()));
    assert!(!Name::root().is_within(&zone));
}

#[test]
fn the_name_decoder_resumes_after_the_first_pointer() {
    // "zone" at 0, then "a" + pointer to 0 at 6.
    let message = b"\x04zone\x00\x01a\xc0\x00";
    let (name, resume) = decode_name(message, 6).unwrap();
    assert_eq!(name, Name::from_dotted("a.zone").unwrap());
    assert_eq!(resume, message.len());
    let (_, resume) = decode_name(message, 0).unwrap();
    assert_eq!(resume, 6);
}

#[test]
fn the_name_decoder_refuses_what_is_not_a_name() {
    assert_eq!(
        decode_name(b"\xc0\x00", 0).err(),
        Some(Error::PointerForward)
    );
    assert_eq!(
        decode_name(b"\x00\xc0\x02", 1).err(),
        Some(Error::PointerForward)
    );
    assert_eq!(decode_name(b"\x40", 0).err(), Some(Error::BadLabel));
    assert_eq!(decode_name(b"\x80", 0).err(), Some(Error::BadLabel));
    assert_eq!(decode_name(b"\x05ab", 0).err(), Some(Error::Truncated));
    assert_eq!(decode_name(b"\xc0", 0).err(), Some(Error::Truncated));
    assert_eq!(decode_name(b"", 0).err(), Some(Error::Truncated));
}

#[test]
fn a_name_longer_than_255_by_pointers_is_refused() {
    // Each 63-byte label points back at the one before; five of them decode past 255 bytes.
    let mut message = vec![0u8];
    let mut previous = 0u16;
    for _ in 0..5 {
        let here = message.len() as u16;
        message.push(63);
        message.extend([b'a'; 63]);
        message.extend((0xc000 | previous).to_be_bytes());
        previous = here;
    }
    assert_eq!(
        decode_name(&message, previous as usize).err(),
        Some(Error::NameTooLong)
    );
}

#[test]
fn a_canonical_name_target_reads_through_the_message() {
    let reply = REAL_GITHUB;
    let mut reader = Reader::new(reply).unwrap();
    reader.question().unwrap();
    let record = reader.record().unwrap();
    assert_eq!(record.record_type, record_type::CANONICAL_NAME);
    assert_eq!(record.ttl_seconds, 1952);
    assert_eq!(
        canonical_name_target(reply, &record).unwrap(),
        Name::from_dotted("github.com").unwrap()
    );
}

// =================================================================================================
// Building, and TCP.
// =================================================================================================

#[test]
fn a_buffer_too_small_is_overflow_not_a_panic() {
    let q = Query::new(1, "zone.test").unwrap();
    let mut small = [0u8; 20];
    assert_eq!(q.request(&mut small), Err(Error::Overflow));
    assert_eq!(q.request_tcp(&mut small[..1]), Err(Error::Overflow));
    assert_eq!(q.request_tcp(&mut small), Err(Error::Overflow));
    assert_eq!(
        Header::default().write(&mut small[..11]),
        Err(Error::Overflow)
    );
    let mut exact = [0u8; 12 + 11 + 4];
    assert_eq!(q.request(&mut exact), Ok(27));
    assert_eq!(q.id(), 1);
    assert_eq!(q.name(), &Name::from_dotted("zone.test").unwrap());
}

#[test]
fn the_tcp_request_is_the_udp_request_with_its_length_in_front() {
    let q = Query::new(0x0102, "zone.test").unwrap();
    let mut udp = [0u8; 512];
    let n = q.request(&mut udp).unwrap();
    let mut tcp = [0u8; 514];
    let m = q.request_tcp(&mut tcp).unwrap();
    assert_eq!(m, n + 2);
    assert_eq!(&tcp[..2], &(n as u16).to_be_bytes());
    assert_eq!(&tcp[2..m], &udp[..n]);
}

#[test]
fn a_tcp_reply_reassembles_a_byte_at_a_time() {
    let real = REAL_EXAMPLE.to_vec();
    let mut framed = (real.len() as u16).to_be_bytes().to_vec();
    framed.extend(&real);
    let mut buffer = [0u8; 600];
    let mut reply = TcpReply::new(&mut buffer);
    for (i, b) in framed.iter().enumerate() {
        assert_eq!(reply.message(), None);
        assert_eq!(reply.feed(&[*b]), Ok(i == framed.len() - 1));
    }
    assert_eq!(reply.message(), Some(&real[..]));
    assert_eq!(reply.feed(&[]), Ok(true));
    assert_eq!(reply.feed(&[0]), Err(Error::Trailing));
}

#[test]
fn a_tcp_reply_refuses_more_than_it_holds_and_more_than_it_announced() {
    let mut buffer = [0u8; 8];
    let mut reply = TcpReply::new(&mut buffer);
    assert_eq!(reply.feed(&[0, 7]), Err(Error::Overflow));

    let mut buffer = [0u8; 8];
    let mut reply = TcpReply::new(&mut buffer);
    assert_eq!(reply.feed(&[0, 2, 9, 9, 9]), Err(Error::Trailing));

    let mut buffer = [0u8; 8];
    let mut reply = TcpReply::new(&mut buffer);
    assert_eq!(reply.feed(&[0, 0]), Ok(true));
    assert_eq!(reply.message(), Some(&[][..]));

    let mut tiny = [0u8; 1];
    let mut reply = TcpReply::new(&mut tiny);
    assert_eq!(reply.feed(&[0]), Ok(false));
    assert_eq!(reply.feed(&[0]), Err(Error::Overflow));

    let mut buffer = [0u8; 8];
    let mut reply = TcpReply::new(&mut buffer);
    assert_eq!(reply.feed(&[0, 6, 1, 2, 3, 4, 5, 6]), Ok(true));
}

/// A length prefix announcing more than the buffer holds is refused even when the body arrives in
/// the same piece as the prefix, before any of it is copied.
#[test]
fn an_oversized_tcp_reply_is_refused_when_its_body_comes_with_its_length() {
    let mut buffer = [0u8; 8];
    let mut reply = TcpReply::new(&mut buffer);
    let mut piece = vec![0, 16];
    piece.extend(1..=10);
    assert_eq!(reply.feed(&piece), Err(Error::Overflow));
}

/// A record's `TTL` is two 16-bit halves on the wire, high half first; one past 65,535 seconds
/// needs both.
#[test]
fn a_time_to_live_wider_than_sixteen_bits_reads_whole() {
    let bytes = Reply::to("zone.test")
        .record(
            &wire("zone.test"),
            record_type::IPV4_ADDRESS,
            CLASS_IN,
            0x0001_0002,
            &[10, 0, 0, 1],
        )
        .bytes;
    let mut reader = Reader::new(&bytes).unwrap();
    reader.question().unwrap();
    assert_eq!(reader.record().unwrap().ttl_seconds, 0x0001_0002);
}

/// A compression pointer is fourteen bits, so a target past offset 255 uses the high six.
#[test]
fn a_pointer_past_offset_255_reaches_its_target() {
    let mut message = vec![0u8; 300];
    message.extend(wire("zone.test"));
    let at = message.len();
    message.extend((0xc000u16 | 300).to_be_bytes());
    assert_eq!(
        decode_name(&message, at).unwrap().0,
        Name::from_dotted("zone.test").unwrap()
    );
}

/// Labels that fill the 255 bytes exactly are read in full; the name fails at its missing end,
/// as truncated, and only a label past the limit is too long.
#[test]
fn labels_that_fill_the_limit_exactly_are_not_too_long() {
    let mut message = Vec::new();
    for len in [63u8, 63, 63, 62] {
        message.push(len);
        message.extend(vec![b'a'; len as usize]);
    }
    assert_eq!(decode_name(&message, 0).err(), Some(Error::Truncated));
}

#[test]
fn a_query_keeps_its_transaction_id() {
    assert_eq!(Query::new(0x1234, "zone.test").unwrap().id(), 0x1234);
}

#[test]
fn a_name_prints_and_parses_as_its_dotted_form() {
    let name: Name = "packages.example.test".parse().unwrap();
    assert_eq!(name, Name::from_dotted("Packages.Example.TEST.").unwrap());
    assert_eq!(format!("{name}"), "packages.example.test");
    assert_eq!(format!("{name:?}"), "packages.example.test");
    assert_eq!(format!("{}", Name::root()), ".");
    assert_eq!("a b".parse::<Name>(), Err(Error::BadCharacter));
}

#[test]
fn the_sizes_the_crate_documents_are_the_sizes_it_has() {
    use core::mem::size_of;

    use domain_name_system::Answer;
    assert_eq!(size_of::<Name>(), 256);
    assert_eq!(size_of::<Answer>(), 296);
    assert_eq!(size_of::<Result<Answer, Reject>>(), 300);
}

// =================================================================================================
// The bound on compression pointers per name.
// =================================================================================================

/// A message of `hops` pointers in a row, each naming the one before it, the first naming `OURS` in
/// the question. Returns the message and the offset of the last pointer.
fn pointer_chain(hops: usize) -> (Vec<u8>, usize) {
    let mut message = Reply::to(OURS).bytes;
    let mut previous = 12; // the question's name
    let mut last = 0;
    for _ in 0..hops {
        last = message.len();
        message.extend([0xc0 | (previous >> 8) as u8, previous as u8]);
        previous = last;
    }
    (message, last)
}

#[test]
fn a_chain_of_exactly_maximum_pointers_decodes_and_one_more_is_refused() {
    let (message, last) = pointer_chain(MAXIMUM_POINTERS);
    let (name, resume) = decode_name(&message, last).unwrap();
    assert_eq!(name, Name::from_dotted(OURS).unwrap());
    assert_eq!(resume, last + 2);

    let (message, last) = pointer_chain(MAXIMUM_POINTERS + 1);
    assert_eq!(decode_name(&message, last), Err(Error::TooManyPointers));
}

#[test]
fn a_longest_legal_name_built_by_compression_one_label_at_a_time_still_decodes() {
    // 127 one-byte labels is the longest name there is (255 bytes on the wire). Each name is one
    // label and a pointer to the name before it, so the last one follows 126 pointers, the most an
    // encoder that compresses every suffix can produce.
    let mut message = vec![0u8; 12];
    let mut previous = None;
    let mut starts = Vec::new();
    for _ in 0..127 {
        let start = message.len();
        starts.push(start);
        message.extend([1, b'a']);
        match previous {
            Some(p) => message.extend([0xc0 | (p >> 8) as u8, p as u8]),
            None => message.push(0),
        }
        previous = Some(start);
    }
    let (name, resume) = decode_name(&message, *starts.last().unwrap()).unwrap();
    assert_eq!(name.as_bytes().len(), 255);
    assert!(name.as_bytes().chunks(2).take(127).all(|c| c == [1, b'a']));
    assert_eq!(resume, message.len());
}

#[test]
fn a_maximum_size_reply_built_on_a_long_pointer_chain_is_refused_at_the_chain() {
    // A TCP reply at the 65,535-byte limit: a record whose data is a long chain of pointers (the
    // data is ignored as a type this crate does not read, but its bytes are in the message), then
    // thousands of A records whose owners point at the end of that chain, then two canonical names.
    let chain_hops = 8000;
    let mut reply = Reply::to(OURS);
    let data_start = reply.bytes.len() + 2 + 2 + 2 + 4 + 2; // owner, type, class, ttl, length
    let mut data = Vec::new();
    let mut previous = 12;
    let mut last = 0;
    for i in 0..chain_hops {
        last = data_start + 2 * i;
        data.extend([0xc0 | (previous >> 8) as u8, previous as u8]);
        previous = last;
    }
    assert!(
        last < 0x4000,
        "a pointer cannot name an offset past 14 bits"
    );
    let owner = [0xc0 | (last >> 8) as u8, last as u8];
    reply = reply.record(&[0xc0, 12], 16, CLASS_IN, 60, &data);
    reply = reply.canonical_name(OURS, "b.zone.test");
    reply = reply.canonical_name("b.zone.test", "c.zone.test");
    while reply.bytes.len() + 16 <= 65_535 {
        reply = reply.record(
            &owner,
            record_type::IPV4_ADDRESS,
            CLASS_IN,
            60,
            &[10, 0, 2, 9],
        );
    }
    assert!(reply.bytes.len() > 65_000);
    assert_eq!(
        reply.judged(),
        Err(Reject::Malformed(Error::TooManyPointers))
    );
}
