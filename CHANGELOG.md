# Changelog

Dates are UTC. One section per release, what changed and why, so a reader of the diff has the
sentence beside it.

## Unreleased

- `decode_name` follows at most `MAXIMUM_POINTERS` (127) compression pointers within one name and
  refuses a longer chain with the new `Error::TooManyPointers`. Before, a reply of the largest size
  a Transmission Control Protocol (TCP) frame can carry could make `Query::accept` spend about a
  second of processor time. That reply held a long chain of pointers and thousands of records that
  point into it. Now the first such name ends the read.

- Breaking: `Answer::ipv4_addresses` returns `&[core::net::Ipv4Addr]` rather than `&[[u8; 4]]`, so
  an address goes to a socket, or compares with one from another crate, as it stands.
  `Ipv4Addr::octets` gives the four bytes back.
- `Error` and `Reject` implement `Display` and `core::error::Error`, and `Reject::Malformed` gives
  its `Error` as the source, so a refusal prints for a log and `?` carries it into a boxed error.
- `Name` implements `Hash`, folding ASCII case as its equality does, so a name can key a cache.
- `Reader` and `TcpReply` implement `Debug`, printing positions and lengths rather than bytes, and
  `Question`, `Record` and `Query` implement `PartialEq` and `Eq`.
- The README's example compiles (it called a `ttl` method that does not exist) and runs as a
  doctest, the crate page carries an example of its own, and six more functions carry one.
- The package carries the source, the tests, the falsification patches, the README, this file and
  the licenses, and no longer the repository's workflows, hooks and settings. The manifest names
  its documentation.

## 0.1.0-pre.1

- First version.

## BUGS

- The template's lag check guards the CI pin, not this file; a change that matters to a user of
  the crate belongs in a release line here.
