# Changelog

Dates are UTC. One section per release, what changed and why, so a reader of the diff has the
sentence beside it.

## Unreleased

- `decode_name` follows at most `MAXIMUM_POINTERS` (127) compression pointers within one name and
  refuses a longer chain with the new `Error::TooManyPointers`. Before, a reply of the largest size
  a Transmission Control Protocol (TCP) frame can carry could make `Query::accept` spend about a
  second of processor time. That reply held a long chain of pointers and thousands of records that
  point into it. Now the first such name ends the read.

## 0.1.0-pre.1

- First version.

## BUGS

- The template's lag check guards the CI pin, not this file; a change that matters to a user of
  the crate belongs in a release line here.
