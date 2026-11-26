# Changelog

Dates are UTC. One section per release, what changed and why, so a reader of the diff has the
sentence beside it.

## Unreleased

- `decode_name` follows at most `MAXIMUM_POINTERS` (127) compression pointers within one name and
  refuses a longer chain with the new `Error::TooManyPointers`. Before, a maximum-size TCP reply
  made of a long chain of pointers and thousands of records that point into it cost about a second
  of CPU in `Query::accept`; now it is refused at its first such name.

## 0.1.0-pre.1

- First version.

## BUGS

- The template's lag check guards the CI pin, not this file; a change that matters to a user of
  the crate belongs in a release line here.
