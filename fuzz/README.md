# Fuzz targets of `domain_name_system`

The targets use cargo-fuzz and need a nightly toolchain. From the repository root:

```sh
cargo install --locked cargo-fuzz
cargo +nightly fuzz list
cargo +nightly fuzz build
```

The weekly workflow runs every target for five minutes. To run one by hand, give libFuzzer a scratch directory first, so that what it finds does not land among the committed inputs:

```sh
mkdir -p "$TMPDIR/work"
cargo +nightly fuzz run <target> "$TMPDIR/work" corpus/<target>
```

Each `corpus/<target>` directory holds the inputs a run starts from. A crash input is not committed: it becomes a regression test in the crate, beside the code it broke.

`corpus/domain_name_system_reply` also holds copies of the inputs in `tests/fixtures`.

## `domain_name_system_reply`

The real captures in `tests/fixtures` seed the target unmodified, and the fuzz run passes that
directory read-only, as it passes every seed directory.
