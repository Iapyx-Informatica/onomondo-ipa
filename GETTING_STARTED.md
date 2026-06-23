# Getting started — onomondo-ipa (SGP.32 v1.2 port)

This is a fork of [onomondo/onomondo-ipa](https://github.com/onomondo/onomondo-ipa)
with an in-progress port from SGP.32 v1.0 to **v1.2**.  The build works
end-to-end and the existing test suite passes; see [MIGRATION_STATUS.md](MIGRATION_STATUS.md)
for the full state.

## Quick build — one command, needs only Docker

```bash
./scripts/build.sh --docker
```

That's it.  It will:

1. Build an `ubuntu:24.04` image containing `asn1c`, `cmake`, `libcurl`,
   `libpcsclite` (about 1 minute first time, cached thereafter).
2. Regenerate `src/ipa/libasn/*.{c,h}` from the updated `asn1/*.asn`.
3. Compile the project and run `ctest`.  Expect **7/7 tests to pass**.

After the build completes, extract the compiled artefacts back to the host:

```bash
docker run --rm -v "$(pwd):/host" onomondo-ipa:v1.2 \
  cp -r /src/build /host/build-docker
```

The binary is at `build-docker/src/ipa/ipa`.

## Native build — Linux with `asn1c` 0.9.28+ and the usual deps

On Debian/Ubuntu:

```bash
sudo apt install asn1c build-essential cmake libcurl4-gnutls-dev libpcsclite-dev
./scripts/build.sh
```

The wrapper falls back to an ephemeral Docker container if `asn1c` is not in
PATH (requires a running Docker daemon).

## Smoke tests

```bash
./build/src/ipa/ipa -h        # prints usage
(cd build && ctest --output-on-failure)
```

## Running against a real eIM / eUICC

This implementation is a working IPAd — it polls an eIM over HTTPS and talks
to an eUICC via PC/SC.  Typical setup on Linux:

```bash
# 1. Plug a PC/SC reader with your IoT eUICC in.  Confirm it shows up:
pcsc_scan

# 2. Load initial eIM configuration once (per eUICC):
./build/src/ipa/ipa -r <reader_num> -f contrib/sample_eim_cfg.ber

# 3. Poll the eIM for pending packages:
./build/src/ipa/ipa -r <reader_num>
```

For testing against a consumer eUICC (not an IoT eUICC) add `-E` to enable
emulation mode.  **Note**: `-E` against a strict v1.2 eIM may fail because
the consumer-emulation signing-input change (§2.11.2.1) is still a TODO —
see [MIGRATION_STATUS.md](MIGRATION_STATUS.md).

## What changed from v1.0

See:
- [MIGRATION.md](MIGRATION.md) — CR-by-CR checklist.
- [MIGRATION_STATUS.md](MIGRATION_STATUS.md) — current build state + what's
  implemented vs. still TODO.
- Inline markers in every touched file: grep for
  `UPDATE for v1.1:`, `UPDATE for v1.2:`, `NEW in v1.1/v1.2:`,
  `TODO v1.1:`, `TODO v1.2:`.

## Questions / feedback

If something doesn't work, it's most useful to know which of the TODOs in
[MIGRATION_STATUS.md](MIGRATION_STATUS.md) actually bite your deployment.
The highest-risk items today are:

1. Does your eIM enforce v1.2 strictly (rejecting if `eidValue` is missing,
   etc.)?
2. Does it exercise Fallback / Emergency Profile flows (§5.9.20–23)?
3. Are you using `-E` (consumer-eUICC emulation)?

A short write-up of what works / what doesn't against your eIM would be
hugely valuable for closing the remaining TODOs.
