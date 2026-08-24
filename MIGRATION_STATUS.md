# Build and verification status

Current state of the tree. For what the SGP.32 v1.0 → v1.2 migration changed and
what remains, see [MIGRATION.md](MIGRATION.md).

## Build

```sh
cmake -S . -B build
cmake --build build --parallel
```

CMake owns libasn generation: [`asn1/gen_libasn.sh`](asn1/gen_libasn.sh) runs
asn1c into the build tree during configure, and again only when a schema or the
generator changes. It produces 970 files, detects `-no-gen-example` /
`-no-gen-XER` / `-no-gen-print` where the installed asn1c offers them, trims the
unused codecs by hand on 0.9.28 where it does not, renames PKIX `Time.{c,h}` to
`PKIX_Time.{c,h}` to dodge the system `<time.h>` collision, normalises
`Psmo.Delete` to `Psmo.delete` across asn1c versions, and applies the
`asn_internal` patch that routes the codec through the `IPA_*` allocators. Only
content-changed files are copied out, so an unrelated schema edit does not
rebuild the whole codec.

Dependencies: `asn1c`, `cmake`, `libcurl4-openssl-dev`, `libssl-dev`,
`libpcsclite-dev`, and `libjansson-dev` + `pkg-config` for the ESipa JSON
binding. See README for the full list and for the build options.

## Test matrix

All four configurations build with **zero compiler warnings** and pass:

| Configuration              | Tests |
|----------------------------|-------|
| default                    | 17/17 |
| `-DESIPA_BINDING_JSON=OFF` | 17/17 |
| `-DESIPA_BINDING_ASN1=OFF` | 17/17 |
| `-DIOT_EUICC_EMULATION=ON` | 18/18 |

The emulation build adds `euicc_emu_test`, which drives the IoT eUICC emulation
paths through the real stack against the fake eUICC in `tests/stubs`. That stub
sits at the smartcard interface and speaks the ES10x carrier of SGP.22 §5.7.2 for
real, so nothing in libipa is overridden — which matters for these paths, since
most of what they do is libipa translating between the SGP.32 and SGP.22 forms of
the same function.

## Verification

- [x] `cmake -S . -B build` configures and generates libasn via asn1c
- [x] `cmake --build build` succeeds, 22 targets, no warnings
- [x] `ctest` passes in all four configurations above
- [x] `ipa -h` prints usage
- [x] Interop against a production eIM (GetEimPackage → AuthenticateClient →
      ProvideEimPackageResult roundtrip)
- [x] Real-device PCSC test with `-E` off (IoT eUICC)
- [ ] Consumer-eUICC emulation against a production eIM with `-E` on. Expected to
      fail on eUICC Package Results: the emulation cannot sign them, see
      MIGRATION.md, "IoT eUICC emulation limits". Profile download and its
      notifications are unaffected, being signed by the eUICC itself.

## Code-review hardening

A review pass over `libipa` and the platform modules landed a batch of fixes
independent of the spec migration:

- **Correctness:** `IpaCapabilities` / `ipaSupportedProtocols` pack named bits
  with `bits_unused` set; the indirect-download procedure returns a real error
  code instead of always 0; `dec_get_bnd_prfle_pkg_res` reads the correct CHOICE
  member; the `0x7F` BER length octet parses as short form; `parse_btlv_hdr` has
  a signed return so its error guard works.
- **Robustness:** curl global init/cleanup is refcounted; connect and total HTTP
  timeouts are split and configurable, with opt-in retry backoff (0 retries by
  default, so no blocking `sleep`); `IPA_BUF_STATIC` uses token-paste and is
  reusable within one scope; CLI path building, `fopen` and length handling are
  bounds-checked rather than `strcpy` + `assert`; `ipa_str_from_num` returns the
  default for the sentinel value.
- **Redundancy:** the ESipa boilerplate is factored into `ipa_esipa_call()`; the
  `bpp_segments` encoders are parameterised by `asn_TYPE_descriptor_t *`.
- **Left as designed:** the single-context static-return storage and the
  same-host nvstate `memcpy` are sound under the current single-context and
  same-host assumptions. The memory-reset dual encode paths do not merge cleanly
  and stay inline.

## Open on the tooling side

`ipa` and `libipa` build under `-Wall` only; the `-Wextra` / `-Wtype-limits`
recommendation from the review has not been taken up.
