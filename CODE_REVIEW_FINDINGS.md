# onomondo-ipa — code review findings

Deep review of the libipa core and platform modules (`src/ipa/`), focused on
correctness bugs, fragilities, redundancy, and maintainability. Line numbers are
against the tree as reviewed; re-grep before editing.

**Verification legend**
- `[compile]` — surfaced/confirmed by building (the tree compiles clean under
  `-Wall`; several of these only appear under `-Wextra`).
- `[read]` — confirmed by reading the code and tracing the logic.
- `[runtime?]` — reasoned from code; should be validated against a real
  eIM / SM-DP+ / strict decoder before trusting the conclusion.

**Suggested first three fixes** (all intersect the direct-download / ES9+ work):
#1 (IpaCapabilities BIT STRING), #2 (swallowed return code), #6 (curl global init).

---

## Correctness bugs

### 1. `IpaCapabilities` encodes named bits as whole bytes — malformed BIT STRING
- **Where:** `src/ipa/libipa/proc_euicc_data_req.c:88-118` (`make_ipa_capabilties`)
- **Status:** `[read]` `[runtime?]`
- **What:** The code writes `1` into **byte index N** for feature bit N, with
  `size = 6` and `bits_unused` never set (stays 0):
  ```c
  ipa_capabilties.ipaFeatures.buf[IpaCapabilities__ipaFeatures_indirectRspServerCommunication] = 1;
  ```
  A DER BIT STRING packs named bit N into `buf[N/8]` at mask `0x80 >> (N%8)`.
  This instead emits a 6-byte string (e.g. `00 01 00 01 00 00`) rather than a
  1-byte `0x50` with `bits_unused = 2`. `ipaSupportedProtocols` in the same
  function has the identical defect.
- **Why it matters:** A conformant eIM decoding named bits reads garbage. This
  field is load-bearing for direct vs indirect download (the eIM reads
  `directRspServerCommunication` here), so it must be correct before the
  direct-download capability is advertised.
- **Reference for the correct idiom:** `src/ipa/libipa/es10b_euicc_mem_rst.c:168`
  uses `rst_opt[0] |= (1 << (7 - bit))` **and** sets `bits_unused` explicitly.
- **Fix:** Pack bits with `buf[N/8] |= 0x80 >> (N%8)`; set `size` to the minimal
  byte count and `bits_unused` accordingly. Add a golden-file encode test.

### 2. `ipa_proc_indirect_prfle_dwnlod()` always returns 0, masking all failures
- **Where:** `src/ipa/libipa/proc_indirect_prfle_dwnld.c:99-104`
- **Status:** `[read]`
- **What:** Both the success path and the `error:` path fall through to
  `return 0;`. The header contracts "0 on success, negative on failure," and the
  caller `src/ipa/libipa/proc_eim_pkg_retr.c:144` tests `if (rc < 0)` — which can
  never fire.
- **Why it matters:** A failed authentication / download / installation is
  reported to `ipa_poll()` as success (`IPA_POLL_AGAIN`). Real errors are
  invisible to the caller and to poll-cadence logic. **The planned direct
  procedure is a near-copy of this file and would inherit the bug.**
- **Fix:** Return a negative code from the error path; audit the success path to
  return 0 only when the install actually succeeded.

### 3. `esipa_get_bnd_prfle_pkg.c` switches on the wrong union member
- **Where:** `src/ipa/libipa/esipa_get_bnd_prfle_pkg.c:96` (`dec_get_bnd_prfle_pkg_res`)
- **Status:** `[read]`
- **What:** Inside the *GetBoundProfilePackage* decoder it reads
  `msg_to_ipa->choice.initiateAuthenticationResponseEsipa.present` — a copy-paste
  from `esipa_init_auth.c`. It works only by accident: both are CHOICE types with
  identical `{ present, choice }` layout at the same union offset, and their `_PR_`
  enums align (NOTHING=0, Ok=1, Error=2).
- **Why it matters:** Correct-by-coincidence; any field reordering silently
  breaks it, and it misleads every reviewer.
- **Fix:** Read `...choice.getBoundProfilePackageResponseEsipa.present`.

### 4. BER length octet `0x7F` is mis-parsed
- **Where:** `src/ipa/libipa/utils.c:327` (`parse_btlv_hdr`)
- **Status:** `[compile]` (adjacent dead check flagged by `-Wtype-limits`)
- **What:** `if (*data < 0x7f)` detects short-form length. Short form is
  `0x00–0x7F`; `0x7F` (127) wrongly falls into the long-form branch where
  `len_bytes = 0x7f & 0x7f = 127 > 4` → `-EINVAL`.
- **Why it matters:** Any TLV whose value is exactly 127 bytes fails to parse.
- **Fix:** `if (*data < 0x80)` (equivalently `<= 0x7f`).

### 5. Dead error check in `ipa_strip_tlv_envelope`
- **Where:** `src/ipa/libipa/utils.c:383`
- **Status:** `[compile]` (`-Wtype-limits`)
- **What:** `if (chop_bytes < 0)` where `chop_bytes` is `size_t` — always false.
  `parse_btlv_hdr` signals errors by returning `-EINVAL` cast to a huge `size_t`,
  so the intended guard is defeated; only the later `chop_bytes > data_len` test
  incidentally catches the huge value.
- **Root cause:** mixing signed error codes with unsigned length returns.
  `parse_btlv_hdr` returns `size_t` but has multiple `return -EINVAL`.
- **Fix:** Give the helper a signed return (or an explicit `bool ok` out-param)
  and check errors before using the length.

---

## Fragilities

### 6. `curl_global_init()`/`curl_global_cleanup()` called per HTTP context
- **Where:** `src/ipa/http.c:343` (init), `src/ipa/http.c:736` (cleanup)
- **Status:** `[read]`
- **What:** These libcurl calls are documented as **per-program**, not
  per-handle, and not thread-safe. Today there is one context so it's benign.
- **Why it matters:** The direct-download plan adds a **second** HTTP context for
  the SM-DP+. Freeing one context calls `curl_global_cleanup()` while the other is
  still live → use-after-cleanup.
- **Fix:** Move global init/cleanup to one-time program setup/teardown (refcount,
  or hoist into `ipa_new_ctx`/`ipa_free_ctx`) **before** adding the second context.

### 7. Hardcoded 5s request timeout + blocking `sleep()` backoff
- **Where:** `src/ipa/http.c:668` (`CURLOPT_TIMEOUT = 5`, whole-request);
  `src/ipa/libipa/esipa.c:189` (`sleep((i+1)*(i+1))`)
- **Status:** `[read]`
- **What:** 5s total (not connect-only) can be too short for a BoundProfilePackage
  download and is not configurable. The retry path blocks up to tens of seconds
  inside a library otherwise driven by non-blocking `ipa_poll()`.
- **Fix:** Make the timeout configurable (and consider connect-timeout vs
  total-timeout separately); make backoff non-blocking or clearly document the
  blocking contract.

### 8. Shared-mutable `static` return storage defeats reentrancy
- **Where:** `src/ipa/libipa/proc_euicc_data_req.c` (`make_ipa_capabilties`,
  `make_device_info`); `src/ipa/libipa/utils.c:45` (`ipa_hexdump` rotating buffers)
- **Status:** `[read]`
- **What:** These return pointers to function-local `static` storage. The README
  advertises library use on IoT devices (potentially >1 context). `ipa_hexdump`'s
  4-slot rotation also clobbers itself when >4 results are live in one expression,
  and returns `char*` into the string literal `"(null)"`.
- **Fix:** For a single-context tool this is acceptable; if multi-context/library
  reentrancy is a goal, thread these through the context or caller-provided buffers.

### 9. `IPA_BUF_STATIC` macro cannot be used twice in one scope
- **Where:** `include/onomondo/ipa/utils.h:108`
- **Status:** `[read]`
- **What:** Hardcodes the backing array name `__name_buf`; two uses in the same
  scope are a redefinition.
- **Fix:** Derive the inner name from `name` via token paste, or pass it in.

### 10. nvstate serialization is a raw `memcpy` of a packed struct
- **Where:** `src/ipa/libipa/ipad.c:70-131`
- **Status:** `[read]`
- **What:** Writes packed `struct ipa_nvstate` verbatim (plus appended `ipa_buf`
  blobs whose serialized form still carries a stale `data` pointer that deserialize
  recomputes). A version byte guards layout drift, but the format is endianness-
  and word-size-dependent despite the comment contemplating "a different machine."
- **Fix:** Fine for same-host persistence; if cross-arch migration is ever needed,
  define an explicit serialized layout.

### 11. Unchecked / asserting I/O and parsing at the CLI boundary
- **Where:** `src/ipa/main.c:71-72` (`strcpy`/`strcat` into `char path[PATH_MAX]`,
  no bounds); `src/ipa/main.c:75` (`assert(ber_file)` aborts on missing file);
  `src/ipa/libipa/ipad.c:277` (reads/mutates `cfg->data[0..1]` without checking
  `cfg->len >= 2`)
- **Status:** `[read]`
- **What:** Operator-supplied inputs, but `assert`-on-bad-input becomes a no-op
  under `-DNDEBUG`, and in-place mutation of the caller's input buffer is surprising.
- **Fix:** Bounds-check path building; return errors instead of asserting on I/O;
  validate length before indexing.

### 12. `ipa_str_from_num` returns NULL instead of `def` for the sentinel value
- **Where:** `src/ipa/libipa/utils.c:26-35`
- **Status:** `[read]`
- **What:** Checks `map->num == num` before the loop's `map->str != NULL`
  condition, so looking up `0` against a `{0, NULL}` terminator returns `NULL`,
  which callers pass straight to `%s`.
- **Fix:** Only return `map->str` for non-terminator entries; return `def`
  otherwise.

---

## Redundancy / duplication

### 13. ESipa function files are ~80% repeated boilerplate (8×)
- **Where:** `src/ipa/libipa/esipa_*.c`
- **Status:** `[read]`
- **What:** Each repeats `enc → ipa_esipa_req → dec`, the `error:`-as-only-return
  idiom, and (in 6 files) an identical copy-pasted JSON-binding dispatch block.
  `esipa_init_auth.c:145` even comments `goto error; /* single return path */` —
  using the error label as the success path.
- **Why it matters:** The direct/ES9+ path will multiply this duplication unless
  factored first.
- **Fix:** Introduce an `esipa_call()` helper parameterized by encode/decode
  function pointers + function name.

### 14. `bpp_segments.c` has near-identical `_87`/`_88`/`_86` encoders
- **Where:** `src/ipa/libipa/bpp_segments.c` (`enc_first_seq_of_87` vs
  `enc_second_seq_of_87`; `enc_each_of_sequenceOf88` vs `enc_each_of_sequenceOf86`)
- **Status:** `[read]`
- **Fix:** Collapse into one helper parameterized by `asn_TYPE_descriptor_t*`.

### 15. `es10b_euicc_mem_rst.c` carries two full encode paths with duplicated bit logic
- **Where:** `src/ipa/libipa/es10b_euicc_mem_rst.c` (SGP.32 vs consumer paths,
  `bits_unused` 3 vs 6)
- **Status:** `[read]`
- **Why it matters:** Duplicated bit-packing is a hazard given finding #1 shows the
  project already gets bit-packing wrong elsewhere.

### 16. Behavior-affecting TODOs left inline
- **Where:** repo-wide (42 `TODO`/`FIXME` + 43 `TODO v1.1/v1.2` markers in `.c`)
- **Status:** `[read]`
- **Examples:** `eimTransactionId` never populated (`esipa_init_auth.c:77`);
  `hashCc`/PPR handling stubbed.
- **Fix:** Convert the ones that change behavior into tracked issues; keep the
  migration ledger markers.

---

## Structural recommendation

Turn on **`-Wextra`** (ideally also `-Wsign-compare` / `-Wtype-limits`, and
consider `-Wconversion`) for the `libipa` and `ipa` targets:
- `src/ipa/CMakeLists.txt:41` — currently `-Wall`
- `src/ipa/libipa/CMakeLists.txt:56` — currently `-Wall`

The tree builds clean under `-Wall`, but `-Wextra` immediately surfaces the
dead-check class (#4, #5). Since the ASN.1 plumbing pervasively mixes `size_t`
lengths with `int`/`long` error codes, `-Wtype-limits`/`-Wsign-compare` are the
cheapest ongoing guard against exactly the length-parsing bugs above.

---

## Cross-reference: impact on the Direct Profile Download plan

If implementing direct download (ES8+ inside ES9+), address these first:
- **#1** — must be correct before advertising `directRspServerCommunication`.
- **#2** — the direct procedure is a near-copy; fix the swallowed return first.
- **#6** — required before adding the second (SM-DP+) HTTP context.
- **#13** — factor the ESipa boilerplate before duplicating it for the ES9+ path.
