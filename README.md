# Onomondo IPA

onomondo-ipa is a C-based IoT Profile Assistant in the IoT Device (IPAd, see also SGP.31) implementation. The IPAd is an
element in the 3GPP IoT eSIM system as described in SGP.31 and SGP.32. It interfaces between the eUICC on one side, 
and the eIM (via HTTPS) on the other side. The implementation presented here can run on a regular Linux host. It can also be used
as a library to add IPAd functionality to an IoT device that runs an RTOS.

This code originally implemented SGP.32 v1.0.  An **in-progress migration to
SGP.32 v1.2** is underway — see [MIGRATION.md](MIGRATION.md) for the full plan,
per-section status, and a checklist of remaining work.  Every changed line in
the schema and source carries an inline marker of the form
`UPDATE for v1.1: <section>` / `UPDATE for v1.2: <CR>` / `NEW in v1.1/v1.2:<section>` / `TODO v1.1/v1.2: <section>` so the diff against the v1.0 baseline
is traceable end-to-end.

This effort to bring the project to SGP.32 v1.2 is independent from the one going on at the `project/nrf-ipa-v1.2` branch of the original [project](https://github.com/onomondo/onomondo-ipa).

Alongside the migration, the core (`libipa` + platform modules) has had a
code-review hardening pass; the resulting correctness and robustness fixes are
in place. Runtime TODOs that still affect behavior will be tracked in the issue
tracker.

For the public summary of spec changes between versions, see
the [osmocom SGP.32 changelog](https://osmocom.org/projects/sim-card-related/wiki/GSMA_SGP32_ChangeLog).

Interfaces
----------

### ESipa

The ESipa interface of onomondo-ipa is implemented as an HTTP client interface (see also GSMA SGP.32, section 6.1) that
uses ASN.1 function bindings (see also GSMA SGP.32, section 6.3).

### ES10x

The interface towards the eUICC is implemented according to GSMA SGP.32 and GSMA SGP.22. The ES10x interface of
onomondo-ipa features an IoT eUICC emulation mode. This allows the usage of regular consumer eUICCs, which are readily
available. The emulation replaces missing IoT eUICC functionality by calling an appropriate consumer eUICC function
as a replacement. In case no equivalent function is available, the function is emulated by onomondo-ipa directly. This
is in particular the case for the functions related to the management of the eIM configuration.

The emulation is a build option and is **not** built by default, see `-DIOT_EUICC_EMULATION` under Options below.


Installation
------------

### Dependencies

The IPAd core implementation (libasn, libipa) is written in a way so that it has no dependencies other than a c99 compliant
C-compiler. However, onomondo-ipa still requires platform dependent modules that allow it to make HTTP(s) requests and
to access the eUICC via some sort of smart card reader. This repository ships with a sample implementation of those
platform-dependent modules that can run on a standard Linux system:

* `http.c`: Contains a libcurl based implementation to make HTTP(s) requests.  It also uses OpenSSL
  directly, to install the eUICC-provisioned TLS credentials (SGP.32 `trustedPublicKeyDataTls`) into
  the handshake via `CURLOPT_SSL_CTX_FUNCTION`.
* `scard.c`: Contains a libpcsclite based implementation to access the eUICC.

On a Debian GNU/Linux system, the following packages are required:

* `asn1c`
* `libcurl4-openssl-dev`
* `libssl-dev`
* `libpcsclite-dev`
* `libjansson-dev`
* `pkg-config`
* `build-essential`
* `cmake`

`libjansson-dev` and `pkg-config` are needed only by the ESipa JSON binding, which is built by default.  A build
configured with `-DESIPA_BINDING_JSON=OFF` does not need either; see Options below.

The OpenSSL flavour of libcurl is required, not the GnuTLS one: `CURLOPT_SSL_CTX_FUNCTION` is
implemented only on OpenSSL-family backends.  Against a GnuTLS-backed libcurl that option fails
with `CURLE_NOT_BUILT_IN`, `http.c` logs the loss and carries on with the system trust store, and
the eUICC-provisioned trust anchor is never installed.

On a Debian system, the standard `apt-get install ...` command can be used to install those dependencies.

### Building

```
cmake -S . -B build -DENABLE_SANITIZE=ON -DSHOW_ASN_OUTPUT=ON   # runs asn1c as needed
cmake --build build
```

CMake generates the libasn ASN.1 codec from `asn1/*.asn` during configure
(requires `asn1c` in PATH) into the build tree — there is no separate regen
step. Editing any `asn1/*.asn` and re-running `cmake --build build` re-runs asn1c and
rebuilds; an unchanged schema is not regenerated.

#### Options

* `-DENABLE_SANITIZE`
this feature is entirely optional and results in a build with AddressSanitizer, which helps to
find out-of-bounds memory accesses during development and testing.
* `-DSHOW_ASN_OUTPUT`
enables decoded printing of the ASN.1 encoded messages that are exchanged between eIM and eUICC.
The decoded ASN.1 output may result in large log output, so it is recommended to use this option only for
development/testing (The hexadecimal representation of messages is still printed).
* `-DASN_EMIT_DEBUG`
the code that is used to encode/decode ASN.1 encoded messages has been generated using asn1c. This
ASN.1 compiler also adds debug messages, which can be enabled by adding this option.
* `-DMEM_EMIT_DEBUG`
this option can be used to analyze the usage of heap memory. When this option is enabled IPA_ALLOC,
IPA_ALLOC_N, IPA_REALLOC, and IPA_FREE will keep track of how much memory is currently allocated. The current memory
usage and the peak memory usage are then displayed. The feature relies on the function malloc_usable_size(), which is a
non-standard API. However, the function is available on GNU LINUX and FreeBSD (see also man malloc_usable_size).
* `-DM32`
use this option to compile onomondo-ipa for 32-BIT x86 architectures,
see also GCC manual, section 3.19.54 x86 Options.
* `-DCERT_ALLOW_UNSET_CLOCK`
onomondo-ipa checks the validity period (notBefore/notAfter) of the SM-DP+ certificates it receives, since the eUICC
verifies those certificates but has no clock to check them against. That check needs a system clock that can be
trusted. By default a clock that is unset (it reads earlier than 2025-01-01) fails the check and the certificate is
refused. Enable this option for a device that has no battery-backed RTC and can only learn the time over an IP
connection it does not have until it is provisioned: an unset clock then skips the check (with a log message)
instead of failing it. Note that this weakens the check, as an attacker who can keep the clock unset also keeps the
check away.
* `-DPPR_ALLOW_WITHOUT_CONSENT`
the Rules Authorisation Table of an eUICC can mark a Profile Policy Rule as one the end user has to consent to before
a profile carrying it may be installed. A device with a user interface answers that by registering
`ipa_config.ppr_consent_cb`, which is handed the rules in question together with the profile name and service
provider name, and returns the end user's decision. A device without a user interface has nobody to ask; this option
decides what it does instead. By default such a profile is refused. Enable this option to install it as if consent
had been given. Note that SGP.32 section 3.2.3.1 observes that IoT devices without a user interface are not expected
to be given a RAT that demands consent in the first place, so needing this option usually points at a RAT that does
not suit the device.
* `-DIOT_EUICC_EMULATION`
build the IoT eUICC emulation described under ES10x above, which lets a consumer (SGP.22) eUICC be used where an IoT
(SGP.32) one is expected. **Off by default**: a product ships with the eUICC it ships with, and a build that will
never meet a consumer card should not carry the adaptation layer -- it is about 17 kB of the image. Without it the
`-E` command-line option is gone and `ipa_init()` refuses a configuration that sets
`ipa_config.iot_euicc_emu_enabled`, rather than quietly ignoring it. libipa defines `IPA_HAVE_IOT_EUICC_EMULATION`
when the emulation is built.
* `-DESIPA_BINDING_ASN1`, `-DESIPA_BINDING_JSON`
the two ESipa wire bindings of SGP.32 v1.2 (sections 6.3 and 6.4). Both are built by default; a deployment that
knows which binding its eIM speaks can drop the other, and at least one has to remain. The JSON binding needs
jansson, and asking for it without jansson present is an error rather than a silent downgrade -- pass
`-DESIPA_BINDING_JSON=OFF` if that is what you meant. libipa defines `IPA_HAVE_ESIPA_ASN1` and `IPA_HAVE_ESIPA_JSON`
for the bindings it has, and selecting one the build does not have makes `ipa_init()` fail. Note that ASN.1 is the
zero value of `ipa_config.esipa_binding`, so a JSON-only build has to set that field explicitly.

#### What the build leaves out

The ASN.1 codec is generated without the codecs this project cannot reach: nothing here reads or writes XER, and the
asn1c type printers are only reachable under `-DSHOW_ASN_OUTPUT`. Together with link-time dead code elimination
(`-ffunction-sections`/`--gc-sections`, enabled for GCC and Clang) that is roughly 30 kB of image that used to be
carried but never executed. Nothing needs to be passed for this; it is how the codec is generated.


Usage
-----

Along with the platform dependent modules, a sample application (`main.c`) is also included. This sample application is
a fully functional IPAd that runs on a Linux system. However, its main purpose is to illustrate how to use the API
presented in `onomondo/ipad.h`.

### Command-Line Options

There are a number of command-line options supported. The most relevant options are:

* `-r` specifies the PCSC reader number.
* `-f` specifies the path to an initial eIM configuration file.
* `-I` omit verification of the SSL certificate of the eIM. This option makes the operation of onomondo-ipa insecure,
but may be helpful for testing and debugging in lab setups.
* `-E` enable the IoT eUICC emulation in case a regular consumer eUICC should be used. Only present when built with
`-DIOT_EUICC_EMULATION=ON`.
* `-j` use the JSON ESipa binding instead of ASN.1. Only present when both bindings are built.

The sample app also exposes the SGP.32 v1.1 ES10b trigger functions as one-shot
options (they run once against the eUICC and exit): `-i` ImmediateEnable,
`-F`/`-b` Execute/Return Fallback, `-X`/`-x` Enable/Disable Emergency Profile,
`-G` GetConnectivityParameters, `-D FQDN` SetDefaultDpAddress, and `-R` to set
the REFRESH flag for the chosen action. These are a reference harness for the
public `ipa_*` trigger API in [`include/onomondo/ipa/ipad.h`](include/onomondo/ipa/ipad.h);
a real device daemon calls that API directly, driven by its own signals (radio
registration state, eCall triggers, ...).

(use option -h to query the full list of parameters)

### Initial Setup

During the first run, onomondo-ipa will create an `nvstate.bin` file in its working directory. 
This file is used as non-volatile storage of data.

In case the IoT eUICC is not yet provisioned with an eIM configuration, onomondo-ipa can be used to perform the
provisioning. The configuration must be supplied as a file that contains an AddInitialEimRequest (see also GSMA SGP.32,
section 5.9.18) data object in its encoded form. It is up to the user to compile the data object using appropriate tools
and the ASN specification presented in GSMA SGP.32. For testing purposes onomondo-ipa ships with a sample configuration
(contrib/sample_eim_cfg.ber) that expects the eIM to be running at 127.0.0.1:8000.

Example: load the initial eIM configuration onto the eUICC in PCSC reader 2
```
./src/ipa/ipa -r 2 -f ../contrib/sample_eim_cfg.ber
```

### Querying eIM Packages

When onomondo-ipa is called without the `-f` parameter, it will read the eUICC configuration and the eidValue from the
eUICC and use it to query the eIM for eIM packages. In case no eIM package is available (error code
noEimPackageAvailable), onomondo-ipa will exit. This condition is technically not an error, it just means that currently
no eIM package is available for the given eUICC / eidValue.

When there is an eIM package available for the given eUICC / eidValue, then onomondo-ipa will download it and execute
the requested procedure. Immediately after that, the next eIM package is requested and processed until the eIM returns
the error code noEimPackageAvailable.

Example: Query the eIM for eIM packages
```
./src/ipa/ipa -r 2
```

License
----------

Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH.

Migration to SGP.32 v1.2 is supported by Iapyx Informática Ltda. and an independent startup that will be named here once it launches publicly.

Many thanks also to [Michael O'Connor](https://www.linkedin.com/in/mikeoconnorirl/) from [DomainsIntel](https://domainsintel.com/) for the code conversion contained in the first commit (1b1756a) to the `sgp.32-v1.2` branch.

Licensed under the GNU Affero General Public License v3.0 only.
