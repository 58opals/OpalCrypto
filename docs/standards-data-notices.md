# Standards data and test-vector notices

OpalCrypto implements its Swift cryptographic primitives in this repository. The standards data and selected published test vectors below retain their upstream provenance; they are not SwiftPM runtime packages. This notice does not change OpalCrypto's own Apache-2.0 license.

## BIP-39 wordlists

The unchanged resources `Sources/OpalCrypto/Resources/BIP39/english.txt` and `korean.txt` each contain 2,048 ordered UTF-8 entries. Preserve their order, normalization and bytes; adding a notice to either `.txt` file would change mnemonic indexing. Notices therefore live outside the loader's text data.

| Resource | Canonical Bitcoin BIPs source | SHA-256 |
| --- | --- | --- |
| English | [bitcoin/bips at `ce1862ac6bcffa1dd20aad858380e51e66e949ea`](https://github.com/bitcoin/bips/blob/ce1862ac6bcffa1dd20aad858380e51e66e949ea/bip-0039/english.txt) | `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda` |
| Korean | [bitcoin/bips at `2880981dc3460801a4f38120a79f290206612942`](https://github.com/bitcoin/bips/blob/2880981dc3460801a4f38120a79f290206612942/bip-0039/korean.txt) | `9e95f86c167de88f450f0aaf89e87f6624a57f973c67b516e338e8e8b8897f60` |

[BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) credits Marek Palatinus, Pavol Rusnak, Aaron Voisine and Sean Bowe and declares the MIT license. The two resource files are also byte-identical to the [English](https://github.com/trezor/python-mnemonic/blob/b57a5ad77a981e743f4167ab2f7927a55c1e82a8/src/mnemonic/wordlist/english.txt) and [Korean](https://github.com/trezor/python-mnemonic/blob/b57a5ad77a981e743f4167ab2f7927a55c1e82a8/src/mnemonic/wordlist/korean.txt) files in the reference implementation `trezor/python-mnemonic` at `b57a5ad77a981e743f4167ab2f7927a55c1e82a8`. Its [MIT notice](https://github.com/trezor/python-mnemonic/blob/b57a5ad77a981e743f4167ab2f7927a55c1e82a8/LICENSE) is retained verbatim below. The wordlist files themselves contain no separate copyright header.

```text
The MIT License (MIT)

Copyright (c) 2013-2016 Pavol Rusnak

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Attributed test vectors

| Local test owner | Published source and retained scope |
| --- | --- |
| `Tests/OpalCryptoTests/BitcoinImprovementProposal340VectorData.swift` | [BIP-340 test vectors](https://github.com/bitcoin/bips/blob/93f161194fbaed12c44f5e2a0c1d4f2b1b317cb0/bip-0340/test-vectors.csv), by Pieter Wuille, Jonas Nick, Tim Ruffing and contributors. Only vectors 0–14 with 32-byte messages are represented. The [specification's test-vector section](https://github.com/bitcoin/bips/blob/93f161194fbaed12c44f5e2a0c1d4f2b1b317cb0/bip-0340.mediawiki#test-vectors-and-reference-code) offers BSD-2-Clause, MIT or CC0-1.0; this data uses its [CC0-1.0 option](https://creativecommons.org/publicdomain/zero/1.0/). The complete upstream CSV SHA-256 is `34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d`. |
| `PublicAPIKeyDerivationValidator.swift` | [RFC 5869 Appendix A.1 and A.3](https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A), HKDF-HMAC-SHA-256 input/output examples. |
| `RSABSSARequestForComments9474Validator.swift` | [RFC 9474 Appendix A.1](https://www.rfc-editor.org/rfc/rfc9474.html#appendix-A.1), randomized SHA-384/PSS blind-signature conformance data. |
| `NostrImplementationPossibility44PrimitiveValidator.swift` | [RFC 8439 §2.3.2](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.3.2) ChaCha20 block data and the [NIP-44 test-vector reference](https://github.com/nostr-protocol/nips/blob/master/44.md#tests-and-code), including its published intermediate message-key values. |
| `PublicAPIAuthenticatedEncryptionValidator.swift` | [NIST CAVP GCM vectors](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes): `gcmEncryptExtIV256.rsp`, key 256, IV 96, plaintext 128, AAD 128, tag 128, count 0. |

The last four filenames are under `Tests/OpalCryptoTests/`. These source references identify test data, not a blanket license for every fixture. RFC, NIP and NIST materials retain their respective upstream notices and terms; no missing license is inferred from an algorithm name, and this notice does not relicense those sources as MIT or CC0. Test fixtures and published example keys are permanently disposable and are not production key material.
