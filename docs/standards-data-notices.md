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
| `PublicAPIKeyDerivationValidator.swift` | [RFC 5869 Appendix A.1–A.3](https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A), HKDF-HMAC-SHA-256 input/output examples. |
| `RSABSSARequestForComments9474Validator.swift` | [RFC 9474 Appendix A.1](https://www.rfc-editor.org/rfc/rfc9474.html#appendix-A.1), randomized SHA-384/PSS blind-signature conformance data. |
| `NostrImplementationPossibility44PrimitiveValidator.swift` | [RFC 8439 §2.3.2](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.3.2) ChaCha20 block data and the [NIP-44 test-vector reference](https://github.com/nostr-protocol/nips/blob/master/44.md#tests-and-code), including its published intermediate message-key values. |
| `PublicAPIAuthenticatedEncryptionValidator.swift` | [NIST CAVP GCM vectors](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes): `gcmEncryptExtIV256.rsp`, key 256, IV 96, plaintext 128, AAD 128, tag 128, count 0. |

The last four filenames are under `Tests/OpalCryptoTests/`. These source references identify test data, not a blanket license for every fixture. RFC, NIP and NIST materials retain their respective upstream notices and terms; no missing license is inferred from an algorithm name, and this notice does not relicense those sources as MIT or CC0. Test fixtures and published example keys are permanently disposable and are not production key material.

## Offline provenance checks and limits

`StandardsResourceProvenanceValidator` hashes the actual bundled English and Korean wordlist bytes with Apple's CryptoKit and checks the immutable source URLs and hashes above. The existing mnemonic tests continue to own word count, normalization, indexing and round-trip behavior; the provenance checks add byte identity without duplicating those behavioral assertions.

For BIP-340, the complete pinned CSV was hash-verified against `34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d`, then its first seven columns for vectors 0–14 were compared field by field with the local records. Those columns, with no header or comment column, comma separators, original uppercase hexadecimal and `TRUE`/`FALSE` values, and one LF after each row, have SHA-256 `b50645731f7a5735194711fab5b9e21942575d9137fada5848c7f65d36fb5a02`. The offline test recomputes this subset digest and binds the notice to the immutable CSV source and complete-source hash. The full CSV is not bundled, so this test does not rehash or refetch it; existing BIP-340 API tests still own signing and invalid-signature assertions.

The RFC-numbered links above identify fixed published documents. The qualifications below bind the current retained fixture bytes to independently inspected sources. They do not establish when or how those bytes were originally imported, and do not claim an independent security audit.

## NIP-44 intermediate vector

The retained message-key case in `NostrImplementationPossibility44PrimitiveValidator.matchOfficialMessageKeyVector` exactly matches `v2.valid.get_message_keys.keys[0]` and its parent `conversation_key` in [paulmillr/nip44 at `671a1f04bcfacaf125b0db68adc45bc9ce0e763b`](https://github.com/paulmillr/nip44/blob/671a1f04bcfacaf125b0db68adc45bc9ce0e763b/nip44.vectors.json). The 37,630-byte complete JSON has SHA-256 `269ed0f69e4c192512cc779e78c555090cebc7c785b609e338a62afc3ce25040`. The [pinned NIP-44 specification](https://github.com/nostr-protocol/nips/blob/0b54c4d1c70b046fbb2e3c599c09b641e00f5dcd/44.md) publishes that same complete-file checksum and identifies this vector collection; its SHA-256 is `b5f89374e4e1dbdee7881e8573b4313b6a89430a9c8d518471599ae0660cf0e2`.

The offline case identity concatenates the lowercase hexadecimal `conversation_key`, `nonce`, `chacha_key`, `chacha_nonce` and `hmac_key`, in that order, with one LF after every field. SHA-256 is `b81330ffdd17c83f1fa55efa148f4f2d6a64a3a70c4e7d79bc05bdef68055e93`. The existing primitive test checks this binding without changing its input bytes or output assertions. The [NIPs repository license statement](https://github.com/nostr-protocol/nips/blob/0b54c4d1c70b046fbb2e3c599c09b641e00f5dcd/README.md#license) declares NIPs public domain; this does not assign a blanket license to the separate implementations or audit report linked by the vector project.

## NIST AES-GCM case

The current CAVP case was independently matched field by field to the [official GCM test-vector archive](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip) linked by [NIST's block-cipher-mode testing page](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes). The inspected archive is 9,154,174 bytes, SHA-256 `f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023`; its unchanged `gcmEncryptExtIV256.rsp` member is 3,182,939 bytes, SHA-256 `4448b4998c3f58cd9f5542ddf7c573189a721ff3d3ac24cd5177bb4910a787f8`. Preserve the member's original CRLF bytes when comparing that whole-file digest.

The selected section is Keylen 256, IVlen 96, PTlen 128, AADlen 128, Taglen 128, Count 0. Its canonical case identity is lowercase hexadecimal Key, IV, PT, AAD, CT and Tag, in that order, with one LF after every field: SHA-256 `f38a9559ae5d0e5f3a49a2ca427c4889c0a7e012ae1c773346f642988a64d626`. The authenticated-encryption test binds its unchanged inputs and expected combined output to this case. NIST provides a mutable download URL rather than an immutable revision; the digest fixes the inspected archive's identity. This is current-byte requalification, not proof of the original download, a new license assignment, or CAVP certification. The tests do not download or bundle the complete archive.

## BCH Schnorr fixtures

`SchnorrVectorRepository.swift` retains all sixteen existing verification cases and its three private-key signing cases. Verification tuples for local indices 1–5, 8–11, 14 and 16 exactly match the corresponding cases in [BCHN's secp256k1 Schnorr tests at `07576013c91ff4a3a74acd85f189c69121cdad1b`](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/secp256k1/src/modules/schnorr/tests_impl.h), SHA-256 `b8a14d1778d0417e58fce2ca8092f9b289a4ccef93ce2b256c92ad5f17540f57`. The referenced source retains Copyright (c) 2017 Amaury SÉCHET and its MIT notice; the accompanying [COPYING](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/secp256k1/COPYING), SHA-256 `a735999c7e5649df6fcda6fb06ab97435851c392b1b93494ae8725f37441632f`, retains the upstream permission and warranty terms.

All sixteen verification outcomes were additionally evaluated with independent integer/point arithmetic against the [BCH Schnorr verification rules](https://github.com/bitcoincashorg/bitcoincash.org/blob/3e2e6da8c38dab7ba12149d327bc4b259aaad684/spec/2019-05-15-schnorr.md), whose source SHA-256 is `86cecdbf7e08876c53479d2d3eca85568a49783c5dcd9c77605912b8443b5dbd`. The procedure decodes and validates the compressed key, checks `r < p` and `s < n`, computes `e = SHA256(r || compressedPublicKey || message) mod n` and `R = sG - eP`, and requires finite R, `R.x = r`, and quadratic-residue R.y. Indices 6, 7, 12, 13 and 15 are independently requalified corner cases; their exact original source is still unknown.

The existing signing tests explicitly select `bitcoinImprovementProposalSchnorrDeterministic`: their first nonce candidate is `SHA256(privateKey32 || digest32) mod n`, with the signing algorithm's quadratic-residue adjustment. Independent arithmetic reproduces all three retained public keys and signatures with that profile. It is different from BCHN's RFC6979/HMAC profile with the `Schnorr+SHA256  ` personalization string; those signatures are not expected to be identical. The BCH specification permits different nonce-generation methods. This qualification does not recover the original fixture-import history or assert that these fixtures were generated by BCHN's RFC6979 signer.

The offline row digest uses the existing order 1–16 and columns index, secret key or empty, compressed public key, message, signature and `TRUE`/`FALSE`, comma-separated, with one LF after each row. Existing uppercase hexadecimal is preserved; the signature field's leading whitespace is trimmed exactly as the fixture decoder already does. SHA-256 is `3ba975b6e47fbddfeb39fe025da07fb48c3b9ad4e9404aea21625c260fad275c`. `StandardsResourceProvenanceValidator` guards these bytes and the source bindings; the existing Schnorr suites retain the signing and rejection assertions. No C/C++ source or external reference implementation is added to the package.
