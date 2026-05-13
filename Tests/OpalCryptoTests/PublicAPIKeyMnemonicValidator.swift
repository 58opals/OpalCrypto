// PublicAPIKeyMnemonicValidator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("Public API key mnemonic validation")
struct PublicAPIKeyMnemonicValidator {
    @Test("Load English and Korean BIP-39 word lists")
    func loadEnglishAndKoreanBip39WordLists() throws {
        let englishWords = try OpalCrypto.Key.Mnemonic.WordList.load(.english)
        let koreanWords = try OpalCrypto.Key.Mnemonic.WordList.load(.korean)

        #expect(englishWords.count == 2048)
        #expect(koreanWords.count == 2048)
        #expect(englishWords[0] == .init("abandon"))
        #expect(englishWords.contains(.init("about")))
        #expect(englishWords.index(of: .init("about")) == 3)
        #expect(koreanWords[0] == .init("가격"))
        #expect(koreanWords.contains(.init("가능")))
    }

    @Test("Reject duplicate normalized mnemonic resource words without trapping")
    func rejectDuplicateNormalizedMnemonicResourceWordsWithoutTrapping() {
        var words = (0..<2048).map { "word\($0)" }
        words[2047] = words[0]

        do {
            _ = try MnemonicWordListRepository.makeWordListData(
                words: words,
                language: .english
            )
            Issue.record("Expected duplicate word-list rejection.")
        } catch let error as OpalCrypto.Key.Mnemonic.Error {
            #expect(error == .invalidWordList(language: .english, actualCount: 2047))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject empty normalized mnemonic resource words")
    func rejectEmptyNormalizedMnemonicResourceWords() {
        var words = (0..<2048).map { "word\($0)" }
        words[1024] = ""

        do {
            _ = try MnemonicWordListRepository.makeWordListData(
                words: words,
                language: .english
            )
            Issue.record("Expected empty word-list entry rejection.")
        } catch let error as OpalCrypto.Key.Mnemonic.Error {
            #expect(error == .invalidWordList(language: .english, actualCount: 2048))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject mnemonic resource words containing whitespace")
    func rejectMnemonicResourceWordsContainingWhitespace() {
        var words = (0..<2048).map { String(format: "word%04d", $0) }
        words[1024] = "word 1024"

        do {
            _ = try MnemonicWordListRepository.makeWordListData(
                words: words,
                language: .english
            )
            Issue.record("Expected whitespace word-list entry rejection.")
        } catch let error as OpalCrypto.Key.Mnemonic.Error {
            #expect(error == .invalidWordList(language: .english, actualCount: 2048))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject unsorted mnemonic resource words")
    func rejectUnsortedMnemonicResourceWords() {
        var words = (0..<2048).map { String(format: "word%04d", $0) }
        words.swapAt(1024, 1025)

        do {
            _ = try MnemonicWordListRepository.makeWordListData(
                words: words,
                language: .english
            )
            Issue.record("Expected unsorted word-list rejection.")
        } catch let error as OpalCrypto.Key.Mnemonic.Error {
            #expect(error == .invalidWordList(language: .english, actualCount: 2048))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Generate valid English mnemonics at every supported length")
    func generateValidEnglishMnemonicsAtEverySupportedLength() throws {
        for length in OpalCrypto.Key.Mnemonic.Length.allCases {
            let mnemonic = try OpalCrypto.Key.Mnemonic.generate(length: length, language: .english)
            let reparsed = try OpalCrypto.Key.Mnemonic(phrase: mnemonic.phrase, language: .english)

            #expect(mnemonic.words.count == length.rawValue)
            #expect(mnemonic.length == length)
            #expect(mnemonic.language == .english)
            #expect(reparsed == mnemonic)
        }
    }

    @Test("Mnemonic entropy encoding accepts sliced Data")
    func mnemonicEntropyEncodingAcceptsSlicedData() throws {
        let entropy = Data(repeating: 0x00, count: 16)
        let slicedEntropy = (Data([0xFF]) + entropy + Data([0xEE]))
            .dropFirst()
            .dropLast()

        let normalizedMnemonic = try MnemonicCodecModel.makeMnemonic(
            entropy: entropy,
            language: .english
        )
        let slicedMnemonic = try MnemonicCodecModel.makeMnemonic(
            entropy: slicedEntropy,
            language: .english
        )

        #expect(slicedMnemonic == normalizedMnemonic)
    }

    @Test("Mnemonic entropy decoding rejects word-count and length mismatches")
    func mnemonicEntropyDecodingRejectsWordCountAndLengthMismatches() {
        let words = englishVectorPhrase
            .split(whereSeparator: \.isWhitespace)
            .map(String.init)
            + ["about"]

        do {
            _ = try MnemonicCodecModel.entropy(
                from: words,
                language: .english,
                length: .words12
            )
            Issue.record("Expected invalid word-count rejection.")
        } catch let error as OpalCrypto.Key.Mnemonic.Error {
            #expect(error == .invalidWordCount(actual: 13))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Mnemonic generation maps random byte failures to facade errors")
    func validateMnemonicGenerationMapsRandomByteFailuresToFacadeErrors() {
        do {
            _ = try OpalCrypto.Key.Mnemonic.generate(
                length: .words12,
                language: .english,
                makeEntropyBytes: { _ in
                    throw SecureRandomByteGenerationModel.Error.failed(status: -1)
                }
            )
            Issue.record("Expected random generation failure.")
        } catch let error as OpalCrypto.Key.Mnemonic.Error {
            #expect(error == .randomGenerationFailed(status: -1))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Auto-detect mnemonic language and derive seed vectors")
    func autoDetectMnemonicLanguageAndDeriveSeedVectors() throws {
        let englishMnemonic = try OpalCrypto.Key.Mnemonic(phrase: englishVectorPhrase)
        #expect(englishMnemonic.language == .english)
        #expect(englishMnemonic.length == .words12)
        #expect(
            try englishMnemonic.deriveSeed(passphrase: "TREZOR").rawRepresentation
                == Data(hexadecimal: englishVectorSeedHex)
        )

        let koreanMnemonic = try OpalCrypto.Key.Mnemonic(phrase: koreanVectorPhrase)
        #expect(koreanMnemonic.language == .korean)
        #expect(koreanMnemonic.length == .words12)
        #expect(
            try koreanMnemonic.deriveSeed(passphrase: "TREZOR").rawRepresentation
                == Data(hexadecimal: koreanVectorSeedHex)
        )
    }

    @Test("Reject mnemonic with invalid checksum")
    func rejectMnemonicWithInvalidChecksum() {
        let invalidPhrase = """
        abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon
        """

        do {
            _ = try OpalCrypto.Key.Mnemonic(phrase: invalidPhrase, language: .english)
            Issue.record("Expected invalid checksum error.")
        } catch let error as OpalCrypto.Key.Mnemonic.Error {
            #expect(error == .invalidChecksum)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    private let englishVectorPhrase = """
    abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
    """

    private let englishVectorSeedHex = """
    c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04
    """

    private let koreanVectorPhrase = """
    가격 가격 가격 가격 가격 가격 가격 가격 가격 가격 가격 가능
    """

    private let koreanVectorSeedHex = """
    a253d07f616223e337b6fa257632a2cc37e1ba36ff0bc7cf5a943366fa1b9ef02d6aa0333da51c17902951634b8aa81b6692a194b07f4f8c542335d73c96aad3
    """
}
