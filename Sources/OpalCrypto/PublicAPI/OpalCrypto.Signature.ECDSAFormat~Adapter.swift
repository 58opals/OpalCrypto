// OpalCrypto.Signature.ECDSAFormat~Adapter.swift

import Foundation

extension OpalCrypto.Signature.ECDSAFormat {
    var diagnosticsName: String {
        switch self {
        case .raw:
            return "raw"
        case .der:
            return "der"
        }
    }
}
