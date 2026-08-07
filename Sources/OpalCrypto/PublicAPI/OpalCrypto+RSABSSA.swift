// OpalCrypto+RSABSSA.swift

extension OpalCrypto {
    /// Validated data contracts for RSA blind signatures with appendix material
    /// from RFC 9474.
    ///
    /// This namespace does not currently provide key generation, blinding,
    /// blind signing, finalization, or verification operations. Callers must
    /// use a separately vetted implementation for those operations.
    public enum RSABSSA {}
}
