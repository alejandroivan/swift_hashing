import Foundation

public extension String {
    var sha1: String { return hash(for: .sha1) }
    var sha256: String { return hash(for: .sha256) }
    var sha384: String { return hash(for: .sha384) }
    var sha512: String { return hash(for: .sha512) }

    private func hash(for variant: Hash.HashType) -> String {
        // Force-unwrapping should never fail for valid UTF-8 strings
        let data = self.data(using: .utf8)!
        let hash = Hash(variant: variant)
        let bytes = hash.bytes(for: data)
        return hash.string(from: bytes)
    }
}
