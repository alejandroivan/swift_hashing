import CommonCrypto
import Foundation

public class Hash {
    /// An enumeration specifying the currently supported hashing algorithms.
    ///
    /// - sha1: Represents a SHA1 hashing algorithm.
    /// - sha256: Represents a SHA256 hashing algorithm.
    /// - sha384: Represents a SHA483 hashing algorithm.
    /// - sha512: Represents a SHA512 hashing algorithm.
    public enum HashType {
        case sha1
        case sha256
        case sha384
        case sha512
    }

    /// A typealias representing the closure types for the hashing funciton.
    private typealias HashFunction = (UnsafeRawPointer?, CC_LONG, UnsafeMutablePointer<UInt8>?) -> UnsafeMutablePointer<UInt8>?

    // MARK: - Properties

    /// The variant to use for hashing.
    public var variant: HashType

    /// The length of the digest for the particular variant chosen, taken from CommonCrypto.
    public var digestLength: Int32 {
        switch variant {
        case .sha1:
            return CC_SHA1_DIGEST_LENGTH
        case .sha256:
            return CC_SHA256_DIGEST_LENGTH
        case .sha384:
            return CC_SHA384_DIGEST_LENGTH
        case .sha512:
            return CC_SHA512_DIGEST_LENGTH
        }
    }

    /// Chooses a hashing function from CommonCrypto, based on the variant specified in the "variant" instance variable.
    private var hashFunction: HashFunction {
        switch variant {
        case .sha1:
            return CC_SHA1
        case .sha256:
            return CC_SHA256
        case .sha384:
            return CC_SHA384
        case .sha512:
            return CC_SHA512
        }
    }

    // MARK: - Initialization

    init(variant: HashType) {
        self.variant = variant
    }

    /// Calculates the hashed bytes for the incoming Data.
    ///
    /// - Parameter data: A Data object representing the original object from which the hash is calculated.
    /// - Returns: An byte array representing the hashed data.
    public func bytes(for data: Data) -> [UInt8] {
        var digest = [UInt8](
            repeating: 0,
            count: Int(digestLength)
        )

        data.withUnsafeBytes {
            _ = hashFunction(
                $0.baseAddress,
                CC_LONG(data.count),
                &digest
            )
        }

        return digest
    }

    /// Transforms the input hashed bytes to a String representation.
    ///
    /// - Parameter bytes: A byte array representing hashed data.
    /// - Returns: The byte array translated into a String.
    public func string(from bytes: [UInt8]) -> String {
        return bytes.map { String(format: "%02hhx", $0) }.joined()
    }
}
