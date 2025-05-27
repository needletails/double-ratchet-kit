//
//  SymmetricKey+Extension.swift
//  double-ratchet-kit
//
//  Created by Cole M on 4/29/25.
//
import Crypto
import Foundation

/// Extension to make SymmetricKey conform to Codable for easy encoding and decoding.
extension SymmetricKey: Codable {
    /// Encodes the SymmetricKey to the given encoder.
    /// - Parameter encoder: The encoder to write data to.
    public func encode(to encoder: Encoder) throws {
        let data = self.withUnsafeBytes { buffer in
            Data(buffer: buffer.bindMemory(to: UInt8.self))
        }
        try data.encode(to: encoder) // Encode the key data.
    }
    
    /// Initializes a SymmetricKey from the given decoder.
    /// - Parameter decoder: The decoder to read data from.
    public init(from decoder: Decoder) throws {
        let data = try Data(from: decoder) // Decode the key data.
        self.init(data: data) // Initialize the SymmetricKey with the decoded data.
    }
}


extension SymmetricKey {
    var bytes: Data {
        self.withUnsafeBytes({ Data($0) })
    }
}

extension SharedSecret {
    var bytes: Data {
        self.withUnsafeBytes({ Data($0) })
    }
}
