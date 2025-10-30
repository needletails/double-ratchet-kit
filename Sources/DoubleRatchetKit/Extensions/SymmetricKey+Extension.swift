//
//  SymmetricKey+Extension.swift
//  double-ratchet-kit
//
//  Created by Cole M on 4/29/25.
//
//  Copyright (c) 2025 NeedleTails Organization.
//
//  This project is licensed under the AGPL-3.0 License.
//
//  See the LICENSE file for more information.
//
//  This file is part of the Double Ratchet Kit SDK, which provides
//  post-quantum secure messaging with Double Ratchet Algorithm and PQXDH integration.
//
import Crypto
import Foundation

/// Extension to make SymmetricKey conform to Codable for easy encoding and decoding.
extension SymmetricKey: @retroactive Codable {
    /// Encodes the SymmetricKey to the given encoder.
    /// - Parameter encoder: The encoder to write data to.
    public func encode(to encoder: Encoder) throws {
        let data = withUnsafeBytes { buffer in
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

public extension SymmetricKey {
    var bytes: Data {
        withUnsafeBytes { Data($0) }
    }
}

public extension SharedSecret {
    var bytes: Data {
        withUnsafeBytes { Data($0) }
    }
}
