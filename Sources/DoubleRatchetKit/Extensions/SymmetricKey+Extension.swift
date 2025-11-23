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
    public func encode(to encoder: Encoder) throws {
        // Raw key bytes → Data
        let data = withUnsafeBytes { buffer in
            Data(buffer: buffer.bindMemory(to: UInt8.self))
        }

        // Encode as a single-value Data
        var container = encoder.singleValueContainer()
        try container.encode(data)
    }

    public init(from decoder: Decoder) throws {
        // Decode as single-value Data
        let container = try decoder.singleValueContainer()
        let data = try container.decode(Data.self)

        self.init(data: data)
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

extension Curve25519.Signing.PrivateKey: @retroactive Codable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.rawRepresentation)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let data = try container.decode(Data.self)
        self = try .init(rawRepresentation: data)
    }
}
