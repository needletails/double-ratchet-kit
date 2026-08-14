//
//  RatchetMessage.swift
//  double-ratchet-kit
//
//  Created by Cole M on 4/15/25.
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

/// Represents an encrypted message along with its header in the Double Ratchet protocol.
public struct RatchetMessage: Codable, Sendable, Hashable {
    /// The header containing metadata about the message.
    public let header: EncryptedHeader

    /// The encrypted content of the message.
    public let ciphertext: Data

    private enum CodingKeys: String, CodingKey, Sendable {
        case header = "a"
        case ciphertext = "b"
    }

    /// Initializes a new RatchetMessage with the specified header and encrypted data.
    /// - Parameters:
    ///   - header: The header of the encrypted message.
    ///   - ciphertext: The encrypted content of the message.
    public init(header: EncryptedHeader, ciphertext: Data) {
        self.header = header
        self.ciphertext = ciphertext
    }
}
