//
//  RatchetHeader.swift
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

/// Represents the header of an encrypted message in the Double Ratchet protocol.
public struct EncryptedHeader: Sendable, Codable, Hashable {
    /// Sender's long-term public key.
    public let remoteLongTermPublicKey: Data

    /// Sender's one-time public key.
    public let remoteOneTimePublicKey: X25519PublicKey?

    /// Sender's MLKEM public key used for key agreement.
    public let remoteMLKEMPublicKey: MLKEMPublicKey

    /// Header encapsulated ciphertext.
    public let headerCiphertext: Data

    /// Message encapsulated ciphertext.
    public let messageCiphertext: Data

    public let oneTimeKeyId: UUID?

    public let mlKEMOneTimeKeyId: UUID?

    /// Encrypted header body
    public let encrypted: Data

    /// Only exists at runtime after decryption.
    public private(set) var decrypted: MessageHeader?

    /// Sets the decrypted message header.
    /// - Parameter decrypted: The decrypted message header to set.
    mutating func setDecrypted(_ decrypted: MessageHeader) {
        self.decrypted = decrypted
    }

    private enum CodingKeys: String, CodingKey, Sendable {
        case remoteLongTermPublicKey = "a"
        case remoteOneTimePublicKey = "b"
        case remoteMLKEMPublicKey = "c"
        case headerCiphertext = "d"
        case messageCiphertext = "e"
        case oneTimeKeyId = "f"
        case mlKEMOneTimeKeyId = "g"
        case encrypted = "h"
    }

    /// Initializes the EncryptedHeader without a decrypted header (sending case).
    /// - Parameters:
    ///   - remoteLongTermPublicKey: The sender's long-term public key.
    ///   - remoteOneTimePublicKey: The sender's one-time public key.
    ///   - remoteMLKEMPublicKey: The sender's MLKEM public key.
    ///   - headerCiphertext: The ciphertext of the header.
    ///   - messageCiphertext: The ciphertext of the message.
    ///   - oneTimeKeyId: The One Time Curve Key
    ///   - mlKEMOneTimeKeyId: The MLKEM Key
    ///   - encrypted: The encrypted body of the header.
    public init(
        remoteLongTermPublicKey: Data,
        remoteOneTimePublicKey: X25519PublicKey?,
        remoteMLKEMPublicKey: MLKEMPublicKey,
        headerCiphertext: Data,
        messageCiphertext: Data,
        oneTimeKeyId: UUID?,
        mlKEMOneTimeKeyId: UUID,
        encrypted: Data
    ) {
        self.remoteLongTermPublicKey = remoteLongTermPublicKey
        self.remoteOneTimePublicKey = remoteOneTimePublicKey
        self.remoteMLKEMPublicKey = remoteMLKEMPublicKey
        self.headerCiphertext = headerCiphertext
        self.messageCiphertext = messageCiphertext
        self.oneTimeKeyId = oneTimeKeyId
        self.mlKEMOneTimeKeyId = mlKEMOneTimeKeyId
        self.encrypted = encrypted
        decrypted = nil
    }

    /// Initializes the EncryptedHeader with a decrypted header (receiving case).
    /// - Parameters:
    ///   - remoteLongTermPublicKey: The sender's long-term public key.
    ///   - remoteOneTimePublicKey: The sender's one-time public key.
    ///   - remoteMLKEMPublicKey: The sender's MLKEM public key.
    ///   - headerCiphertext: The ciphertext of the header.
    ///   - messageCiphertext: The ciphertext of the message.
    ///   - encrypted: The encrypted body of the header.
    ///   - oneTimeKeyId: The One Time Curve Key
    ///   - mlKEMOneTimeKeyId: The MLKEM Key
    ///   - decrypted: The decrypted **MessageHeader**.
    public init(
        remoteLongTermPublicKey: Data,
        remoteOneTimePublicKey: X25519PublicKey,
        remoteMLKEMPublicKey: MLKEMPublicKey,
        headerCiphertext: Data,
        messageCiphertext: Data,
        encrypted: Data,
        oneTimeKeyId: UUID?,
        mlKEMOneTimeKeyId: UUID,
        decrypted: MessageHeader
    ) {
        self.remoteLongTermPublicKey = remoteLongTermPublicKey
        self.remoteOneTimePublicKey = remoteOneTimePublicKey
        self.remoteMLKEMPublicKey = remoteMLKEMPublicKey
        self.headerCiphertext = headerCiphertext
        self.messageCiphertext = messageCiphertext
        self.encrypted = encrypted
        self.oneTimeKeyId = oneTimeKeyId
        self.mlKEMOneTimeKeyId = mlKEMOneTimeKeyId
        self.decrypted = decrypted
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(remoteLongTermPublicKey)
        hasher.combine(remoteOneTimePublicKey)
        hasher.combine(remoteMLKEMPublicKey)
        hasher.combine(headerCiphertext)
        hasher.combine(messageCiphertext)
        hasher.combine(oneTimeKeyId)
        hasher.combine(mlKEMOneTimeKeyId)
        hasher.combine(encrypted)
    }

    public static func == (lhs: EncryptedHeader, rhs: EncryptedHeader) -> Bool {
        lhs.remoteLongTermPublicKey == rhs.remoteLongTermPublicKey
            && lhs.remoteOneTimePublicKey == rhs.remoteOneTimePublicKey
            && lhs.remoteMLKEMPublicKey == rhs.remoteMLKEMPublicKey
            && lhs.headerCiphertext == rhs.headerCiphertext
            && lhs.messageCiphertext == rhs.messageCiphertext
            && lhs.oneTimeKeyId == rhs.oneTimeKeyId
            && lhs.mlKEMOneTimeKeyId == rhs.mlKEMOneTimeKeyId
            && lhs.encrypted == rhs.encrypted
    }
}

/// Represents the header of a message in the Double Ratchet protocol.
///
/// The per-turn hybrid ratchet fields ride inside the *encrypted* header body
/// (HE variant), preserving metadata protection. Public keys are required on
/// every frame. The KEM ciphertext is absent until this party has taken a
/// sending DH step (the initiator's first PQXDH bootstrap chain has none).
public struct MessageHeader: Sendable, Codable {
    /// The length of the previous message chain.
    public let previousChainLength: Int

    public let messageNumber: Int

    /// The sender's current per-turn Curve25519 ratchet public key (32 bytes).
    public let ratchetPublicKey: Data

    /// The sender's current per-turn ML-KEM-1024 ratchet public key (~1.6 KB).
    /// The peer encapsulates to this key on its next sending ratchet step.
    public let ratchetKEMPublicKey: Data

    /// ML-KEM ciphertext encapsulated to the receiver's last advertised ratchet
    /// KEM public key. Rides in every header of the sending chain (not just the
    /// turn boundary) so the receiver can complete the matching receiving step
    /// even when the first message of the chain is lost or reordered.
    /// `nil` on the initiator's PQXDH bootstrap chain, before any sending DH step.
    public let ratchetKEMCiphertext: Data?

    private enum CodingKeys: String, CodingKey, Sendable {
        case previousChainLength = "a"
        case messageNumber = "b"
        case ratchetPublicKey = "c"
        case ratchetKEMPublicKey = "d"
        case ratchetKEMCiphertext = "e"
    }

    /// Initializes a new MessageHeader with the specified parameters.
    /// - Parameters:
    ///   - previousChainLength: The length of the previous message chain.
    ///   - messageNumber: The message number of the given message
    ///   - ratchetPublicKey: The sender's per-turn Curve25519 ratchet public key.
    ///   - ratchetKEMPublicKey: The sender's per-turn ML-KEM ratchet public key.
    ///   - ratchetKEMCiphertext: ML-KEM ciphertext for the receiver, if a sending DH step has run.
    public init(
        previousChainLength: Int,
        messageNumber: Int,
        ratchetPublicKey: Data,
        ratchetKEMPublicKey: Data,
        ratchetKEMCiphertext: Data? = nil
    ) {
        self.previousChainLength = previousChainLength
        self.messageNumber = messageNumber
        self.ratchetPublicKey = ratchetPublicKey
        self.ratchetKEMPublicKey = ratchetKEMPublicKey
        self.ratchetKEMCiphertext = ratchetKEMCiphertext
    }
}
