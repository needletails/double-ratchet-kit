//
//  SessionIdentity.swift
//  double-ratchet-kit
//
//  Created by Cole M on 9/13/24.
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

import Foundation
import BinaryCodable
import NeedleTailCrypto
import Synchronization

/// Protocol defining the base model functionality.
public protocol SecureModelProtocol: Codable, Sendable {
    associatedtype Props: Codable & Sendable

    /// Asynchronously sets the properties of the model using the provided symmetric key.
    /// - Parameter symmetricKey: The symmetric key used for decryption.
    /// - Returns: The decrypted properties.
    func decryptProps(symmetricKey: SymmetricKey) async throws -> Props

    /// Updates the properties of the model.
    /// - Parameter symmetricKey: The symmetric key used for encryption.
    /// - Parameter props: The properties to update.
    /// - Returns: The updated properties, or nil if the update failed.
    func updateProps(symmetricKey: SymmetricKey, props: Props) async throws -> Props?
}

/// Custom error type for encryption-related errors.
public enum CryptoError: Error {
    case encryptionFailed, decryptionFailed, propsError, messageOutOfOrder
}

/// This model represents a message and provides an interface for working with encrypted data.
/// The public interface is for creating local models to be saved to the database as encrypted data.
public final class SessionIdentity: SecureModelProtocol, Hashable, @unchecked Sendable {
    public let id: UUID

    /// Encrypted payload storage. A `Mutex` guards the bytes because instances
    /// legitimately cross actor boundaries (state manager, persistence
    /// delegates): an unsynchronized `var data: Data` raced concurrent
    /// `update(_:symmetricKey:)`/`decryptProps` calls on the copy-on-write buffer's
    /// reference counts, corrupting the heap (caught by glibc on Linux).
    private let storage: Mutex<Data>

    public var data: Data {
        get { storage.withLock { $0 } }
        set { storage.withLock { $0 = newValue } }
    }

    enum CodingKeys: String, CodingKey, Codable, Sendable {
        case id = "a"
        case data = "b"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        storage = Mutex(try container.decode(Data.self, forKey: .data))
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(data, forKey: .data)
    }

    /// Identity-based equality and hashing: two instances are equal when they
    /// share the same `id`, regardless of the current encrypted payload. This
    /// gives a stable key for `Set`/`Dictionary` even as the ratchet state
    /// inside `data` evolves.
    public static func == (lhs: SessionIdentity, rhs: SessionIdentity) -> Bool {
        lhs.id == rhs.id
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }

    /// Asynchronously retrieves the decrypted properties, if available.
    public func props(symmetricKey: SymmetricKey) async -> UnwrappedProps? {
        do {
            return try await decryptProps(symmetricKey: symmetricKey)
        } catch {
            return nil
        }
    }

    /// Model class handling encrypted storage of session identity.
    ///
    /// This struct maps to cryptographic key components and session metadata.
    /// - `longTermPublicKey` → **IKB**
    /// - `signingPublicKey` → **SPKB**
    /// - `oneTimePublicKey` → **OPKBₙ**
    /// - `postQuantumKemPublicKey` → **PQSPKB**
    public struct UnwrappedProps: Codable & Sendable {
        public let secretName: String
        public let deviceId: UUID
        /// Mutable so hosts can archive/restore a lane without reconstructing props
        /// (and without naming the internal ratchet snapshot).
        public var sessionContextId: Int

        /// Identity Key Bundle (long-term public key) → IKB
        public var longTermPublicKey: Data

        /// Signed Pre-Key Bundle (signing public key) → SPKB
        public var signingPublicKey: Data

        /// One-Time Pre-Key Bundle (optional) → OPKBₙ
        public var oneTimePublicKey: X25519PublicKey?

        /// Post-Quantum KEM Public Key (e.g., Kyber) → PQSPKB
        public var mlKEMPublicKey: MLKEMPublicKey

        /// Nested ratchet snapshot. Internal: hosts use `hasRatchetState` and the
        /// `ratchet*` accessors, not this type.
        var state: RatchetState?

        /// Human-readable device name. Mutable for host archive prefixes.
        public var deviceName: String
        public var serverTrusted: Bool?
        public var previousRekey: Date?
        public var isMasterDevice: Bool
        public var verifiedIdentity: Bool
        public var verificationCode: String?

        /// Whether this blob contains an established ratchet snapshot.
        public var hasRatchetState: Bool { state != nil }

        /// One-time private key stored in the ratchet snapshot, if any.
        public var ratchetOneTimePrivateKey: X25519PrivateKey? {
            state?.localOneTimePrivateKey
        }

        /// ML-KEM private key stored in the ratchet snapshot, if any.
        public var ratchetMLKEMPrivateKey: MLKEMPrivateKey? {
            state?.localMLKEMPrivateKey
        }

        /// Received-message count from the snapshot (`0` if none).
        public var ratchetReceivedMessagesCount: Int {
            state?.receivedMessagesCount ?? 0
        }

        /// Drops the nested ratchet snapshot. App metadata is left unchanged.
        public mutating func clearRatchetState() {
            state = nil
        }

        /// Copies the nested snapshot from another props value without exposing `RatchetState`.
        public mutating func copyRatchetState(from other: UnwrappedProps) {
            state = other.state
        }

        /// Opaque encoding of the nested snapshot, for equality checks. `nil` if none.
        public var ratchetSnapshotData: Data? {
            guard let state else { return nil }
            return try? BinaryEncoder().encode(state)
        }
        
        public mutating func setLongTermPublicKey(_ data: Data) {
            self.longTermPublicKey = data
        }

         public mutating func setSigningPublicKey(_ key: Data) {
            self.signingPublicKey = key
        }
        
        public mutating func setOneTimePublicKey(_ key: X25519PublicKey) {
            self.oneTimePublicKey = key
        }
        
        public mutating func setMLKEMPublicKey(_ key: MLKEMPublicKey) {
            self.mlKEMPublicKey = key
        }
        
        enum CodingKeys: String, CodingKey, Codable, Sendable {
            case secretName = "a",
                 deviceId = "b",
                 sessionContextId = "c",
                 longTermPublicKey = "d",
                 signingPublicKey = "e",
                 oneTimePublicKey = "f",
                 mlKEMPublicKey = "g",
                 state = "h",
                 deviceName = "i",
                 serverTrusted = "j",
                 previousRekey = "k",
                 isMasterDevice = "l",
                 verifiedIdentity = "m",
                 verificationCode = "n"
        }

        public init(
            secretName: String,
            deviceId: UUID,
            sessionContextId: Int,
            longTermPublicKey: Data,
            signingPublicKey: Data,
            mlKEMPublicKey: MLKEMPublicKey,
            oneTimePublicKey: X25519PublicKey?,
            deviceName: String,
            serverTrusted: Bool? = nil,
            previousRekey: Date? = nil,
            isMasterDevice: Bool,
            verifiedIdentity: Bool = true,
            verificationCode: String? = nil
        ) {
            self.secretName = secretName
            self.deviceId = deviceId
            self.sessionContextId = sessionContextId
            self.longTermPublicKey = longTermPublicKey
            self.signingPublicKey = signingPublicKey
            self.oneTimePublicKey = oneTimePublicKey
            self.mlKEMPublicKey = mlKEMPublicKey
            self.state = nil
            self.deviceName = deviceName
            self.serverTrusted = serverTrusted
            self.previousRekey = previousRekey
            self.isMasterDevice = isMasterDevice
            self.verifiedIdentity = verifiedIdentity
            self.verificationCode = verificationCode
        }
    }

    public init(
        id: UUID,
        props: UnwrappedProps,
        symmetricKey: SymmetricKey
    ) throws {
        let crypto = NeedleTailCrypto()
        let data = try BinaryEncoder().encode(props)
        guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.encryptionFailed
        }
        self.id = id
        self.storage = Mutex(encryptedData)
    }

    public init(id: UUID, data: Data) {
        self.id = id
        self.storage = Mutex(data)
    }

    /// Asynchronously sets the properties of the model using the provided symmetric key.
    /// - Parameter symmetricKey: The symmetric key used for decryption.
    /// - Returns: The decrypted properties.
    /// - Throws: An error if decryption fails.
    public func decryptProps(symmetricKey: SymmetricKey) async throws -> UnwrappedProps {
        let crypto = NeedleTailCrypto()
        guard let decrypted = try crypto.decrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.decryptionFailed
        }
        return try BinaryDecoder().decode(UnwrappedProps.self, from: decrypted)
    }

    /// Asynchronously updates the properties of the model.
    /// - Parameters:
    ///   - symmetricKey: The symmetric key used for encryption.
    ///   - props: The new unwrapped properties to be set.
    /// - Returns: The updated decrypted properties.
    ///
    /// - Throws: An error if encryption fails.
    public func updateProps(symmetricKey: SymmetricKey, props: UnwrappedProps) async throws -> UnwrappedProps? {
        try await update(props, symmetricKey: symmetricKey)
        return try await decryptProps(symmetricKey: symmetricKey)
    }

    /// Re-encrypts and stores `props` as the identity blob. Encoding is still `UnwrappedProps` with keys `a`–`n`.
    public func update(_ props: UnwrappedProps, symmetricKey: SymmetricKey) async throws {
        let crypto = NeedleTailCrypto()
        let data = try BinaryEncoder().encode(props)
        guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.encryptionFailed
        }
        self.data = encryptedData
    }
}
