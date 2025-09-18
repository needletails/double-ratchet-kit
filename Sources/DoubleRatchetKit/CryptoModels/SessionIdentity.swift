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
import BSON
#if os(Android) || os(Linux)
@preconcurrency import Crypto
#else
import Crypto
#endif
import Foundation
import NeedleTailCrypto
import SwiftKyber

/// Protocol defining the base model functionality.
public protocol SecureModelProtocol: Codable, Sendable {
    associatedtype Props: Codable & Sendable

    /// Asynchronously sets the properties of the model using the provided symmetric key.
    /// - Parameter symmetricKey: The symmetric key used for decryption.
    /// - Returns: The decrypted properties.
    func decryptProps(symmetricKey: SymmetricKey) async throws -> Props

    /// Updates the properties with the provided symmetric key.
    /// - Parameter symmetricKey: The symmetric key used for decryption.
    /// - Parameter props: The properties to update.
    /// - Returns: The updated properties, or nil if the update failed.
    func updateProps(symmetricKey: SymmetricKey, props: Props) async throws -> Props?

    func makeDecryptedModel<T: Sendable & Codable>(of: T.Type, symmetricKey: SymmetricKey) async throws -> T
}

/// Custom error type for encryption-related errors.
public enum CryptoError: Error {
    case encryptionFailed, decryptionFailed, propsError, messageOutOfOrder
}

/// Represents the stored identity for an encrypted session.
/// - Note: Field names correspond to Signal protocol key types.
public struct _SessionIdentity: Codable, Sendable {
    public let id: UUID
    public let secretName: String
    public let deviceId: UUID
    public let sessionContextId: Int

    /// Long-term identity key (Curve25519 public key) → **IKB**
    public let longTermPublicKey: Data

    /// Medium-term signed pre-key (Curve25519 public key) → **SPKB**
    public let signingPublicKey: Data

    /// Ephemeral one-time pre-key (Curve25519 public key) → **OPKBₙ**
    public let oneTimePublicKey: CurvePublicKey?

    /// PQ post‑quantum signed pre-key (Kyber1024) → **PQSPKB**
    public let pqKemPublicKey: PQKemPublicKey

    public var state: RatchetState?
    public var deviceName: String
    public var serverTrusted: Bool?
    public var previousRekey: Date?
    public var isMasterDevice: Bool
    public var verifiedIdentity: Bool
}

/// This model represents a message and provides an interface for working with encrypted data.
/// The public interface is for creating local models to be saved to the database as encrypted data.
public final class SessionIdentity: SecureModelProtocol, @unchecked Sendable {
    public let id: UUID
    public var data: Data

    enum CodingKeys: String, CodingKey, Codable, Sendable {
        case id = "a"
        case data = "b"
    }

    /// Asynchronously retrieves the decrypted properties, if available.
    public func props(symmetricKey: SymmetricKey) async -> UnwrappedProps? {
        do {
            return try await decryptProps(symmetricKey: symmetricKey)
        } catch {
            return nil
        }
    }

    /// Model class handling encrypted storage of `_SessionIdentity`.
    ///
    /// This struct maps to cryptographic key components and session metadata.
    /// It follows the Signal Protocol naming pattern:
    /// - `longTermPublicKey` → **IKB**
    /// - `signingPublicKey` → **SPKB**
    /// - `oneTimePublicKey` → **OPKBₙ**
    /// - `postQuantumKemPublicKey` → **PQSPKB**
    public struct UnwrappedProps: Codable & Sendable {
        public let secretName: String
        public let deviceId: UUID
        public let sessionContextId: Int

        /// Identity Key Bundle (long-term public key) → IKB
        public var longTermPublicKey: Data

        /// Signed Pre-Key Bundle (signing public key) → SPKB
        public let signingPublicKey: Data

        /// One-Time Pre-Key Bundle (optional) → OPKBₙ
        public var oneTimePublicKey: CurvePublicKey?

        /// Post-Quantum KEM Public Key (e.g., Kyber) → PQSPKB
        public var pqKemPublicKey: PQKemPublicKey

        /// Ratchet state for forward secrecy
        public var state: RatchetState?

        public let deviceName: String
        public var serverTrusted: Bool?
        public var previousRekey: Date?
        public var isMasterDevice: Bool
        public var verifiedIdentity: Bool
        public var verificationCode: String?
        
        public mutating func setLongTermPublicKey(_ data: Data) {
            self.longTermPublicKey = data
        }
        
        public mutating func setOneTimePublicKey(_ key: CurvePublicKey) {
            self.oneTimePublicKey = key
        }
        
        public mutating func setPQKemPublicKey(_ key: PQKemPublicKey) {
            self.pqKemPublicKey = key
        }

        public init(
            secretName: String,
            deviceId: UUID,
            sessionContextId: Int,
            longTermPublicKey: Data,
            signingPublicKey: Data,
            pqKemPublicKey: PQKemPublicKey,
            oneTimePublicKey: CurvePublicKey?,
            state: RatchetState? = nil,
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
            self.pqKemPublicKey = pqKemPublicKey
            self.state = state
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
        let data = try BSONEncoder().encodeData(props)
        guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.encryptionFailed
        }
        self.id = id
        self.data = encryptedData
    }

    public init(id: UUID, data: Data) {
        self.id = id
        self.data = data
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
        return try BSONDecoder().decodeData(UnwrappedProps.self, from: decrypted)
    }

    /// Asynchronously updates the properties of the model.
    /// - Parameters:
    ///   - symmetricKey: The symmetric key used for encryption.
    ///   - props: The new unwrapped properties to be set.
    /// - Returns: The updated decrypted properties.
    ///
    /// - Throws: An error if encryption fails.
    public func updateProps(symmetricKey: SymmetricKey, props: UnwrappedProps) async throws -> UnwrappedProps? {
        let crypto = NeedleTailCrypto()
        let data = try BSONEncoder().encodeData(props)
        guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.encryptionFailed
        }
        self.data = encryptedData
        return try await decryptProps(symmetricKey: symmetricKey)
    }

    public func updateIdentityProps(symmetricKey: SymmetricKey, props: UnwrappedProps) async throws {
        let crypto = NeedleTailCrypto()
        let data = try BSONEncoder().encodeData(props)
        guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.encryptionFailed
        }
        self.data = encryptedData
    }

    public func makeDecryptedModel<T: Sendable & Codable>(of _: T.Type, symmetricKey: SymmetricKey) async throws -> T {
        guard let props = await props(symmetricKey: symmetricKey) else {
            throw CryptoError.propsError
        }
        return _SessionIdentity(
            id: id,
            secretName: props.secretName,
            deviceId: props.deviceId,
            sessionContextId: props.sessionContextId,
            longTermPublicKey: props.longTermPublicKey,
            signingPublicKey: props.signingPublicKey,
            oneTimePublicKey: props.oneTimePublicKey,
            pqKemPublicKey: props.pqKemPublicKey,
            deviceName: props.deviceName,
            isMasterDevice: props.isMasterDevice,
            verifiedIdentity: props.verifiedIdentity,
        ) as! T
    }
}
