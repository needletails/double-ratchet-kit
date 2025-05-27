//
//  SessionUser.swift
//  needletail-crypto
//
//  Created by Cole M on 9/13/24.
//
import Foundation
import Crypto
import BSON
import NeedleTailCrypto
import SwiftKyber

/// Protocol defining the base model functionality.
public protocol SecureModelProtocol: Codable, Sendable {
    associatedtype Props: Codable & Sendable
    
    /// Asynchronously sets the properties of the model using the provided symmetric key.
    /// - Parameter symmetricKey: The symmetric key used for decryption.
    /// - Returns: The decrypted properties.
    func decryptProps(symmetricKey: SymmetricKey, data: Data) async throws -> Props
    
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

public struct _SessionIdentity: Codable, Sendable {
    public let id: UUID
    public let secretName: String
    public let deviceId: UUID
    public let sessionContextId: Int
    public let publicLongTermKey: Data
    public let publicSigningKey: Data
    public let publicOneTimeKey: Data?
    public let kyber1024PublicKey: Kyber1024PublicKeyRepresentable
    public var state: RatchetState?
    public var deviceName: String
    public var serverTrusted: Bool?
    public var previousRekey: Date?
    public var isMasterDevice: Bool
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
            return try await decryptProps(symmetricKey: symmetricKey, data: self.data)
        } catch {
            return nil
        }
    }

    
    /// Struct representing the unwrapped properties of the message.
    public struct UnwrappedProps: Codable & Sendable {
        public let secretName: String
        public let deviceId: UUID
        public let sessionContextId: Int
        public var publicLongTermKey: Data
        public let publicSigningKey: Data
        public let publicOneTimeKey: Data?
        public var kyber1024PublicKey: Kyber1024PublicKeyRepresentable
        public var state: RatchetState?
        public let deviceName: String
        public var serverTrusted: Bool?
        public var previousRekey: Date?
        public var isMasterDevice: Bool
        
        public init(
            secretName: String,
            deviceId: UUID,
            sessionContextId: Int,
            publicLongTermKey: Data,
            publicSigningKey: Data,
            kyber1024PublicKey: Kyber1024PublicKeyRepresentable,
            publicOneTimeKey: Data?,
            state: RatchetState? = nil,
            deviceName: String,
            serverTrusted: Bool? = nil,
            previousRekey: Date? = nil,
            isMasterDevice: Bool
        ) {
            self.secretName = secretName
            self.deviceId = deviceId
            self.sessionContextId = sessionContextId
            self.publicLongTermKey = publicLongTermKey
            self.publicSigningKey = publicSigningKey
            self.publicOneTimeKey = publicOneTimeKey
            self.kyber1024PublicKey = kyber1024PublicKey
            self.state = state
            self.deviceName = deviceName
            self.serverTrusted = serverTrusted
            self.previousRekey = previousRekey
            self.isMasterDevice = isMasterDevice
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
    public func decryptProps(symmetricKey: SymmetricKey, data: Data) async throws -> UnwrappedProps {
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
        return try await self.decryptProps(symmetricKey: symmetricKey, data: encryptedData)
    }
    
    public func updateIdentityProps(symmetricKey: SymmetricKey, props: UnwrappedProps) async throws {
        let crypto = NeedleTailCrypto()
        let data = try BSONEncoder().encodeData(props)
        guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.encryptionFailed
        }
        self.data = encryptedData
    }
    
    public func makeDecryptedModel<T: Sendable & Codable>(of: T.Type, symmetricKey: SymmetricKey) async throws -> T {
        guard let props = await self.props(symmetricKey: symmetricKey) else {
            throw CryptoError.propsError
        }
        return _SessionIdentity(
            id: id,
            secretName: props.secretName,
            deviceId: props.deviceId,
            sessionContextId: props.sessionContextId,
            publicLongTermKey: props.publicLongTermKey,
            publicSigningKey: props.publicSigningKey,
            publicOneTimeKey: props.publicOneTimeKey,
            kyber1024PublicKey: props.kyber1024PublicKey,
            deviceName: props.deviceName,
            isMasterDevice: props.isMasterDevice
        ) as! T
    }
}

