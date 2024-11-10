//
//  SessionUser.swift
//  needletail-crypto
//
//  Created by Cole M on 9/13/24.
//
import Foundation
import Crypto
import BSON
import NeedleTailHelpers
import NeedleTailCrypto

public struct _SessionIdentity: Codable, Sendable {
    public let id: UUID
    public let secretName: String
    public let deviceId: UUID
    public let sessionContextId: Int
    public let publicKeyRepesentable: Data
    public let publicSigningRepresentable: Data
    public var state: RatchetState?
    public var deviceName: String
    public var serverTrusted: Bool?
    public var previousRekey: Date?
    public var isMasterDevice: Bool
}

/// This model represents a message and provides an interface for working with encrypted data.
/// The public interface is for creating local models to be saved to the database as encrypted data.
public final class SessionIdentity: SecureModelProtocol, @unchecked Sendable {
    public let id = UUID()
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

    
    /// Struct representing the unwrapped properties of the message.
    public struct UnwrappedProps: Codable & Sendable {
        public let secretName: String
        public let deviceId: UUID
        public let sessionContextId: Int
        public let publicKeyRepesentable: Data
        public let publicSigningRepresentable: Data
        public var state: RatchetState?
        public let deviceName: String
        public var serverTrusted: Bool?
        public var previousRekey: Date?
        public var isMasterDevice: Bool
        
        public init(
            secretName: String,
            deviceId: UUID,
            sessionContextId: Int,
            publicKeyRepesentable: Data,
            publicSigningRepresentable: Data,
            state: RatchetState? = nil,
            deviceName: String,
            serverTrusted: Bool? = nil,
            previousRekey: Date? = nil,
            isMasterDevice: Bool
        ) {
            self.secretName = secretName
            self.deviceId = deviceId
            self.sessionContextId = sessionContextId
            self.publicKeyRepesentable = publicKeyRepesentable
            self.publicSigningRepresentable = publicSigningRepresentable
            self.state = state
            self.deviceName = deviceName
            self.serverTrusted = serverTrusted
            self.previousRekey = previousRekey
            self.isMasterDevice = isMasterDevice
        }
    }
    
    public init(
        props: UnwrappedProps,
        symmetricKey: SymmetricKey
    ) throws {
        let crypto = NeedleTailCrypto()
        let data = try BSONEncoder().encodeData(props)
        guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.encryptionFailed
        }
        self.data = encryptedData
    }
    
    public init(data: Data) {
        self.data = data
    }
    
    /// Asynchronously sets the properties of the model using the provided symmetric key.
    /// - Parameter symmetricKey: The symmetric key used for decryption.
    /// - Returns: The decrypted properties.
    /// - Throws: An error if decryption fails.
    public func decryptProps(symmetricKey: SymmetricKey) async throws -> UnwrappedProps {
        let crypto = NeedleTailCrypto()
        guard let decrypted = try crypto.decrypt(data: self.data, symmetricKey: symmetricKey) else {
            throw CryptoError.decryptionError
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
        return try await self.decryptProps(symmetricKey: symmetricKey)
    }
    
    public func makeDecryptedModel<T: Sendable & Codable>(of: T.Type, symmetricKey: SymmetricKey) async throws -> T {
        guard let props = await self.props(symmetricKey: symmetricKey) else {
            throw CryptoError.propsError
        }
        return try _SessionIdentity(
            id: id,
            secretName: props.secretName,
            deviceId: props.deviceId,
            sessionContextId: props.sessionContextId,
            publicKeyRepesentable: props.publicKeyRepesentable,
            publicSigningRepresentable: props.publicSigningRepresentable,
            deviceName: props.deviceName,
            isMasterDevice: props.isMasterDevice
        ) as! T
    }
}
