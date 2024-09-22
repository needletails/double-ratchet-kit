//
//  CommunicationModel.swift
//  double-ratchet-kit
//
//  Created by Cole M on 9/22/24.
//
import Foundation
import Crypto
import BSON
import NeedleTailCrypto

public protocol CommunicationSession: Codable & Sendable {
    var base: CommunicationModel { get }
}

public final class CommunicationModel: Codable, @unchecked Sendable {
    public let id = UUID()
    var data: Data
    
    enum CodingKeys: String, CodingKey, Codable & Sendable {
        case id = "a"
        case data = "b"
    }
    
    /// SymmetricKey can be updated.
    private var symmetricKey: SymmetricKey?
    
    /// Asynchronously retrieves the decrypted properties, if available.
    public var props: UnwrappedProps? {
        get async {
            do {
                guard let symmetricKey = symmetricKey else { return nil }
                return try await setProps(symmetricKey: symmetricKey)
            } catch {
                //TODO: Handle error appropriately (e.g., log it)
                return nil
            }
        }
    }
    
    
    public struct UnwrappedProps: Codable & Sendable {
        private enum CodingKeys: String, CodingKey, Codable, Sendable {
            case messageCount = "a"
            case administrator = "b"
            case members = "c"
            case operators = "d"
            case blockedMembers = "e"
            case metadata = "f"
        }
        // The current count of messages in this communication... Message number
        public var messageCount: Int
        //No-op on private messages
        public var administrator: String?
        //No-op on private messages
        public var operators: Set<String>?
        // private messages need at least 2 memebers
        public var members: Set<String>
        public var metadata: Document
        // private message can kick/block other member
        public let blockedMembers: Set<String>
        
        public init(
            messageCount: Int,
            administrator: String? = nil,
            operators: Set<String>? = nil,
            members: Set<String>,
            metadata: Document,
            blockedMembers: Set<String>
        ) {
            self.messageCount = messageCount
            self.administrator = administrator
            self.operators = operators
            self.members = members
            self.metadata = metadata
            self.blockedMembers = blockedMembers
        }
    }
    
    public init(
        props: UnwrappedProps,
        symmetricKey: SymmetricKey
    ) throws {
        self.symmetricKey = symmetricKey
        let crypto = NeedleTailCrypto()
        let data = try BSONEncoder().encodeData(props)
        guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.encryptionFailed
        }
        self.data = encryptedData
    }
    
    /// Asynchronously sets the properties of the model using the provided symmetric key.
    /// - Parameter symmetricKey: The symmetric key used for decryption.
    /// - Returns: The decrypted properties.
    /// - Throws: An error if decryption fails.
    public func setProps(symmetricKey: SymmetricKey) async throws -> UnwrappedProps {
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
    public func updateProps(symmetricKey: SymmetricKey, props: Codable & Sendable) async throws -> UnwrappedProps? {
        let crypto = NeedleTailCrypto()
        let data = try BSONEncoder().encodeData(props)
        guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.encryptionFailed
        }
        self.data = encryptedData
        return await self.props
    }
}
