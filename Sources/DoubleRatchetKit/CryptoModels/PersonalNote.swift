//
//  PersonalNote.swift
//  double-ratchet-kit
//
//  Created by Cole M on 9/25/24.
//
import Foundation
import Crypto
import BSON
import Foundation
import NeedleTailHelpers
import NeedleTailCrypto

public struct _PersonalNote: Sendable, Codable {
    public let id: UUID
    public let createdData: Date
    public let recipient: MessageRecipient
    public var base: BaseCommunication
    public var messages: [PrivateMessage]
}
public final class PersonalNote: SecureModelProtocol, @unchecked Sendable {
    
    public let id: UUID
    public let communicationID: UUID
    public var data: Data
    
    enum CodingKeys: String, CodingKey, Codable, Sendable {
        case id = "a"
        case communicationID = "b"
        case data = "c"
    }
    
    /// SymmetricKey can be updated.
    private var symmetricKey: SymmetricKey?
    
    /// Asynchronously retrieves the decrypted properties, if available.
    public var props: UnwrappedProps? {
        get async {
            do {
                guard let symmetricKey = symmetricKey else { return nil }
                return try await decryptProps(symmetricKey: symmetricKey)
            } catch {
                return nil
            }
        }
    }

    /// Struct representing the unwrapped properties of the message.
    /// A struct representing the properties of a message in a communication, including its delivery state and timestamps.
    public struct UnwrappedProps: Codable, Sendable, CommunicationProtocol {
        /// The base object for all Communication Types
        public var base: BaseCommunication
        /// The date and time when the message was sent.
        public let createdData: Date
        /// The date and time when the message was received.
        public let receiveDate: Date?
        /// The message content.
        public var messages: [PrivateMessage]
        public let recipient: MessageRecipient
        
        // MARK: - Coding Keys
        private enum CodingKeys: String, CodingKey, Codable, Sendable {
            case base = "a"
            case createdData = "b"
            case receiveDate = "c"
            case messages = "d"
            case recipient = "e"
        }
        
        /// Initializes a new instance of `UnwrappedProps`.
        /// - Parameters:
        ///   - createdData: The date and time when the message was created.
        ///   - receiveDate: The date and time when the message was received.
        ///   - deliveryState: The current delivery state of the message.
        ///   - message: The content of the message.
        ///   - sendersSecretName: The sender's secret name.
        ///   - sendersIdentity: The unique identifier for the sender's identity.
        public init(
            base: BaseCommunication,
            createdData: Date,
            receiveDate: Date? = nil,
            messages: [PrivateMessage],
            recipient: MessageRecipient
        ) {
            self.base = base
            self.createdData = createdData
            self.receiveDate = receiveDate
            self.messages = messages
            self.recipient = recipient
        }
    }
    
    /// Initializes a new MessageModel instance.
    /// - Parameters:
    ///   - communicationID: The ID of the communication.
    ///   - senderIdentity: The ID of the sender.
    ///   - sharedMessageIdentity: The remote ID associated with the message.
    ///   - props: The unwrapped properties of the message.
    ///   - symmetricKey: The symmetric key used for encryption.
    /// - Throws: An error if encryption fails.
    public init(
        communicationID: UUID,
        props: UnwrappedProps,
        symmetricKey: SymmetricKey
    ) async throws {
        self.id = UUID()
        self.communicationID = communicationID
        self.symmetricKey = symmetricKey
        
        let crypto = NeedleTailCrypto()
        let data = try BSONEncoder().encodeData(props)
        guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.encryptionFailed
        }
        self.data = encryptedData
    }
    
    public init(
        communicationID: UUID,
        data: Data
    ) async throws {
        self.id = UUID()
        self.communicationID = communicationID
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
    /// - Throws: An error if encryption fails.
    public func updateProps(symmetricKey: SymmetricKey, props: UnwrappedProps) async throws -> UnwrappedProps? {
        let crypto = NeedleTailCrypto()
        let data = try BSONEncoder().encodeData(props)
        guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.encryptionFailed
        }
        self.data = encryptedData
        return await self.props
    }
    
    public func makeDecryptedModel<T: Sendable & Codable>(of: T.Type, symmetricKey: SymmetricKey) async throws -> T {
        self.symmetricKey = symmetricKey
        guard let props = await props else { throw CryptoError.propsError }
        return _PersonalNote(
            id: id,
            createdData: props.createdData,
            recipient: props.recipient,
            base: props.base,
            messages: props.messages) as! T
    }
}
