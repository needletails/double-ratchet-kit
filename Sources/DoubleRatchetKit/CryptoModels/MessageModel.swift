//
//  Message.swift
//  needletail-crypto
//
//  Created by Cole M on 9/13/24.
//
import Foundation
import Crypto
import BSON
import Foundation
import NeedleTailHelpers
import NeedleTailCrypto

/// Protocol defining the base model functionality.
public protocol SessionModel: Codable, Sendable {
    associatedtype Props: Codable & Sendable
    
    /// Asynchronously sets the properties of the model using the provided symmetric key.
    /// - Parameter symmetricKey: The symmetric key used for decryption.
    /// - Returns: The decrypted properties.
    func setProps(symmetricKey: SymmetricKey) async throws -> Props
    
    /// Updates the properties with the provided symmetric key.
    /// - Parameter symmetricKey: The symmetric key used for decryption.
    /// - Parameter props: The properties to update.
    /// - Returns: The updated properties, or nil if the update failed.
    func updateProps(symmetricKey: SymmetricKey, props: Props) async throws -> Props?
}

/// This model represents a message and provides an interface for working with encrypted data.
/// The public interface is for creating local models to be saved to the database as encrypted data.
public final class MessageModel: SessionModel, @unchecked Sendable {
    
    public let id: UUID
    public let communicationID: UUID
    public let senderIdentity: Int
    public let sequenceId: Int
    public let sharedMessageIdentity: String
    public var data: Data
    
    enum CodingKeys: String, CodingKey, Codable, Sendable {
        case id = "a"
        case communicationID = "b"
        case senderIdentity = "c"
        case sequenceId = "d"
        case sharedMessageIdentity = "e"
        case data = "f"
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
    
    
    /// An enumeration representing the delivery state of a message in a communication.
    public enum DeliveryState: Codable, Sendable {
        /// The message has been successfully delivered to the recipient.
        case delivered
        /// The message has been read by the recipient.
        case read
        /// The message has been received by the recipient's device but not yet read.
        case received
        /// The message is currently waiting to be delivered (e.g., due to network issues).
        case waitingDelivery
        /// The message has not been sent or is in an undefined state.
        case none
        /// The message has been blocked from being delivered (e.g., by the recipient's settings).
        case blocked
        /// The message failed to be delivered due to an error (e.g., network failure).
        case failed(String)
        /// The message is in the process of being sent but has not yet been delivered.
        case sending
        /// The message has been scheduled for delivery at a later time.
        case scheduled(Date)
    }

    /// Struct representing the unwrapped properties of the message.
    /// A struct representing the properties of a message in a communication, including its delivery state and timestamps.
    public struct UnwrappedProps: Codable, Sendable, CommunicationSession {
        /// The base object for all Communication Types
        public var base: CommunicationModel
        /// The date and time when the message was sent.
        public let sendDate: Date
        /// The date and time when the message was received.
        public let receiveDate: Date?
        /// The current delivery state of the message.
        public var deliveryState: DeliveryState
        /// The message content.
        public var message: CryptoMessage
        /// The sender's secret name, which may be used for privacy.
        public let sendersSecretName: String
        /// The unique identifier for the sender's identity.
        public let sendersIdentity: UUID
        
        // MARK: - Coding Keys
        private enum CodingKeys: String, CodingKey, Codable, Sendable {
            case base = "a"
            case sendDate = "b"
            case receiveDate = "c"
            case deliveryState = "d"
            case message = "e"
            case sendersSecretName = "f"
            case sendersIdentity = "g"
        }
        
        /// Initializes a new instance of `UnwrappedProps`.
        /// - Parameters:
        ///   - sendDate: The date and time when the message was sent.
        ///   - receiveDate: The date and time when the message was received.
        ///   - deliveryState: The current delivery state of the message.
        ///   - message: The content of the message.
        ///   - sendersSecretName: The sender's secret name.
        ///   - sendersIdentity: The unique identifier for the sender's identity.
        public init(
            base: CommunicationModel,
            sendDate: Date,
            receiveDate: Date? = nil,
            deliveryState: DeliveryState,
            message: CryptoMessage,
            sendersSecretName: String,
            sendersIdentity: UUID
        ) {
            self.base = base
            self.sendDate = sendDate
            self.receiveDate = receiveDate
            self.deliveryState = deliveryState
            self.message = message
            self.sendersSecretName = sendersSecretName
            self.sendersIdentity = sendersIdentity
        }
    }
    
    /// Initializes a new MessageModel instance.
    /// - Parameters:
    ///   - communicationID: The ID of the communication.
    ///   - senderIdentity: The ID of the sender.
    ///   - sharedMessageIdentity: The remote ID associated with the message.
    ///   - sequenceId: The sequenceId of the message in the communication.
    ///   - props: The unwrapped properties of the message.
    ///   - symmetricKey: The symmetric key used for encryption.
    /// - Throws: An error if encryption fails.
    public init(
        communicationID: UUID,
        senderIdentity: Int,
        sharedMessageIdentity: String,
        sequenceId: Int,
        props: UnwrappedProps,
        symmetricKey: SymmetricKey
    ) async throws {
        self.id = UUID()
        self.communicationID = communicationID
        self.senderIdentity = senderIdentity
        self.sharedMessageIdentity = sharedMessageIdentity
        self.sequenceId = sequenceId
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
}

/// Custom error type for encryption-related errors.
public enum CryptoError: Error {
    case encryptionFailed, decryptionError
}

// An enumeration representing the different types of push notifications that can be received.
public enum PushNotificationType: Codable, Sendable {
    /// A notification indicating that a new message has been received.
    case message
    /// A notification indicating an incoming call.
    case call
    /// A notification indicating that there are no active notifications.
    case none
    /// A notification indicating that a user would like to be one of your contacts
    case contactRequest
}

/// An enumeration representing the different types of messages that can be sent or received.
public enum MessageType: Codable, Sendable {
    /// A text message containing plain text content.
    case text
    /// A binary message containing raw binary data.
    case binary
    /// A message containing media content, such as images or videos.
    case media
    /// A nudgeServer message, typically used to send a message to the end point, but will not save a SignedRatchetMessage to the remote DB
    case nudgeServer
    /// A nudgeLocal message, typically used to send a message to the end point, but will not save a CryptoMessage to the local DB
    case nudgeLocal
    /// A message type indicating that there is no specific type assigned.
    case none
}

/// An enumeration representing the different types of message recipients in a messaging network.
public enum MessageRecipient: Codable, Sendable {
    /// A recipient identified by a nickname.
    /// This case is used when sending a message to a user identified by their chosen nickname.
    case nickname(String)
    /// A recipient identified by a channel name.
    /// This case is used when sending a message to a specific channel where multiple users can participate.
    case channel(String)
    /// A recipient for broadcast messages sent to multiple users.
    /// This case is used for messages intended to be sent to all users in the network or a specific group.
    case broadcast
    /// A personal message intended for the user, visible across all their devices and to others on the network.
    /// This case is used for messages that are specifically directed to the user but are not private.
    case personalMessage
}

public enum MessageFlags: Codable, Sendable {
    case friendshipStateRequest, deliveryStateChange, editMessage, none
    
}

public struct CryptoMessage: Codable, Sendable {
    public let messageType: MessageType
    public let messageFlags: MessageFlags
    public let recipient: MessageRecipient
    public var text: String
    public var pushType: PushNotificationType
    public var metadata: Document
    public let sentDate: Date
    public let destructionDate: Date?
    public var updatedDate: Date?
    
    private enum CodingKeys: String, CodingKey, Codable, Sendable {
        case messageType = "a"
        case messageFlags = "b"
        case recipient = "c"
        case text = "d"
        case pushType = "e"
        case metadata = "f"
        case sentDate = "g"
        case destructionDate = "h"
        case updatedDate = "i"
    }
    
    public init(
        messageType: MessageType,
        messageFlags: MessageFlags,
        recipient: MessageRecipient,
        text: String,
        pushType: PushNotificationType,
        metadata: Document,
        sentDate: Date,
        destructionDate: Date?,
        updatedDate: Date? = nil
    ) {
        self.messageType = messageType
        self.messageFlags = messageFlags
        self.recipient = recipient
        self.text = text
        self.pushType = pushType
        self.metadata = metadata
        self.sentDate = sentDate
        self.destructionDate = destructionDate
        self.updatedDate = updatedDate
    }
}
