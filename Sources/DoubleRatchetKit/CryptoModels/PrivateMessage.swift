//
//  Message.swift
//  needletail-crypto
//
//  Created by Cole M on 9/13/24.
//
import Foundation
import Crypto
import BSON
import NIOConcurrencyHelpers
import NeedleTailCrypto

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

extension SecureModelProtocol {
    
    public func deriveRecipient(symmetricKey: SymmetricKey) async throws -> MessageRecipient {
        switch self {
        case let messageType as PrivateMessage:
            guard let props = await messageType.props(symmetricKey: symmetricKey) else {
                throw DerivationError.invalidProps
            }
            return props.message.recipient
            
        case let messageType as Channel:
            guard let props = await messageType.props(symmetricKey: symmetricKey) else {
                throw DerivationError.invalidProps
            }
            return props.recipient
            
        case let messageType as PersonalNote:
            guard let props = await messageType.props(symmetricKey: symmetricKey) else {
                throw DerivationError.invalidProps
            }
            return props.recipient
            
        default:
            throw DerivationError.unsupportedType
        }
    }
}

public struct _PrivateMessage: Sendable, Codable, Equatable {
    public let id: UUID
    public var base: BaseCommunication
    public let sendDate: Date
    public let receiveDate: Date?
    public var deliveryState: DeliveryState
    public var message: CryptoMessage
    public let sendersSecretName: String
    public let sendersDeviceId: UUID
    
    public static func == (lhs: _PrivateMessage, rhs: _PrivateMessage) -> Bool {
        return lhs.id == rhs.id
    }
}



/// This model represents a message and provides an interface for working with encrypted data.
/// The public interface is for creating local models to be saved to the database as encrypted data.
public final class PrivateMessage: SecureModelProtocol, @unchecked Sendable, Hashable {
    
    public let id: UUID
    public let communicationId: UUID
    public let sessionContextId: Int
    public let sharedId: String
    public let sequenceNumber: Int
    public var data: Data
    private let lock = NIOLock()
    
    enum CodingKeys: String, CodingKey, Codable, Sendable {
        case id
        case communicationId = "a"
        case sessionContextId = "b"
        case sharedId = "c"
        case sequenceNumber = "d"
        case data = "e"
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
    /// A struct representing the properties of a message in a communication, including its delivery state and timestamps.
    public struct UnwrappedProps: Codable, Sendable, CommunicationProtocol {
        /// The base object for all Communication Types
        public var base: BaseCommunication
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
        public let sendersDeviceId: UUID
        
        // MARK: - Coding Keys
        private enum CodingKeys: String, CodingKey, Codable, Sendable {
            case base = "a"
            case sendDate = "b"
            case receiveDate = "c"
            case deliveryState = "d"
            case message = "e"
            case sendersSecretName = "f"
            case sendersDeviceId = "g"
        }
        
        /// Initializes a new instance of `UnwrappedProps`.
        /// - Parameters:
        ///   - sendDate: The date and time when the message was sent.
        ///   - receiveDate: The date and time when the message was received.
        ///   - deliveryState: The current delivery state of the message.
        ///   - message: The content of the message.
        ///   - sendersSecretName: The sender's secret name.
        ///   - sendersDeviceId: The unique identifier for the sender's identity.
        public init(
            base: BaseCommunication,
            sendDate: Date,
            receiveDate: Date? = nil,
            deliveryState: DeliveryState,
            message: CryptoMessage,
            sendersSecretName: String,
            sendersDeviceId: UUID
        ) {
            self.base = base
            self.sendDate = sendDate
            self.receiveDate = receiveDate
            self.deliveryState = deliveryState
            self.message = message
            self.sendersSecretName = sendersSecretName
            self.sendersDeviceId = sendersDeviceId
        }
    }
    
    /// Initializes a new MessageModel instance.
    /// - Parameters:
    ///   - communicationIdentity: The ID of the communication.
    ///   - senderIdentity: The ID of the sender.
    ///   - sharedMessageIdentity: The remote ID associated with the message.
    ///   - sequenceId: The sequenceId of the message in the communication.
    ///   - props: The unwrapped properties of the message.
    ///   - symmetricKey: The symmetric key used for encryption.
    /// - Throws: An error if encryption fails.
    public init(
        id: UUID,
        communicationId: UUID,
        sessionContextId: Int,
        sharedId: String,
        sequenceNumber: Int,
        props: UnwrappedProps,
        symmetricKey: SymmetricKey
    ) throws {
        self.id = id
        self.communicationId = communicationId
        self.sessionContextId = sessionContextId
        self.sharedId = sharedId
        self.sequenceNumber = sequenceNumber
        
        let crypto = NeedleTailCrypto()
        let data = try BSONEncoder().encodeData(props)
        guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
            throw CryptoError.encryptionFailed
        }
        self.data = encryptedData
    }
    
    public init(
        id: UUID,
        communicationId: UUID,
        sessionContextId: Int,
        sharedId: String,
        sequenceNumber: Int,
        data: Data
    ) throws {
        self.id = id
        self.communicationId = communicationId
        self.sessionContextId = sessionContextId
        self.sharedId = sharedId
        self.sequenceNumber = sequenceNumber
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
        lock.lock()
        self.data = encryptedData
        lock.unlock()
        return try await decryptProps(symmetricKey: symmetricKey)
    }
    
    public func makeDecryptedModel<T: Sendable & Codable>(of: T.Type, symmetricKey: SymmetricKey) async throws -> T {
        guard let props = await props(symmetricKey: symmetricKey) else {
            throw CryptoError.propsError
        }
        return _PrivateMessage(
            id: id,
            base: props.base,
            sendDate: props.sendDate,
            receiveDate: props.receiveDate,
            deliveryState: props.deliveryState,
            message: props.message,
            sendersSecretName: props.sendersSecretName,
            sendersDeviceId: props.sendersDeviceId) as! T
    }
    
    public func updatePropsMetadata(symmetricKey: SymmetricKey, metadata: Data, with key: String) async throws -> UnwrappedProps? {
        var props = try await decryptProps(symmetricKey: symmetricKey)
        lock.lock()
        props.message.metadata[key] = metadata
        lock.unlock()
        return try await updateProps(symmetricKey: symmetricKey, props: props)
    }
    
    public static func == (lhs: PrivateMessage, rhs: PrivateMessage) -> Bool {
        return lhs.id == rhs.id
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
}

/// An enumeration representing the delivery state of a message in a communication.
public enum DeliveryState: Codable, Sendable, Equatable {
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


/// Custom error type for encryption-related errors.
public enum CryptoError: Error {
    case encryptionFailed, decryptionError, propsError
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
    /// A notication indicating theat the recipient is being nudge to wake up a communicate.
    case nudge
}

/// An enumeration representing the different types of messages that can be sent or received.
public enum MessageType: String, Codable, Sendable {
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
    case server
}

/// An enumeration representing the different types of message recipients in a messaging network.
public enum MessageRecipient: Codable, Sendable, Equatable {
    /// A personal message intended for the user, visible across all their devices and to others on the network.
    /// This case is used for messages that are specifically directed to the user but are not private.
    case personalMessage
    /// A recipient identified by a nickname.
    /// This case is used when sending a message to a user identified by their chosen nickname.
    case nickname(String)
    /// A recipient identified by a channel name.
    /// This case is used when sending a message to a specific channel where multiple users can participate.
    case channel(String)
    /// A recipient for broadcast messages sent to multiple users.
    /// This case is used for messages intended to be sent to all users in the network or a specific group.
    case broadcast
    
    /// Computed property to derive the nickname string if applicable.
    public var nicknameDescription: String {
        switch self {
        case .nickname(let name):
            return name
        default:
            fatalError()
        }
    }
}

public enum MessageFlags: Codable, Sendable, Equatable {
    case friendshipStateRequest(Data?), deliveryStateChange, editMessage, editMessageMetadata(String), notifyContactRemoval, isTyping(Data), multipart, registerVoIP(Data), registerAPN(Data), publishUserConfiguration, newDevice(Data), unlinkedDevice(Data), ack(Data), audio, image, thumbnail, doc, requestMediaResend, revokeMessage, communicationSynchronization, contactCreated, contactUpdated, addContacts, synchronizeContacts, dccSymmetricKey, start_call, sdp_offer(OfferAnswerMetadata), sdp_answer(OfferAnswerMetadata), ice_candidate, end_call, hold_call, upgrade_to_video(Bool), downgrade_to_audio(Bool), none
}

public struct OfferAnswerMetadata: Codable, Sendable, Equatable {
    public var sharedMessageId: String?
    public let communicationId: String
    public let supportsVideo: Bool
    
    public init(sharedMessageId: String? = nil, communicationId: String, supportsVideo: Bool) {
        self.sharedMessageId = sharedMessageId
        self.communicationId = communicationId
        self.supportsVideo = supportsVideo
    }
}

public struct CryptoMessage: Codable, Sendable {
    public let messageType: MessageType
    public let messageFlags: MessageFlags
    public let recipient: MessageRecipient
    public var text: String
    public var pushType: PushNotificationType
    public var metadata: Document
    public let sentDate: Date
    public let destructionTime: TimeInterval?
    public var updatedDate: Date?
    
    private enum CodingKeys: String, CodingKey, Codable, Sendable {
        case messageType = "a"
        case messageFlags = "b"
        case recipient = "c"
        case text = "d"
        case pushType = "e"
        case metadata = "f"
        case sentDate = "g"
        case destructionTime = "h"
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
        destructionTime: TimeInterval?,
        updatedDate: Date? = nil
    ) {
        self.messageType = messageType
        self.messageFlags = messageFlags
        self.recipient = recipient
        self.text = text
        self.pushType = pushType
        self.metadata = metadata
        self.sentDate = sentDate
        self.destructionTime = destructionTime
        self.updatedDate = updatedDate
    }
}
