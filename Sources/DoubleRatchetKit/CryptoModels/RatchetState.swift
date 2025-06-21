//
//  RatchetState.swift
//  double-ratchet-kit
//
//  Created by Cole M on 6/16/25.
//
import Crypto
import Foundation

public typealias RemotePublicLongTermKey = Data
public typealias RemotePublicOneTimeKey = Curve25519PublicKeyRepresentable
public typealias RemoteKyber1024PublicKey = Kyber1024PublicKeyRepresentable
public typealias LocalPrivateLongTermKey = Data
public typealias LocalPrivateOneTimeKey = Curve25519PrivateKeyRepresentable
public typealias LocalKyber1024PrivateKey = Kyber1024PrivateKeyRepresentable

typealias LocalPrivateKey = Data
typealias RemotePublicKey = Data

/// A protocol defining operations related to managing a session identity and associated cryptographic keys.
///
/// Conforming types are responsible for persisting and retrieving identity and one-time key information.
/// This is typically implemented by a storage layer (e.g. database, in-memory store, or secure enclave manager).
public protocol SessionIdentityDelegate: AnyObject, Sendable {
    
    /// Updates the stored session identity.
    ///
    /// - Parameter identity: The new session identity to persist.
    /// - Throws: An error if the update operation fails.
    func updateSessionIdentity(_ identity: SessionIdentity) async throws
    
    /// Fetches a previously stored private one-time Curve25519 key by its unique identifier.
    ///
    /// - Parameter id: The UUID of the one-time key to retrieve.
    /// - Returns: The corresponding `Curve25519PrivateKeyRepresentable`.
    /// - Throws: An error if the key could not be found or retrieved.
    func fetchPrivateOneTimeKey(_ id: UUID?) async throws -> Curve25519PrivateKeyRepresentable?
    
    /// Notifies that a new one-time key should be generated and made available.
    ///
    /// This may trigger background key generation or publication to a server.
    func updateOneTimeKey(remove id: UUID) async
}


/// Represents a set of skipped message keys for later processing in the Double Ratchet protocol.
public struct SkippedMessageKey: Codable, Sendable {
    /// The public key of the sender associated with the skipped message.
    let remotePublicLongTermKey: Data
    
    /// The public key of the sender associated with the skipped message.
    let remotePublicOneTimeKey: Data?
    
    let remoteKyber1024PublicKey: Data
    
    /// The index of the skipped message.
    let messageIndex: Int
    
    /// The symmetric key used to encrypt the skipped message.
    let chainKey: SymmetricKey
    
    private enum CodingKeys: String, CodingKey, Sendable {
        case remotePublicLongTermKey = "a"
        case remotePublicOneTimeKey = "b"
        case remoteKyber1024PublicKey = "c"
        case messageIndex = "d"
        case chainKey = "e"
    }
}

/// Represents an encrypted message along with its header in the Double Ratchet protocol.
public struct RatchetMessage: Codable, Sendable, Hashable {
    /// The header containing metadata about the message.
    public let header: EncryptedHeader
    
    /// The encrypted content of the message.
    let encryptedData: Data
    
    private enum CodingKeys: String, CodingKey, Sendable {
        case header = "a"
        case encryptedData = "b"
    }
    
    /// Initializes a new RatchetMessage with the specified header and encrypted data.
    /// - Parameters:
    ///   - header: The header of the encrypted message.
    ///   - encryptedData: The encrypted content of the message.
    public init(header: EncryptedHeader, encryptedData: Data) {
        self.header = header
        self.encryptedData = encryptedData
    }
}

/// Represents the header of an encrypted message in the Double Ratchet protocol.
public struct EncryptedHeader: Sendable, Codable, Hashable {
    
    /// Sender's long-term public key.
    public let remotePublicLongTermKey: RemotePublicLongTermKey
    
    /// Sender's one-time public key.
    public let remotePublicOneTimeKey: RemotePublicOneTimeKey?
    
    /// Sender's Kyber1024 public key used for key agreement.
    public let remoteKyber1024PublicKey: RemoteKyber1024PublicKey
    
    /// Header encapsulated ciphertext.
    public let headerCiphertext: Data
    
    /// Message encapsulated ciphertext.
    public let messageCiphertext: Data
    
    public let curveOneTimeKeyId: UUID?
    
    public let kyberOneTimeKeyId: UUID?
    
    /// Encrypted header body (e.g., BSON).
    public let encrypted: Data
    
    /// Only exists at runtime after decryption.
    public private(set) var decrypted: MessageHeader?
    
    /// Sets the decrypted message header.
    /// - Parameter decrypted: The decrypted message header to set.
    public mutating func setDecrypted(_ decrypted: MessageHeader) {
        self.decrypted = decrypted
    }
    
    private enum CodingKeys: String, CodingKey, Sendable {
        case remotePublicLongTermKey = "a"
        case remotePublicOneTimeKey = "b"
        case remoteKyber1024PublicKey = "c"
        case headerCiphertext = "d"
        case messageCiphertext = "e"
        case curveOneTimeKeyId = "f"
        case kyberOneTimeKeyId = "g"
        case encrypted = "h"
    }
    
    /// Initializes the EncryptedHeader without a decrypted header (sending case).
    /// - Parameters:
    ///   - remotePublicLongTermKey: The sender's long-term public key.
    ///   - remotePublicOneTimeKey: The sender's one-time public key.
    ///   - remoteKyber1024PublicKey: The sender's Kyber1024 public key.
    ///   - headerCiphertext: The ciphertext of the header.
    ///   - messageCiphertext: The ciphertext of the message.
    ///   - encrypted: The encrypted body of the header.
    public init(
        remotePublicLongTermKey: RemotePublicLongTermKey,
        remotePublicOneTimeKey: RemotePublicOneTimeKey?,
        remoteKyber1024PublicKey: RemoteKyber1024PublicKey,
        headerCiphertext: Data,
        messageCiphertext: Data,
        curveOneTimeKeyId: UUID?,
        kyberOneTimeKeyId: UUID,
        encrypted: Data
    ) {
        self.remotePublicLongTermKey = remotePublicLongTermKey
        self.remotePublicOneTimeKey = remotePublicOneTimeKey
        self.remoteKyber1024PublicKey = remoteKyber1024PublicKey
        self.headerCiphertext = headerCiphertext
        self.messageCiphertext = messageCiphertext
        self.curveOneTimeKeyId = curveOneTimeKeyId
        self.kyberOneTimeKeyId = kyberOneTimeKeyId
        self.encrypted = encrypted
        self.decrypted = nil
    }
    
    /// Initializes the EncryptedHeader with a decrypted header (receiving case).
    /// - Parameters:
    ///   - remotePublicLongTermKey: The sender's long-term public key.
    ///   - remotePublicOneTimeKey: The sender's one-time public key.
    ///   - remoteKyber1024PublicKey: The sender's Kyber1024 public key.
    ///   - headerCiphertext: The ciphertext of the header.
    ///   - messageCiphertext: The ciphertext of the message.
    ///   - encrypted: The encrypted body of the header.
    ///   - decrypted: The decrypted **MessageHeader**.
    public init(
        remotePublicLongTermKey: RemotePublicLongTermKey,
        remotePublicOneTimeKey: RemotePublicOneTimeKey,
        remoteKyber1024PublicKey: RemoteKyber1024PublicKey,
        headerCiphertext: Data,
        messageCiphertext: Data,
        encrypted: Data,
        curveOneTimeKeyId: UUID?,
        kyberOneTimeKeyId: UUID,
        decrypted: MessageHeader
    ) {
        self.remotePublicLongTermKey = remotePublicLongTermKey
        self.remotePublicOneTimeKey = remotePublicOneTimeKey
        self.remoteKyber1024PublicKey = remoteKyber1024PublicKey
        self.headerCiphertext = headerCiphertext
        self.messageCiphertext = messageCiphertext
        self.encrypted = encrypted
        self.curveOneTimeKeyId = curveOneTimeKeyId
        self.kyberOneTimeKeyId = kyberOneTimeKeyId
        self.decrypted = decrypted
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(remotePublicLongTermKey)
        hasher.combine(remotePublicOneTimeKey)
        hasher.combine(remoteKyber1024PublicKey)
        hasher.combine(headerCiphertext)
        hasher.combine(messageCiphertext)
        hasher.combine(curveOneTimeKeyId)
        hasher.combine(kyberOneTimeKeyId)
        hasher.combine(encrypted)
    }
    
    public static func == (lhs: EncryptedHeader, rhs: EncryptedHeader) -> Bool {
        return lhs.remotePublicLongTermKey == rhs.remotePublicLongTermKey
        && lhs.remotePublicOneTimeKey   == rhs.remotePublicOneTimeKey
        && lhs.remoteKyber1024PublicKey == rhs.remoteKyber1024PublicKey
        && lhs.headerCiphertext         == rhs.headerCiphertext
        && lhs.messageCiphertext        == rhs.messageCiphertext
        && lhs.curveOneTimeKeyId        == rhs.curveOneTimeKeyId
        && lhs.kyberOneTimeKeyId        == rhs.kyberOneTimeKeyId
        && lhs.encrypted                == rhs.encrypted
    }
}

/// Represents the header of a message in the Double Ratchet protocol.
public struct MessageHeader: Sendable, Codable {
    
    /// The length of the previous message chain.
    public let previousChainLength: Int
    
    public let messageNumber: Int
    
    
    private enum CodingKeys: String, CodingKey, Sendable {
        case previousChainLength = "a"
        case messageNumber = "b"
    }
    
    /// Initializes a new MessageHeader with the specified parameters.
    /// - Parameters:
    ///   - previousChainLength: The length of the previous message chain.
    public init(
        previousChainLength: Int,
        messageNumber: Int
    ) {
        self.previousChainLength = previousChainLength
        self.messageNumber = messageNumber
    }
}

/// Configuration for the Double Ratchet protocol, defining parameters for key management.
public struct RatchetConfiguration: Sendable, Codable {
    let messageKeyData: Data         // Data used to derive message keys.
    let chainKeyData: Data           // Data used to derive chain keys.
    let rootKeyData: Data            // Data used to derive the root key.
    let associatedData: Data          // Additional data associated with the messages.
    let maxSkippedMessageKeys: Int    // Maximum number of skipped message keys to retain.
    
    private enum CodingKeys: String, CodingKey, Sendable {
        case messageKeyData = "a"
        case chainKeyData = "b"
        case rootKeyData = "c"
        case associatedData = "d"
        case maxSkippedMessageKeys = "e"
    }
    
    /// Initializes a new RatchetConfiguration with the specified parameters.
    /// - Parameters:
    ///   - messageKeyData: Data used to derive message keys.
    ///   - chainKeyData: Data used to derive chain keys.
    ///   - rootKeyData: Data used to derive the root key.
    ///   - associatedData: Additional data associated with the messages.
    ///   - maxSkippedMessageKeys: Maximum number of skipped message keys to retain.
    public init(
        messageKeyData: Data,
        chainKeyData: Data,
        rootKeyData: Data,
        associatedData: Data,
        maxSkippedMessageKeys: Int
    ) {
        self.messageKeyData = messageKeyData
        self.chainKeyData = chainKeyData
        self.rootKeyData = rootKeyData
        self.associatedData = associatedData
        self.maxSkippedMessageKeys = maxSkippedMessageKeys
    }
}

/// Default configuration for the Double Ratchet protocol.
let defaultRatchetConfiguration = RatchetConfiguration(
    messageKeyData: Data([0x00]),                // Data for message key derivation.
    chainKeyData: Data([0x01]),                  // Data for chain key derivation.
    rootKeyData: Data([0x02, 0x03]),             // Data for root key derivation.
    associatedData: "DoubleRatchetKit".data(using: .ascii)!, // Associated data for messages.
    maxSkippedMessageKeys: 80                     // Maximum number of skipped message keys to retain.
)

/// Represents the state of the Double Ratchet protocol.
public struct RatchetState: Sendable, Codable {
    
    /// Coding keys for encoding and decoding the RatchetState.
    enum CodingKeys: String, CodingKey, Sendable, Codable {
        case localPrivateLongTermKey = "a"             // Local long-term private key.
        case localPrivateOneTimeKey = "b"              // Local one-time private key.
        case localKyber1024PrivateKey = "c"            // Local post-quantum key exchange private key.
        case remotePublicLongTermKey = "d"             // Remote long-term public key.
        case remotePublicOneTimeKey = "e"              // Remote one-time public key.
        case remoteKyber1024PublicKey = "f"            // Remote post-quantum key exchange public key.
        case messageCiphertext = "g"                   // Ciphertext of the message.
        case rootKey = "h"                             // Root symmetric key.
        case sendingKey = "i"                          // Chain key for sending.
        case receivingKey = "j"                        // Chain key for receiving.
        case sentMessagesCount = "k"                   // Count of sent messages.
        case receivedMessagesCount = "l"               // Count of received messages.
        case previousMessagesCount = "m"               // Count of messages in the previous sending chain.
        case skippedHeaderMesages = "n"                // Dictionary of skipped header keys.
        case skippedMessageKeys = "o"                  // Dictionary of skipped message keys.
        case headerCiphertext = "p"                    // Header ciphertext.
        case sendingHeaderKey = "q"                    // Current sending header key.
        case nextSendingHeaderKey = "r"                // Next sending header key.
        case receivingHeaderKey = "s"                  // Current receiving header key.
        case nextReceivingHeaderKey = "t"              // Next receiving header key.
        case sendingHandshakeFinished = "u"            // Whether the sending initial handshake has completed.
        case receivingHandshakeFinished = "v"          // Whether the receiving initial handshake has completed.
        case lastSkippedIndex = "w"                    // Last skipped message index.
        case headerIndex = "x"                         // Index of the skipped header.
        case lastDecryptedMessageNumber = "y"          // The message number for the last decrytped message.
        case alreadyDecryptedMessageNumbers = "z"      // A Set of already decrypted messages
    }
    
    
    // MARK: - Properties
    
    /// Local long-term private key.
    private(set) public var localPrivateLongTermKey: LocalPrivateLongTermKey
    
    /// Local one-time private key.
    private(set) public var localPrivateOneTimeKey: LocalPrivateOneTimeKey?
    
    /// Local post-quantum key exchange private key.
    private(set) public var localKyber1024PrivateKey: LocalKyber1024PrivateKey
    
    /// Remote long-term public key.
    private(set) public var remotePublicLongTermKey: RemotePublicLongTermKey
    
    /// Remote one-time public key.
    private(set) public var remotePublicOneTimeKey: RemotePublicOneTimeKey?
    
    /// Remote post-quantum key exchange public key.
    private(set) public var remoteKyber1024PublicKey: RemoteKyber1024PublicKey
    
    /// Ciphertext of the message being sent or received.
    private(set) var messageCiphertext: Data?
    
    /// Root symmetric key used for encryption.
    private(set) var rootKey: SymmetricKey?
    
    /// Current chain key for sending messages.
    private(set) var sendingKey: SymmetricKey?
    
    /// Current chain key for receiving messages.
    private(set) var receivingKey: SymmetricKey?
    
    /// Count of messages sent.
    private(set) var sentMessagesCount: Int = 0
    
    /// Count of messages received.
    private(set) var receivedMessagesCount: Int = 0
    
    /// Count of messages in the previous sending chain.
    private(set) var previousMessagesCount: Int = 0
    
    /// List of skipped message keys.
    private(set) var skippedMessageKeys = [SkippedMessageKey]()
    
    /// Last Skipped Message
    private(set) var lastSkippedIndex: Int = 0
    
    /// A list of Skipped Header Message
    private(set) var skippedHeaderMesages = [SkippedHeaderMessage]()
    
    /// The Index of the Skipped Header
    private(set) var headerIndex: Int = 0
    
    /// Ciphertext for the header.
    private(set) var headerCiphertext: Data?
    
    /// Current sending header key.
    private(set) var sendingHeaderKey: SymmetricKey?
    
    /// Next sending header key.
    private(set) var nextSendingHeaderKey: SymmetricKey?
    
    /// Current receiving header key.
    private(set) var receivingHeaderKey: SymmetricKey?
    
    /// Next receiving header key.
    private(set) var nextReceivingHeaderKey: SymmetricKey?
    
    /// Indicates if the sending hanshake has finished
    private(set) var sendingHandshakeFinished: Bool = false
    
    /// Indicates if the receiving hanshake has finished
    private(set) var receivingHandshakeFinished: Bool = false
    
    /// Indicates if the receiving hanshake has finished
    private(set) var lastDecryptedMessageNumber: Int = 0
    
    private(set) var alreadyDecryptedMessageNumbers = Set<Int>()
    
    // MARK: - Initializers
    
    /// Initializes a new RatchetState with the provided keys and parameters for receiving.
    /// - Parameters:
    ///   - remotePublicLongTermKey: The remote party's long-term public key.
    ///   - remotePublicOneTimeKey: The remote party's one-time public key.
    ///   - remoteKyber1024PublicKey: The remote party's post-quantum key exchange public key.
    ///   - localPrivateLongTermKey: The local party's long-term private key.
    ///   - localPrivateOneTimeKey: The local party's one-time private key.
    ///   - localKyber1024PrivateKey: The local party's post-quantum key exchange private key.
    ///   - rootKey: The root symmetric key used for encryption.
    ///   - messageCiphertext: The ciphertext of the message being sent or received.
    ///   - receivingKey: The current chain key for receiving messages.
    init(
        remotePublicLongTermKey: RemotePublicLongTermKey,
        remotePublicOneTimeKey: RemotePublicOneTimeKey?,
        remoteKyber1024PublicKey: RemoteKyber1024PublicKey,
        localPrivateLongTermKey: LocalPrivateLongTermKey,
        localPrivateOneTimeKey: LocalPrivateOneTimeKey?,
        localKyber1024PrivateKey: LocalKyber1024PrivateKey
    ) {
        self.remotePublicLongTermKey = remotePublicLongTermKey
        self.remotePublicOneTimeKey = remotePublicOneTimeKey
        self.remoteKyber1024PublicKey = remoteKyber1024PublicKey
        self.localPrivateLongTermKey = localPrivateLongTermKey
        self.localPrivateOneTimeKey = localPrivateOneTimeKey
        self.localKyber1024PrivateKey = localKyber1024PrivateKey
    }
    
    /// Initializes a new RatchetState with the provided keys and parameters for sending.
    /// - Parameters:
    ///   - remotePublicLongTermKey: The remote party's long-term public key.
    ///   - remotePublicOneTimeKey: The remote party's one-time public key.
    ///   - remoteKyber1024PublicKey: The remote party's post-quantum key exchange public key.
    ///   - localPrivateLongTermKey: The local party's long-term private key.
    ///   - localPrivateOneTimeKey: The local party's one-time private key.
    ///   - localKyber1024PrivateKey: The local party's post-quantum key exchange private key.
    ///   - rootKey: The root symmetric key used for encryption.
    ///   - messageCiphertext: The ciphertext of the message being sent or received.
    ///   - sendingKey: The current chain key for sending messages.
    init(
        remotePublicLongTermKey: RemotePublicLongTermKey,
        remotePublicOneTimeKey: RemotePublicOneTimeKey?,
        remoteKyber1024PublicKey: RemoteKyber1024PublicKey,
        localPrivateLongTermKey: LocalPrivateLongTermKey,
        localPrivateOneTimeKey: LocalPrivateOneTimeKey?,
        localKyber1024PrivateKey: LocalKyber1024PrivateKey,
        rootKey: SymmetricKey,
        messageCiphertext: Data,
        sendingKey: SymmetricKey
    ) {
        self.remotePublicLongTermKey = remotePublicLongTermKey
        self.remotePublicOneTimeKey = remotePublicOneTimeKey
        self.remoteKyber1024PublicKey = remoteKyber1024PublicKey
        self.localPrivateLongTermKey = localPrivateLongTermKey
        self.localPrivateOneTimeKey = localPrivateOneTimeKey
        self.localKyber1024PrivateKey = localKyber1024PrivateKey
        self.rootKey = rootKey
        self.messageCiphertext = messageCiphertext
        self.sendingKey = sendingKey
    }
    
    // MARK: - Methods
    
    /// Updates the list of skipped message keys by appending a new key.
    /// - Parameter skippedMessageKeys: The skipped message key to add.
    func updateSkippedMessage(skippedMessageKey: SkippedMessageKey) async -> Self {
        var ratchetState = self
        ratchetState.skippedMessageKeys.append(skippedMessageKey)
        return ratchetState
    }
    
    /// Drops the first `count` entries from `skippedMessageKeys`.
    /// - Parameter count: Number of oldest entries to remove.
    /// - Returns: A new `RatchetState` with those entries removed.
    func removeFirstSkippedMessages(count: Int = 1) async -> Self {
        var ratchetState = self
        guard count > 0, skippedMessageKeys.count > 0 else {
            return self
        }
        
        // Clamp to avoid slicing past end
        let dropCount = min(count, skippedMessageKeys.count)
        let remainingKeys = Array(skippedMessageKeys.dropFirst(dropCount))
        ratchetState.skippedMessageKeys = remainingKeys
        return ratchetState
    }
    
    /// Removes a skipped message key at the specified index.
    /// - Parameter index: The index of the skipped message key to remove.
    func removeSkippedMessages(at number: Int) async -> Self {
        var ratchetState = self
        ratchetState.skippedMessageKeys.removeAll(where: { $0.messageIndex == number })
        return ratchetState
    }
    
    func removeAllSkippedMessages() async -> Self {
        var ratchetState = self
        ratchetState.skippedMessageKeys.removeAll()
        return ratchetState
    }
    
    func incrementSkippedHeaderIndex() async -> Self {
        var ratchetState = self
        ratchetState.headerIndex += 1
        return ratchetState
    }
    
    /// Increments the count of received messages by one.
    func incrementReceivedMessagesCount() async -> Self {
        var ratchetState = self
        ratchetState.receivedMessagesCount += 1
        return ratchetState
    }
    
    /// Increments the count of sent messages by one.
    func incrementSentMessagesCount() async -> Self {
        var ratchetState = self
        ratchetState.sentMessagesCount += 1
        return ratchetState
    }
    
    /// Updates the remote long-term public key.
    /// - Parameter remotePublicKey: The new remote long-term public key.
    func updateRemotePublicLongTermKey(_ remotePublicKey: Data) async -> Self {
        var ratchetState = self
        ratchetState.remotePublicLongTermKey = remotePublicKey
        return ratchetState
    }
    
    /// Updates the remote one-time public key.
    /// - Parameter remoteOTPublicKey: The new remote one-time public key.
    func updateRemotePublicOneTimeKey(_ remotePublicOneTimeKey: Curve25519PublicKeyRepresentable?) async -> Self {
        var ratchetState = self
        ratchetState.remotePublicOneTimeKey = remotePublicOneTimeKey
        return ratchetState
    }
    
    /// Updates the remote post-quantum key exchange public key.
    /// - Parameter remoteKyber1024PublicKey: The new remote post-quantum public key.
    func updateRemoteKyber1024PublicKey(_ remoteKyber1024PublicKey: Kyber1024PublicKeyRepresentable) async -> Self {
        var ratchetState = self
        ratchetState.remoteKyber1024PublicKey = remoteKyber1024PublicKey
        return ratchetState
    }
    
    /// Updates the current sending chain key.
    /// - Parameter sendingKey: The new sending chain key.
    func updateSendingKey(_ sendingKey: SymmetricKey) async -> Self {
        var ratchetState = self
        ratchetState.sendingKey = sendingKey
        return ratchetState
    }
    
    /// Updates the current receiving chain key.
    /// - Parameter receivingKey: The new receiving chain key.
    func updateReceivingKey(_ receivingKey: SymmetricKey) async -> Self {
        var ratchetState = self
        ratchetState.receivingKey = receivingKey
        return ratchetState
    }
    
    /// Updates the local long-term private key.
    /// - Parameter localPrivateKey: The new local long-term private key.
    func updateLocalPrivateLongTermKey(_ localPrivateKey: Data) async -> Self {
        var ratchetState = self
        ratchetState.localPrivateLongTermKey = localPrivateKey
        return ratchetState
    }
    
    /// Updates the local one-time private key.
    /// - Parameter localOTPrivateKey: The new local one-time private key.
    func updateLocalPrivateOneTimeKey(_ localOTPrivateKey: Curve25519PrivateKeyRepresentable?) async -> Self {
        var ratchetState = self
        ratchetState.localPrivateOneTimeKey = localOTPrivateKey
        return ratchetState
    }
    
    /// Updates the local post-quantum key exchange private key.
    /// - Parameter localKyber1024PrivateKey: The new local post-quantum private key.
    func updatelocalKyber1024PrivateKey(_ localKyber1024PrivateKey: LocalKyber1024PrivateKey) async -> Self {
        var ratchetState = self
        ratchetState.localKyber1024PrivateKey = localKyber1024PrivateKey
        return ratchetState
    }
    
    /// Updates the count of sent messages.
    /// - Parameter sentMessagesCount: The new count of sent messages.
    func updateSentMessagesCount(_ sentMessagesCount: Int) async -> Self {
        var ratchetState = self
        ratchetState.sentMessagesCount = sentMessagesCount
        return ratchetState
    }
    
    /// Updates the count of received messages.
    /// - Parameter receivedMessagesCount: The new count of received messages.
    func updateReceivedMessagesCount(_ receivedMessagesCount: Int) async -> Self {
        var ratchetState = self
        ratchetState.receivedMessagesCount = receivedMessagesCount
        return ratchetState
    }
    
    /// Updates the count of messages in the previous sending chain.
    /// - Parameter previousMessagesCount: The new count of previous messages.
    func updatePreviousMessagesCount(_ previousMessagesCount: Int) async -> Self {
        var ratchetState = self
        ratchetState.previousMessagesCount = previousMessagesCount
        return ratchetState
    }
    
    /// Updates the root symmetric key.
    /// - Parameter rootKey: The new root symmetric key.
    func updateRootKey(_ rootKey: SymmetricKey) async -> Self {
        var ratchetState = self
        ratchetState.rootKey = rootKey
        return ratchetState
    }
    
    /// Updates the message ciphertext.
    /// - Parameter cipherText: The new ciphertext for the message.
    func updateCiphertext(_ cipherText: Data) async -> Self {
        var ratchetState = self
        ratchetState.messageCiphertext = cipherText
        return ratchetState
    }
    
    /// Updates the header ciphertext.
    /// - Parameter cipherText: The new ciphertext for the header.
    func updateHeaderCiphertext(_ cipherText: Data) async -> Self {
        var ratchetState = self
        ratchetState.headerCiphertext = cipherText
        return ratchetState
    }
    
    /// Updates the current sending header key.
    /// - Parameter HKs: The new current sending header key.
    func updateSendingHeaderKey(_ sendingHeaderKey: SymmetricKey) async -> Self {
        var ratchetState = self
        ratchetState.sendingHeaderKey = sendingHeaderKey
        return ratchetState
    }
    
    /// Updates the next sending header key.
    /// - Parameter NHKs: The new next sending header key.
    func updateSendingNextHeaderKey(_ nextSendingHeaderKey: SymmetricKey) async -> Self {
        var ratchetState = self
        ratchetState.nextSendingHeaderKey = nextSendingHeaderKey
        return ratchetState
    }
    
    /// Updates the current receiving header key.
    /// - Parameter HKr: The new current receiving header key.
    func updateReceivingHeaderKey(_ receivingHeaderKey: SymmetricKey) async -> Self {
        var ratchetState = self
        ratchetState.receivingHeaderKey = receivingHeaderKey
        return ratchetState
    }
    
    /// Updates the next receiving header key.
    /// - Parameter NHKr: The new next receiving header key.
    func updateReceivingNextHeaderKey(_ nextReceivingHeaderKey: SymmetricKey?) async -> Self {
        var ratchetState = self
        ratchetState.nextReceivingHeaderKey = nextReceivingHeaderKey
        return ratchetState
    }
    
    /// Marks the initial post-quantum X3DH handshake as completed.
    /// - Parameter handshakeFinished: A Boolean value indicating whether the handshake has finished.
    func updateSendingHandshakeFinished(_ handshakeFinished: Bool) async -> Self {
        var ratchetState = self
        ratchetState.sendingHandshakeFinished = handshakeFinished
        return ratchetState
    }
    
    func updateReceivingHandshakeFinished(_ handshakeFinished: Bool) async -> Self {
        var ratchetState = self
        ratchetState.receivingHandshakeFinished = handshakeFinished
        return ratchetState
    }
    
    func updateSkippedHeaderMessage(_ message: SkippedHeaderMessage) async -> Self {
        var ratchetState = self
        ratchetState.skippedHeaderMesages.append(message)
        return ratchetState
    }
    
    func removeSkippedHeaderMessage(_ message: SkippedHeaderMessage) async -> Self {
        var ratchetState = self
        ratchetState.skippedHeaderMesages.removeAll(where: { $0.chainKey == message.chainKey })
        return ratchetState
    }
    
    func removeAllSkippedHeaderMessage() async -> Self {
        var ratchetState = self
        ratchetState.skippedHeaderMesages.removeAll()
        return ratchetState
    }
    
    func incrementSkippedMessageIndex() async -> Self {
        var ratchetState = self
        ratchetState.lastSkippedIndex += 1
        return ratchetState
    }
    
    func updateSkippedMessageIndex(_ currentIndex: Int) async -> Self {
        var ratchetState = self
        ratchetState.lastSkippedIndex = currentIndex
        return ratchetState
    }
    
    func updateLastDecryptedMessageNumber(_ number: Int) async -> Self {
        var ratchetState = self
        ratchetState.lastDecryptedMessageNumber = number
        return ratchetState
    }
    
    func setAlreadyDecryptedMessageNumbers(_ numbers: Set<Int>) async -> Self {
        var ratchetState = self
        ratchetState.alreadyDecryptedMessageNumbers = numbers
        return ratchetState
    }
    
    func updateAlreadyDecryptedMessageNumber(_ number: Int) async -> Self {
        var ratchetState = self
        ratchetState.alreadyDecryptedMessageNumbers.insert(number)
        return ratchetState
    }
    
    func resetAlreadyDecryptedMessageNumber() async -> Self {
        var ratchetState = self
        ratchetState.alreadyDecryptedMessageNumbers.removeAll()
        return ratchetState
    }
}

struct SkippedHeaderMessage: Codable, Sendable, Equatable {
    let chainKey: SymmetricKey
    let index: Int
}

// MARK: - RatchetError Enum

/// Enum representing possible errors that can occur in the Double Ratchet protocol.
public enum RatchetError: Error {
    case missingConfiguration               // Configuration is missing.
    case missingProps                       // Required properties are missing.
    case sendingKeyIsNil                    // Sending key is nil.
    case receivingKeyIsNil                  // Receiving key is nil.
    case headerDataIsNil                    // Header data is nil.
    case invalidNonceLength                 // Nonce length is invalid.
    case encryptionFailed                   // Encryption operation failed.
    case decryptionFailed                   // Decryption operation failed.
    case expiredKey                         // A key has expired.
    case stateUninitialized                 // The state is uninitialized.
    case missingCipherText                  // Ciphertext is missing.
    case headerKeysNil                      // Header keys are nil.
    case headerEncryptionFailed             // Header encryption failed.
    case headerDecryptFailed                // Header decryption failed.
    case missingNextHeaderKey
    case missingOneTimeKey                  // Next header key is missing.
    case delegateNotSet                     // Next header key is missing.
    case receivingHeaderKeyIsNil
    case maxSkippedHeadersExceeded
    case rootKeyIsNil
    case initialMessageNotReceived
    case skippedKeysDrained
}
