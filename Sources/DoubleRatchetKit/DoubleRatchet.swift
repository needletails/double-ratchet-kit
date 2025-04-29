//  DoubleRatchet.swift
//  needletail-crypto
//
//  Created by Cole M on 9/12/24.
//

import Crypto
import Foundation
import BSON
import NeedleTailCrypto
import SwiftKyber

/*
 # Double Ratchet API Overview
 
 This module implements the **Double Ratchet Algorithm**, which provides *asynchronous forward secrecy* and *post-compromise security* for secure messaging. It is based on the Signal protocol specification:
 
 📄 Specification: https://signal.org/docs/specifications/doubleratchet/doubleratchet.pdf
 
 The Double Ratchet combines a **Diffie-Hellman (DH) ratchet** and **symmetric-key ratchets** to derive message keys that change with every message. It ensures that compromise of current or past keys does not reveal other session messages.
 
 ## Core Features
 
 1. **Header Encryption (HE) Variant**
 This implementation includes *header encryption*, which encrypts message headers (e.g., message counters, key IDs) under the current sending header key (`HKs`). This protects metadata against passive traffic analysis. See the `encryptHeader` and `decryptHeader` methods for details.
 
 2. **Skipped Message Key Management**
 To support out-of-order message receipt, skipped message keys are temporarily stored. To mitigate denial-of-service (DoS) and compromise risks:
 - A cap is placed on the number of stored skipped keys per session (e.g., 1000).
 - Keys are purged after timeouts or event-based thresholds (e.g., number of received messages).
 
 3. **Deferred DH Ratchet Key Generation**
 As an optimization, the generation of new DH ratchet keys can be deferred until a message is actually sent. This slightly increases security by reducing the window in which private keys exist.
 
 4. **Post-Compromise Recovery**
 Even if a party is compromised (e.g., key leak or device breach), the Double Ratchet ensures that new messages are still secure once the ratchet advances. However, active attacks can persist unless new identity keys and devices are re-established.
 
 5. **Post-Quantum X3DH (PQXDH) Integration**
 This Double Ratchet is designed to work with **PQXDH**, a post-quantum secure version of X3DH for initial key agreement:
 - `SK` from PQXDH is used as the initial root key.
 - `AD` (associated data) from PQXDH is passed to message encryption/decryption.
 - Bob’s signed prekey (SPKB) becomes the initial DH ratchet public key.
 - Alice’s first Double Ratchet message includes the PQXDH initial ciphertext.
 
 🔒 PQXDH Specification: https://signal.org/docs/specifications/pqxdh/
 
 ## Key Components
 
 - `RatchetStateManager`: Core ratchet state machine. Handles key rotation, message counters, and skipped key pruning.
 - `encryptHeader`: Serializes and encrypts the message header under the current header key (HKs).
 - `decryptHeader`: Decrypts the header using current, next, or skipped header keys. May trigger a DH ratchet step.
 
 ## References
 
 - Double Ratchet Specification: https://signal.org/docs/specifications/doubleratchet/
 - PQXDH Specification: https://signal.org/docs/specifications/pqxdh/
 - X3DH (original): https://signal.org/docs/specifications/x3dh/
 */


public typealias RemotePublicLongTermKey = Data
public typealias RemotePublicOneTimeKey = Data
public typealias RemoteKyber1024PublicKey = Data
public typealias LocalPrivateLongTermKey = Data
public typealias LocalPrivateOneTimeKey = Data
public typealias LocalKyber1024PrivateKey = Data

typealias LocalPrivateKey = Data
typealias RemotePublicKey = Data

public protocol SessionIdentityDelegate: AnyObject, Sendable {
    func updateSessionIdentity(_ identity: SessionIdentity) async throws
}

/// Represents a set of skipped message keys for later processing in the Double Ratchet protocol.
public struct SkippedMessageKey: Codable, Sendable {
    /// The public key of the sender associated with the skipped message.
    let remotePublicLongTermKey: Data
    
    /// The public key of the sender associated with the skipped message.
    let remotePublicOneTimeKey: Data
    
    /// The index of the skipped message.
    let messageIndex: Int
    
    /// The symmetric key used to encrypt the skipped message.
    let messageKey: SymmetricKey
    
    private enum CodingKeys: String, CodingKey, Sendable {
        case remotePublicLongTermKey = "a"
        case remotePublicOneTimeKey = "b"
        case messageIndex = "c"
        case messageKey = "d"
    }
}

/// Represents an encrypted message along with its header in the Double Ratchet protocol.
public struct RatchetMessage: Codable, Sendable {
    /// The header containing metadata about the message.
    let header: EncryptedHeader
    
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
public struct EncryptedHeader: Sendable, Codable {
    /// Sender's long-term public key.
    let remotePublicLongTermKey: RemotePublicLongTermKey
    
    /// Sender's one-time public key.
    let remotePublicOneTimeKey: RemotePublicOneTimeKey
    
    /// Sender's Kyber1024 public key used for key agreement.
    let remoteKyber1024PublicKey: RemoteKyber1024PublicKey
    
    /// Header encapsulated ciphertext.
    let headerCiphertext: Data
    
    /// Message encapsulated ciphertext.
    let messageCiphertext: Data
    
    /// Encrypted header body (e.g., BSON).
    let encrypted: Data
    
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
        case encrypted = "f"
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
        remotePublicOneTimeKey: RemotePublicOneTimeKey,
        remoteKyber1024PublicKey: RemoteKyber1024PublicKey,
        headerCiphertext: Data,
        messageCiphertext: Data,
        encrypted: Data
    ) {
        self.remotePublicLongTermKey = remotePublicLongTermKey
        self.remotePublicOneTimeKey = remotePublicOneTimeKey
        self.remoteKyber1024PublicKey = remoteKyber1024PublicKey
        self.headerCiphertext = headerCiphertext
        self.messageCiphertext = messageCiphertext
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
        decrypted: MessageHeader
    ) {
        self.remotePublicLongTermKey = remotePublicLongTermKey
        self.remotePublicOneTimeKey = remotePublicOneTimeKey
        self.remoteKyber1024PublicKey = remoteKyber1024PublicKey
        self.headerCiphertext = headerCiphertext
        self.messageCiphertext = messageCiphertext
        self.encrypted = encrypted
        self.decrypted = decrypted
    }
}

/// Represents the header of a message in the Double Ratchet protocol.
public struct MessageHeader: Sendable, Codable {
    
    /// The length of the previous message chain.
    let previousChainLength: Int
    
    /// The sequence number of the message.
    let messageNumber: Int
    
    private enum CodingKeys: String, CodingKey, Sendable {
        case previousChainLength = "a"
        case messageNumber = "b"
    }
    
    /// Initializes a new MessageHeader with the specified parameters.
    /// - Parameters:
    ///   - remotePublicKey: The public key of the sender.
    ///   - previousChainLength: The length of the previous message chain.
    ///   - messageNumber: The sequence number of the message.
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
    associatedData: "NeedleTail DoubleRatchet".data(using: .ascii)!, // Associated data for messages.
    maxSkippedMessageKeys: 80                     // Maximum number of skipped message keys to retain.
)

/// Represents the state of the Double Ratchet protocol.
public struct RatchetState: Sendable, Codable {
    
    /// Coding keys for encoding and decoding the RatchetState.
    enum CodingKeys: String, CodingKey, Sendable, Codable {
        case localPrivateLongTermKey = "a"         // Local long-term private key.
        case localPrivateOneTimeKey = "b"          // Local one-time private key.
        case localKyber1024PrivateKey = "c"            // Local post-quantum key exchange private key.
        case remotePublicLongTermKey = "d"         // Remote long-term public key.
        case remotePublicOneTimeKey = "e"          // Remote one-time public key.
        case remoteKyber1024PublicKey = "f"            // Remote post-quantum key exchange public key.
        case messageCiphertext = "g"               // Ciphertext of the message.
        case rootKey = "h"                         // Root symmetric key.
        case sendingKey = "i"                      // Chain key for sending.
        case receivingKey = "j"                    // Chain key for receiving.
        case sentMessagesCount = "k"               // Count of sent messages.
        case receivedMessagesCount = "l"           // Count of received messages.
        case previousMessagesCount = "m"           // Count of messages in the previous sending chain.
        case skippedMessageKeys = "n"              // Dictionary of skipped message keys.
        case headerCiphertext = "o"                // Header ciphertext.
        case sendingHeaderKey = "p"                // Current sending header key.
        case nextSendingHeaderKey = "q"            // Next sending header key.
        case receivingHeaderKey = "r"              // Current receiving header key.
        case nextReceivingHeaderKey = "s"          // Next receiving header key.
    }
    
    // MARK: - Properties
    
    /// Local long-term private key.
    private(set) fileprivate var localPrivateLongTermKey: LocalPrivateLongTermKey
    
    /// Local one-time private key.
    private(set) fileprivate var localPrivateOneTimeKey: LocalPrivateOneTimeKey
    
    /// Local post-quantum key exchange private key.
    private(set) fileprivate var localKyber1024PrivateKey: LocalKyber1024PrivateKey
    
    /// Remote long-term public key.
    private(set) fileprivate var remotePublicLongTermKey: RemotePublicLongTermKey
    
    /// Remote one-time public key.
    private(set) fileprivate var remotePublicOneTimeKey: RemotePublicOneTimeKey
    
    /// Remote post-quantum key exchange public key.
    private(set) fileprivate var remoteKyber1024PublicKey: RemoteKyber1024PublicKey
    
    /// Ciphertext of the message being sent or received.
    private(set) fileprivate var messageCiphertext: Data?
    
    /// Root symmetric key used for encryption.
    private(set) fileprivate var rootKey: SymmetricKey
    
    /// Current chain key for sending messages.
    private(set) fileprivate var sendingKey: SymmetricKey?
    
    /// Current chain key for receiving messages.
    private(set) fileprivate var receivingKey: SymmetricKey?
    
    /// Count of messages sent.
    private(set) fileprivate var sentMessagesCount: Int = 0
    
    /// Count of messages received.
    private(set) fileprivate var receivedMessagesCount: Int = 0
    
    /// Count of messages in the previous sending chain.
    private(set) fileprivate var previousMessagesCount: Int = 0
    
    /// List of skipped message keys.
    private(set) fileprivate var skippedMessageKeys = [SkippedMessageKey]()
    
    /// Ciphertext for the header.
    private(set) fileprivate var headerCiphertext: Data?
    
    /// Current sending header key.
    private(set) fileprivate var sendingHeaderKey: SymmetricKey?
    
    /// Next sending header key.
    private(set) fileprivate var nextSendingHeaderKey: SymmetricKey?
    
    /// Current receiving header key.
    private(set) fileprivate var receivingHeaderKey: SymmetricKey?
    
    /// Next receiving header key.
    private(set) fileprivate var nextReceivingHeaderKey: SymmetricKey?
    
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
        remotePublicOneTimeKey: RemotePublicOneTimeKey,
        remoteKyber1024PublicKey: RemoteKyber1024PublicKey,
        localPrivateLongTermKey: LocalPrivateLongTermKey,
        localPrivateOneTimeKey: LocalPrivateOneTimeKey,
        localKyber1024PrivateKey: LocalKyber1024PrivateKey,
        rootKey: SymmetricKey,
        messageCiphertext: Data,
        receivingKey: SymmetricKey
    ) {
        self.remotePublicLongTermKey = remotePublicLongTermKey
        self.remotePublicOneTimeKey = remotePublicOneTimeKey
        self.remoteKyber1024PublicKey = remoteKyber1024PublicKey
        self.localPrivateLongTermKey = localPrivateLongTermKey
        self.localPrivateOneTimeKey = localPrivateOneTimeKey
        self.localKyber1024PrivateKey = localKyber1024PrivateKey
        self.rootKey = rootKey
        self.messageCiphertext = messageCiphertext
        self.receivingKey = receivingKey
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
        remotePublicOneTimeKey: RemotePublicOneTimeKey,
        remoteKyber1024PublicKey: RemoteKyber1024PublicKey,
        localPrivateLongTermKey: LocalPrivateLongTermKey,
        localPrivateOneTimeKey: LocalPrivateOneTimeKey,
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
    mutating func updateSkippedMessages(skippedMessageKeys: SkippedMessageKey) async {
        self.skippedMessageKeys.append(skippedMessageKeys)
    }
    
    /// Updates the list of skipped message keys with a new array of keys.
    /// - Parameter newKeys: The new array of skipped message keys.
    mutating func updateSkippedMessages(with newKeys: [SkippedMessageKey]) async {
        self.skippedMessageKeys = newKeys
    }
    
    /// Removes the first skipped message key from the list.
    mutating func removeFirstSkippedMessages() async {
        skippedMessageKeys.removeFirst()
    }
    
    /// Removes a skipped message key at the specified index.
    /// - Parameter index: The index of the skipped message key to remove.
    mutating func removeSkippedMessages(at index: Int) async {
        skippedMessageKeys.remove(at: index)
    }
    
    /// Increments the count of received messages by one.
    mutating func incrementReceivedMessagesCount() async {
        receivedMessagesCount += 1
    }
    
    /// Increments the count of sent messages by one.
    mutating func incrementSentMessagesCount() async {
        sentMessagesCount += 1
    }
    
    /// Updates the remote long-term public key.
    /// - Parameter remotePublicKey: The new remote long-term public key.
    mutating func updateRemotePublicLongTermKey(_ remotePublicKey: Data) async {
        self.remotePublicLongTermKey = remotePublicKey
    }
    
    /// Updates the remote one-time public key.
    /// - Parameter remoteOTPublicKey: The new remote one-time public key.
    mutating func updateRemotePublicOneTimeKey(_ remoteOTPublicKey: Data) async {
        self.remotePublicOneTimeKey = remoteOTPublicKey
    }
    
    /// Updates the remote post-quantum key exchange public key.
    /// - Parameter remoteKyber1024PublicKey: The new remote post-quantum public key.
    mutating func updateremoteKyber1024PublicKey(_ remoteKyber1024PublicKey: Data) async {
        self.remoteKyber1024PublicKey = remoteKyber1024PublicKey
    }
    
    /// Updates the current sending chain key.
    /// - Parameter sendingKey: The new sending chain key.
    mutating func updateSendingKey(_ sendingKey: SymmetricKey) async {
        self.sendingKey = sendingKey
    }
    
    /// Updates the current receiving chain key.
    /// - Parameter receivingKey: The new receiving chain key.
    mutating func updateReceivingKey(_ receivingKey: SymmetricKey) async {
        self.receivingKey = receivingKey
    }
    
    /// Updates the local long-term private key.
    /// - Parameter localPrivateKey: The new local long-term private key.
    mutating func updateLocalPrivateLongTermKey(_ localPrivateKey: Data) async {
        self.localPrivateLongTermKey = localPrivateKey
    }
    
    /// Updates the local one-time private key.
    /// - Parameter localOTPrivateKey: The new local one-time private key.
    mutating func updateLocalPrivateOneTimeKey(_ localOTPrivateKey: Data) async {
        self.localPrivateOneTimeKey = localOTPrivateKey
    }
    
    /// Updates the local post-quantum key exchange private key.
    /// - Parameter localKyber1024PrivateKey: The new local post-quantum private key.
    mutating func updatelocalKyber1024PrivateKey(_ localKyber1024PrivateKey: Data) async {
        self.localKyber1024PrivateKey = localKyber1024PrivateKey
    }
    
    /// Updates the count of sent messages.
    /// - Parameter sentMessagesCount: The new count of sent messages.
    mutating func updateSentMessagesCount(_ sentMessagesCount: Int) async {
        self.sentMessagesCount = sentMessagesCount
    }
    
    /// Updates the count of received messages.
    /// - Parameter receivedMessagesCount: The new count of received messages.
    mutating func updateReceivedMessagesCount(_ receivedMessagesCount: Int) async {
        self.receivedMessagesCount = receivedMessagesCount
    }
    
    /// Updates the count of messages in the previous sending chain.
    /// - Parameter previousMessagesCount: The new count of previous messages.
    mutating func updatePreviousMessagesCount(_ previousMessagesCount: Int) async {
        self.previousMessagesCount = previousMessagesCount
    }
    
    /// Updates the root symmetric key.
    /// - Parameter rootKey: The new root symmetric key.
    mutating func updateRootKey(_ rootKey: SymmetricKey) async {
        self.rootKey = rootKey
    }
    
    /// Updates the message ciphertext.
    /// - Parameter cipherText: The new ciphertext for the message.
    mutating func updateCiphertext(_ cipherText: Data) async {
        self.messageCiphertext = cipherText
    }
    
    /// Updates the header ciphertext.
    /// - Parameter cipherText: The new ciphertext for the header.
    mutating func updateHeaderCiphertext(_ cipherText: Data) async {
        self.headerCiphertext = cipherText
    }
    
    /// Updates the current sending header key.
    /// - Parameter HKs: The new current sending header key.
    mutating func updateSendingHeaderKey(_ sendingHeaderKey: SymmetricKey) async {
        self.sendingHeaderKey = sendingHeaderKey
    }
    
    /// Updates the next sending header key.
    /// - Parameter NHKs: The new next sending header key.
    mutating func updateSendingNextHeaderKey(_ nextSendingHeaderKey: SymmetricKey) async {
        self.nextSendingHeaderKey = nextSendingHeaderKey
    }
    
    /// Updates the current receiving header key.
    /// - Parameter HKr: The new current receiving header key.
    mutating func updateReceivingHeaderKey(_ receivingHeaderKey: SymmetricKey) async {
        self.receivingHeaderKey = receivingHeaderKey
    }
    
    /// Updates the next receiving header key.
    /// - Parameter NHKr: The new next receiving header key.
    mutating func updateReceivingNextHeaderKey(_ nextReceivingHeaderKey: SymmetricKey) async {
        self.nextReceivingHeaderKey = nextReceivingHeaderKey
    }
}

// MARK: - RatchetError Enum

/// Enum representing possible errors that can occur in the Double Ratchet protocol.
internal enum RatchetError: Error {
    case missingConfiguration               // Configuration is missing.
    case missingProps                       // Required properties are missing.
    case sendingKeyIsNil                    // Sending key is nil.
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
    case missingNextHeaderKey               // Next header key is missing.
}

/// An actor that manages the cryptographic state for secure messaging using the Double Ratchet algorithm.
///
/// This includes session state initialization, identity management, and state synchronization
/// for both sending and receiving parties. This implementation is designed to be concurrency-safe
/// and supports post-quantum key exchange via Kyber1024.
///
/// - Note: Always ensure that `RatchetState` is kept up-to-date and properly cached through `loadDeviceIdentities`.
public actor RatchetStateManager<Hash: HashFunction & Sendable> {
    
    // MARK: - Private Properties
    
    /// The executor responsible for serialized task execution within the actor.
    private let executor: any SerialExecutor
    
    /// Returns the executor used for non-isolated tasks.
    public nonisolated var unownedExecutor: UnownedSerialExecutor {
        executor.asUnownedSerialExecutor()
    }
    
    /// Internal cryptographic utility object.
    private let crypto = NeedleTailCrypto()
    
    /// The active Double Ratchet configuration. Allow asynchronous access to a global constant.
    private var configuration: RatchetConfiguration? {
        get async {
            defaultRatchetConfiguration
        }
    }
    
    /// Holds all known session configurations keyed by session identity.
    private(set) public var sessionConfigurations = [SessionConfiguration]()
    
    /// The currently active session configuration.
    private var currentConfiguration: SessionConfiguration?
    public weak var delegate: SessionIdentityDelegate?
    public func setDelegate(_ delegate: SessionIdentityDelegate) {
        self.delegate = delegate
    }
   
    // MARK: - Initialization
    
    /// Initializes the ratchet state manager.
    /// - Parameter executor: A `SerialExecutor` used to coordinate concurrent operations within the actor.
    public init(executor: any SerialExecutor) {
        self.executor = executor
    }
    
    // MARK: - Types
    
    /// Represents the direction of message flow and associated keys.
    private enum MessageType: Sendable {
        case sending(EncryptionKeys)
        case receiving(EncryptionKeys)
    }
    
    /// Container for cryptographic key material used in ratchet initialization.
    private struct EncryptionKeys: Sendable {
        let remotePublicLongTermKey: RemotePublicLongTermKey
        let remotePublicOneTimeKey: RemotePublicOneTimeKey
        let remoteKyber1024PublicKey: RemoteKyber1024PublicKey
        let localPrivateLongTermKey: LocalPrivateLongTermKey
        let localPrivateOneTimeKey: LocalPrivateOneTimeKey
        let localKyber1024PrivateKey: LocalKyber1024PrivateKey
    }
    
    /// Represents session identity and associated symmetric key for key derivation.
    public struct SessionConfiguration: Sendable {
        var sessionIdentity: SessionIdentity
        var sessionSymmetricKey: SymmetricKey
    }
    
    /// Load or create session configuration and ratchet state as needed.
    /// - Parameters:
    ///   - sessionIdentity: Identity of the communicating peer.
    ///   - sessionSymmetricKey: Symmetric key for deriving state secrets.
    ///   - messageType: Indicates if the context is for sending or receiving.
    private func loadDeviceIdentities(
        sessionIdentity: SessionIdentity,
        sessionSymmetricKey: SymmetricKey,
        messageType: MessageType
    ) async throws {
        if let configuration = sessionConfigurations.first(where: { $0.sessionIdentity.id == sessionIdentity.id }) {
            currentConfiguration = configuration
        } else {
            let configuration = SessionConfiguration(
                sessionIdentity: sessionIdentity,
                sessionSymmetricKey: sessionSymmetricKey)
            sessionConfigurations.append(configuration)
            currentConfiguration = configuration
        }
        guard currentConfiguration != nil else {
            throw RatchetError.missingConfiguration
        }
        
        if try await sessionProps().state == nil {
            let state = try await createNewState(for: messageType)
            try await updateSessionIdentity(state: state)
        }
    }
    
    /// Returns unwrapped properties from the current session identity.
    private func sessionProps() async throws -> SessionIdentity.UnwrappedProps {
        guard let currentConfiguration else {
            throw RatchetError.missingConfiguration
        }
        guard let props = await currentConfiguration.sessionIdentity.props(symmetricKey: currentConfiguration.sessionSymmetricKey) else {
            throw RatchetError.missingProps
        }
        return props
    }
    
    /// Updates the session identity with a new ratchet state.
    private func updateSessionIdentity(state: RatchetState) async throws {
        guard let currentConfiguration else {
            throw RatchetError.missingConfiguration
        }
        var props = try await sessionProps()
        props.state = state
        if let updatedSessionIdentity = try await currentConfiguration.sessionIdentity.updateIdentityProps(symmetricKey: currentConfiguration.sessionSymmetricKey, props: props),
           let index = sessionConfigurations.firstIndex(where: { $0.sessionIdentity.id == updatedSessionIdentity.id }) {
            sessionConfigurations[index].sessionIdentity = updatedSessionIdentity
            //Forward updated identity for consumer session identity updates
            try await delegate?.updateSessionIdentity(updatedSessionIdentity)
        }
    }
    
    /// Updates the given ratchet state with new encryption key material.
    private func updateState(
        _ state: RatchetState,
        for messageType: MessageType
    ) async -> RatchetState {
        switch messageType {
        case .receiving(let recipientKeys):
            return await update(state, for: recipientKeys)
        case .sending(let senderKeys):
            return await update(state, for: senderKeys)
        }
    }
    
    /// Applies key updates to a ratchet state.
    private func update(
        _ state: RatchetState,
        for keys: EncryptionKeys
    ) async -> RatchetState {
        var state = state
        await state.updateLocalPrivateLongTermKey(keys.localPrivateLongTermKey)
        await state.updateLocalPrivateOneTimeKey(keys.localPrivateOneTimeKey)
        await state.updatelocalKyber1024PrivateKey(keys.localKyber1024PrivateKey)
        await state.updateRemotePublicLongTermKey(keys.remotePublicLongTermKey)
        await state.updateRemotePublicOneTimeKey(keys.remotePublicOneTimeKey)
        await state.updateremoteKyber1024PublicKey(keys.remoteKyber1024PublicKey)
        return state
    }
    
    /// Creates a new ratchet state based on message direction and keying material.
    private func createNewState(for messageType: MessageType) async throws -> RatchetState {
        switch messageType {
        case .receiving(let recipientKeys):
            let cipher = try await derivePQXDHFinalKey(
                localPrivateLongTermKey: recipientKeys.localPrivateLongTermKey,
                remotePublicLongTermKey: recipientKeys.remotePublicLongTermKey,
                localPrivateOneTimeKey: recipientKeys.localPrivateOneTimeKey,
                remotePublicOneTimeKey: recipientKeys.remotePublicOneTimeKey,
                remoteKyber1024PublicKey: recipientKeys.remoteKyber1024PublicKey)
            return await RatchetState(
                remotePublicLongTermKey: recipientKeys.remotePublicLongTermKey,
                remotePublicOneTimeKey: recipientKeys.remotePublicOneTimeKey,
                remoteKyber1024PublicKey: recipientKeys.remoteKyber1024PublicKey,
                localPrivateLongTermKey: recipientKeys.localPrivateLongTermKey,
                localPrivateOneTimeKey: recipientKeys.localPrivateOneTimeKey,
                localKyber1024PrivateKey: recipientKeys.localKyber1024PrivateKey,
                rootKey: cipher.symmetricKey,
                messageCiphertext: cipher.ciphertext,
                receivingKey: try deriveChainKey(from: cipher.symmetricKey, configuration: defaultRatchetConfiguration))
            
        case .sending(let senderKeys):
            let (sendingKey, cipher) = try await deriveNextMessageKey(
                localPrivateLongTermKey: senderKeys.localPrivateLongTermKey,
                remotePublicLongTermKey: senderKeys.remotePublicLongTermKey,
                localPrivateOneTimeKey: senderKeys.localPrivateOneTimeKey,
                remotePublicOneTimeKey: senderKeys.remotePublicOneTimeKey,
                remoteKyber1024PublicKey: senderKeys.remoteKyber1024PublicKey)
            return RatchetState(
                remotePublicLongTermKey: senderKeys.remotePublicLongTermKey,
                remotePublicOneTimeKey: senderKeys.remotePublicOneTimeKey,
                remoteKyber1024PublicKey: senderKeys.remoteKyber1024PublicKey,
                localPrivateLongTermKey: senderKeys.localPrivateLongTermKey,
                localPrivateOneTimeKey: senderKeys.localPrivateOneTimeKey,
                localKyber1024PrivateKey: senderKeys.localKyber1024PrivateKey,
                rootKey: cipher.symmetricKey,
                messageCiphertext: cipher.ciphertext,
                sendingKey: sendingKey)
        }
    }
    
    // MARK: - Public Interface
    
    /// Initializes a sending session with the given cryptographic identity.
    ///
    /// This prepares the ratchet state for outbound message encryption.
    public func senderInitialization(
        sessionIdentity: SessionIdentity,
        sessionSymmetricKey: SymmetricKey,
        remotePublicLongTermKey: Curve25519PublicKeyRepresentable,
        remotePublicOneTimeKey: Curve25519PublicKeyRepresentable,
        remoteKyber1024PublicKey: Kyber1024PublicKeyRepresentable,
        localPrivateLongTermKey: Curve25519PrivateKeyRepresentable,
        localPrivateOneTimeKey: Curve25519PrivateKeyRepresentable,
        localKyber1024PrivateKey: Kyber1024PrivateKeyRepresentable
    ) async throws {
        try await loadDeviceIdentities(
            sessionIdentity: sessionIdentity,
            sessionSymmetricKey: sessionSymmetricKey,
            messageType: .sending(
                EncryptionKeys(
                    remotePublicLongTermKey: remotePublicLongTermKey.rawRepresentation,
                    remotePublicOneTimeKey: remotePublicOneTimeKey.rawRepresentation,
                    remoteKyber1024PublicKey: remoteKyber1024PublicKey.rawRepresentation,
                    localPrivateLongTermKey: localPrivateLongTermKey.rawRepresentation,
                    localPrivateOneTimeKey: localPrivateOneTimeKey.rawRepresentation,
                    localKyber1024PrivateKey: localKyber1024PrivateKey.rawRepresentation)))
    }
    
    /// Initializes a receiving session using the initial encrypted message.
    ///
    /// - Returns: The decrypted content of the initial message.
    public func recipientInitialization(
        sessionIdentity: SessionIdentity,
        sessionSymmetricKey: SymmetricKey,
        remotePublicLongTermKey: Curve25519PublicKeyRepresentable,
        remotePublicOneTimeKey: Curve25519PublicKeyRepresentable,
        remoteKyber1024PublicKey: Kyber1024PublicKeyRepresentable,
        localPrivateLongTermKey: Curve25519PrivateKeyRepresentable,
        localPrivateOneTimeKey: Curve25519PrivateKeyRepresentable,
        localKyber1024PrivateKey: Kyber1024PrivateKeyRepresentable,
        initialMessage: RatchetMessage
    ) async throws -> Data {
        let keys = EncryptionKeys(
            remotePublicLongTermKey: remotePublicLongTermKey.rawRepresentation,
            remotePublicOneTimeKey: remotePublicOneTimeKey.rawRepresentation,
            remoteKyber1024PublicKey: remoteKyber1024PublicKey.rawRepresentation,
            localPrivateLongTermKey: localPrivateLongTermKey.rawRepresentation,
            localPrivateOneTimeKey: localPrivateOneTimeKey.rawRepresentation,
            localKyber1024PrivateKey: localKyber1024PrivateKey.rawRepresentation)
        try await loadDeviceIdentities(
            sessionIdentity: sessionIdentity,
            sessionSymmetricKey: sessionSymmetricKey,
            messageType: .receiving(keys))
        return try await ratchetDecrypt(initialMessage)
    }
    
    /// Represents a Diffie-Hellman key pair used for Curve25519.
    private struct DiffieHellmanKeyPair: Sendable {
        let privateKey: Curve25519PrivateKey
        let publicKey: Curve25519PublicKey
    }
    
    /// Generates a new Curve25519 key pair.
    private func generateDHKeyPair() async -> DiffieHellmanKeyPair {
        let privateKey = crypto.generateCurve25519PrivateKey()
        return DiffieHellmanKeyPair(privateKey: privateKey, publicKey: privateKey.publicKey)
    }
    
    /// Derives a symmetric key using HKDF and configuration-provided shared info.
    private func deriveHKDFSymmetricKey(
        sharedSecret: SharedSecret,
        symmetricKey: SymmetricKey,
        configuration: RatchetConfiguration
    ) async throws -> SymmetricKey {
        return try await crypto.deriveHKDFSymmetricKey(
            hash: Hash.self,
            from: sharedSecret,
            with: symmetricKey,
            sharedInfo: configuration.rootKeyData
        )
    }
    
    /// Encrypts plaintext data and returns a RatchetMessage.
    public func ratchetEncrypt(plainText: Data) async throws -> RatchetMessage {
        guard var state = try await sessionProps().state else {
            throw RatchetError.stateUninitialized
        }
        guard let sendingKey = state.sendingKey else {
            throw RatchetError.sendingKeyIsNil
        }
        
        let messageHeader = MessageHeader(
            previousChainLength: state.previousMessagesCount,
            messageNumber: state.sentMessagesCount)
        let headerCipher = try await derivePQXDHFinalKey(
            localPrivateLongTermKey: state.localPrivateLongTermKey,
            remotePublicLongTermKey: state.remotePublicLongTermKey,
            localPrivateOneTimeKey: state.localPrivateOneTimeKey,
            remotePublicOneTimeKey: state.remotePublicOneTimeKey,
            remoteKyber1024PublicKey: state.remoteKyber1024PublicKey)
        
        await state.updateHeaderCiphertext(headerCipher.ciphertext)
        await state.updateSendingHeaderKey(headerCipher.symmetricKey)
        
        let nextSendingHeaderKey = try await derivePQXDHFinalKey(
            localPrivateLongTermKey: state.localPrivateLongTermKey,
            remotePublicLongTermKey: state.remotePublicLongTermKey,
            localPrivateOneTimeKey: state.localPrivateOneTimeKey,
            remotePublicOneTimeKey: state.remotePublicOneTimeKey,
            remoteKyber1024PublicKey: state.remoteKyber1024PublicKey)
        
        await state.updateSendingNextHeaderKey(nextSendingHeaderKey.symmetricKey)
        try await updateSessionIdentity(state: state)
        
        let localPublicLongTermKey = try Curve25519PrivateKey(rawRepresentation: state.localPrivateLongTermKey).publicKey.rawRepresentation
        let localPublicOneTimeKey = try Curve25519PrivateKey(rawRepresentation: state.localPrivateOneTimeKey).publicKey.rawRepresentation
        
        let encryptedHeader = try await encryptHeader(
            messageHeader,
            remotePublicLongTermKey: localPublicLongTermKey,
            remotePublicOneTimeKey: localPublicOneTimeKey,
            remoteKyber1024PublicKey: state.localKyber1024PrivateKey)
        
        guard let encryptedData = try crypto.encrypt(
            data: plainText,
            symmetricKey: sendingKey
        ) else { throw RatchetError.encryptionFailed }
        
        let (newSendingKey, _) = try await deriveNextMessageKey(
            localPrivateLongTermKey: state.localPrivateLongTermKey,
            remotePublicLongTermKey: state.remotePublicLongTermKey,
            localPrivateOneTimeKey: state.localPrivateOneTimeKey,
            remotePublicOneTimeKey: state.remotePublicOneTimeKey,
            remoteKyber1024PublicKey: state.remoteKyber1024PublicKey)
        
        guard let associatedData = await configuration?.associatedData else {
            throw RatchetError.headerDataIsNil
        }
        let nonce = try await concatenate(
            associatedData: associatedData,
            header: encryptedHeader
        )
        guard nonce.count == 32 else {
            throw RatchetError.invalidNonceLength
        }
        
        guard var state = try await sessionProps().state else {
            throw RatchetError.stateUninitialized
        }
        
        await state.updateSendingKey(newSendingKey)
        await state.incrementSentMessagesCount()
        try await updateSessionIdentity(state: state)
        return RatchetMessage(header: encryptedHeader, encryptedData: encryptedData)
    }
    
    /// Runs PQXDH, then HKDF chain-key, then HMAC ratchet to get the next message key.
    private func deriveNextMessageKey(localPrivateLongTermKey: LocalPrivateLongTermKey,
                                      remotePublicLongTermKey: RemotePublicLongTermKey,
                                      localPrivateOneTimeKey: LocalPrivateOneTimeKey,
                                      remotePublicOneTimeKey: RemotePublicOneTimeKey,
                                      remoteKyber1024PublicKey: RemoteKyber1024PublicKey
    ) async throws -> (SymmetricKey, PQXDHCipher) {
        let cipher = try await derivePQXDHFinalKey(
            localPrivateLongTermKey: localPrivateLongTermKey,
            remotePublicLongTermKey: remotePublicLongTermKey,
            localPrivateOneTimeKey: localPrivateOneTimeKey,
            remotePublicOneTimeKey: remotePublicOneTimeKey,
            remoteKyber1024PublicKey: remoteKyber1024PublicKey)
        
        let ck = try await deriveChainKey(
            from: cipher.symmetricKey,
            configuration: defaultRatchetConfiguration)
        
        if var state = try await sessionProps().state {
            await state.updateRootKey(cipher.symmetricKey)
            await state.updateCiphertext(cipher.ciphertext)
            try await updateSessionIdentity(state: state)
        }
        
        return (try await symmetricKeyRatchet(from: ck), cipher)
    }
    
    private enum KeyChangeType {
        case none
        case longTermKeyChanged
        case oneTimeKeyChanged
    }
    
    public func ratchetDecrypt(_ message: RatchetMessage) async throws -> Data {
        guard var state = try await sessionProps().state else {
            throw RatchetError.stateUninitialized
        }
        
        let finalHeaderReceivingKey = try await derivePQXDHFinalKeyReceiver(
            remotePublicLongTermKey: message.header.remotePublicLongTermKey,
            remotePublicOneTimeKey: message.header.remotePublicOneTimeKey,
            localPrivateLongTermKey: state.localPrivateLongTermKey,
            localPrivateOneTimeKey: state.localPrivateOneTimeKey,
            localKyber1024PrivateKey: state.localKyber1024PrivateKey,
            receivedCiphertext: message.header.headerCiphertext)
        
        await state.updateReceivingHeaderKey(finalHeaderReceivingKey)
        try await updateSessionIdentity(state: state)
        
        let header = try await decryptHeader(message.header)
        
        let keyChangeType: KeyChangeType = {
            if message.header.remotePublicLongTermKey != state.remotePublicLongTermKey {
                return .longTermKeyChanged
            } else if message.header.remotePublicOneTimeKey != state.remotePublicOneTimeKey {
                return .oneTimeKeyChanged
            } else {
                return .none
            }
        }()
        
        switch keyChangeType {
        case .longTermKeyChanged, .oneTimeKeyChanged:
            if let nextReceivingHeaderKey = state.nextReceivingHeaderKey {
                await state.updateReceivingHeaderKey(nextReceivingHeaderKey)
            } else {
                throw RatchetError.missingNextHeaderKey
            }
            let newNextReceivingHeaderKey = try await derivePQXDHFinalKey(
                localPrivateLongTermKey: state.localPrivateLongTermKey,
                remotePublicLongTermKey: state.remotePublicLongTermKey,
                localPrivateOneTimeKey: state.localPrivateOneTimeKey,
                remotePublicOneTimeKey: state.remotePublicOneTimeKey,
                remoteKyber1024PublicKey: state.remoteKyber1024PublicKey)
            await state.updateReceivingNextHeaderKey(newNextReceivingHeaderKey.symmetricKey)
            state = try await diffieHellmanRatchet(header: header)
        case .none:
            let newNextReceivingHeaderKey = try await derivePQXDHFinalKey(
                localPrivateLongTermKey: state.localPrivateLongTermKey,
                remotePublicLongTermKey: state.remotePublicLongTermKey,
                localPrivateOneTimeKey: state.localPrivateOneTimeKey,
                remotePublicOneTimeKey: state.remotePublicOneTimeKey,
                remoteKyber1024PublicKey: state.remoteKyber1024PublicKey)
            await state.updateReceivingNextHeaderKey(newNextReceivingHeaderKey.symmetricKey)
        }
        
        guard let decrypted = header.decrypted else {
            throw RatchetError.headerDecryptFailed
        }
        
        let (foundMessage, _state) = try await checkForSkippedMessages(
            message,
            header: decrypted,
            skippedMessageKeys: state.skippedMessageKeys)
        try await updateSessionIdentity(state: _state)
        
        if let foundMessage = foundMessage {
            return try await processFoundMessage(decodedMessage: foundMessage)
        }
        
        if message.header.remotePublicLongTermKey != state.remotePublicLongTermKey && message.header.remotePublicOneTimeKey != state.remotePublicOneTimeKey {
            guard let configuration = await configuration else { throw RatchetError.missingConfiguration }
            state = try await trySkipMessageKeys(
                header: header,
                configuration: configuration)
            await state.updateSkippedMessages(with: state.skippedMessageKeys)
            try await updateSessionIdentity(state: state)
            state = try await diffieHellmanRatchet(header: header)
        } else if decrypted.messageNumber < state.receivedMessagesCount {
            throw RatchetError.expiredKey
        }
        guard let configuration = await configuration else { throw RatchetError.missingConfiguration }
        state = try await trySkipMessageKeys(
            header: header,
            configuration: configuration)
        await state.updateSkippedMessages(with: state.skippedMessageKeys)
        try await updateSessionIdentity(state: state)
        
        let finalReceivingKey = try await derivePQXDHFinalKeyReceiver(
            remotePublicLongTermKey: message.header.remotePublicLongTermKey,
            remotePublicOneTimeKey: message.header.remotePublicOneTimeKey,
            localPrivateLongTermKey: state.localPrivateLongTermKey,
            localPrivateOneTimeKey: state.localPrivateOneTimeKey,
            localKyber1024PrivateKey: state.localKyber1024PrivateKey,
            receivedCiphertext: message.header.messageCiphertext)
        
        await state.updateRemotePublicLongTermKey(message.header.remotePublicLongTermKey)
        await state.updateRemotePublicOneTimeKey(message.header.remotePublicOneTimeKey)
        
        try await updateSessionIdentity(state: state)
        
        let newReceivingKey = try await deriveChainKey(from: finalReceivingKey, configuration: configuration)
        let messageKey = try await symmetricKeyRatchet(from: newReceivingKey)
        await state.updateReceivingKey(messageKey)
        
        let newNextReceivingHeaderKey = try await derivePQXDHFinalKey(
            localPrivateLongTermKey: state.localPrivateLongTermKey,
            remotePublicLongTermKey: state.remotePublicLongTermKey,
            localPrivateOneTimeKey: state.localPrivateOneTimeKey,
            remotePublicOneTimeKey: state.remotePublicOneTimeKey,
            remoteKyber1024PublicKey: state.remoteKyber1024PublicKey)
        await state.updateReceivingNextHeaderKey(newNextReceivingHeaderKey.symmetricKey)
        
        try await updateSessionIdentity(state: state)
        
        await state.incrementReceivedMessagesCount()
        try await updateSessionIdentity(state: state)
        
        return try await processFoundMessage(
            decodedMessage: DecodedMessage(
                ratchetMessage: message,
                messageKey: messageKey))
    }
    
    /// Attempts to skip message keys based on the received message.
    private func trySkipMessageKeys(
        header: EncryptedHeader,
        configuration: RatchetConfiguration
    ) async throws -> RatchetState {
        guard var state = try await sessionProps().state else {
            throw RatchetError.stateUninitialized
        }
        guard let receivingKey = state.receivingKey else {
            return state
        }
        guard let decryptedHeader = header.decrypted else {
            throw RatchetError.decryptionFailed
        }
        
        while state.receivedMessagesCount < decryptedHeader.previousChainLength {
            let messageKey = try await symmetricKeyRatchet(from: receivingKey)
            let newReceivingKey = try await deriveChainKey(from: receivingKey, configuration: configuration)
            
            await state.updateReceivingKey(newReceivingKey)
            try await updateSessionIdentity(state: state)
            
            await state.updateSkippedMessages(skippedMessageKeys: SkippedMessageKey(
                remotePublicLongTermKey: header.remotePublicLongTermKey,
                remotePublicOneTimeKey: header.remotePublicOneTimeKey,
                messageIndex: state.receivedMessagesCount,
                messageKey: messageKey
            ))
            try await updateSessionIdentity(state: state)
            
            if state.skippedMessageKeys.count > configuration.maxSkippedMessageKeys {
                await state.removeFirstSkippedMessages()
                try await updateSessionIdentity(state: state)
            }
            
            await state.incrementReceivedMessagesCount()
            try await updateSessionIdentity(state: state)
        }
        return state
    }
    
    /// Processes a received message by decrypting its contents using the associated message key.
    ///
    /// - Parameter decodedMessage: The parsed message containing the ratcheted header and message key.
    /// - Returns: The decrypted plaintext message data.
    /// - Throws: `RatchetError.headerDataIsNil` if associated data is missing,
    ///           `RatchetError.invalidNonceLength` if nonce derivation fails,
    ///           `RatchetError.decryptionFailed` if decryption cannot be completed.
    private func processFoundMessage(decodedMessage: DecodedMessage) async throws -> Data {
        guard let associatedData = await configuration?.associatedData else { throw RatchetError.headerDataIsNil }
        let nonce = try await concatenate(
            associatedData: associatedData,
            header: decodedMessage.ratchetMessage.header
        )
        guard nonce.count == 32 else {
            throw RatchetError.invalidNonceLength
        }
        
        guard let decryptedMessage = try crypto.decrypt(
            data: decodedMessage.ratchetMessage.encryptedData,
            symmetricKey: decodedMessage.messageKey
        ) else { throw RatchetError.decryptionFailed }
        return decryptedMessage
    }
    
    /// A container for a decrypted ratchet message and its corresponding symmetric key.
    private struct DecodedMessage: Sendable {
        let ratchetMessage: RatchetMessage
        let messageKey: SymmetricKey
    }
    
    /// Attempts to decrypt a message using previously stored skipped message keys.
    ///
    /// - Parameters:
    ///   - message: The encrypted ratchet message.
    ///   - header: The parsed message header.
    ///   - skippedMessageKeys: A list of keys corresponding to skipped messages.
    /// - Returns: A tuple containing the decrypted message (if matched) and updated state.
    /// - Throws: `RatchetError.stateUninitialized` if the session state is unavailable.
    private func checkForSkippedMessages(
        _ message: RatchetMessage,
        header: MessageHeader,
        skippedMessageKeys: [SkippedMessageKey]
    ) async throws -> (DecodedMessage?, RatchetState) {
        guard var state = try await sessionProps().state else {
            throw RatchetError.stateUninitialized
        }
        
        for skippedMessageKey in skippedMessageKeys {
            if skippedMessageKey.messageIndex == header.messageNumber,
               message.header.remotePublicLongTermKey == skippedMessageKey.remotePublicLongTermKey &&
                message.header.remotePublicOneTimeKey == skippedMessageKey.remotePublicOneTimeKey {
                
                await state.removeSkippedMessages(at: skippedMessageKey.messageIndex)
                try await updateSessionIdentity(state: state)
                
                let finalReceivingKey = try await derivePQXDHFinalKeyReceiver(
                    remotePublicLongTermKey: message.header.remotePublicLongTermKey,
                    remotePublicOneTimeKey: message.header.remotePublicOneTimeKey,
                    localPrivateLongTermKey: state.localPrivateLongTermKey,
                    localPrivateOneTimeKey: state.localPrivateOneTimeKey,
                    localKyber1024PrivateKey: state.localKyber1024PrivateKey,
                    receivedCiphertext:  message.header.messageCiphertext
                )
                
                await state.updateReceivingKey(finalReceivingKey)
                await state.updateRemotePublicLongTermKey(message.header.remotePublicLongTermKey)
                await state.updateRemotePublicOneTimeKey(message.header.remotePublicOneTimeKey)
                
                try await updateSessionIdentity(state: state)
                
                let messageKey = try await symmetricKeyRatchet(from: finalReceivingKey)
                
                return (DecodedMessage(
                    ratchetMessage: message,
                    messageKey: messageKey
                ), state)
            }
        }
        
        return (nil, state)
    }
    
    /// Performs a symmetric-key ratchet step to derive the next message key.
    ///
    /// - Parameter symmetricKey: The current symmetric key in the ratchet chain.
    /// - Returns: A newly derived symmetric message key.
    /// - Throws: `RatchetError.missingConfiguration` if configuration is not available.
    private func symmetricKeyRatchet(from symmetricKey: SymmetricKey) async throws -> SymmetricKey {
        guard let configuration = await configuration else { throw RatchetError.missingConfiguration }
        let chainKey = HMAC<SHA256>.authenticationCode(for: configuration.messageKeyData, using: symmetricKey)
        return SymmetricKey(data: chainKey)
    }
    
    /// Derives a new chain key from a base symmetric key and ratchet configuration.
    ///
    /// - Parameters:
    ///   - symmetricKey: The base symmetric key to derive from.
    ///   - configuration: Ratchet configuration parameters used as context.
    /// - Returns: A derived symmetric chain key.
    private func deriveChainKey(
        from symmetricKey: SymmetricKey,
        configuration: RatchetConfiguration
    ) async throws -> SymmetricKey {
        let chainKey = HMAC<SHA256>.authenticationCode(for: configuration.chainKeyData, using: symmetricKey)
        return SymmetricKey(data: chainKey)
    }
    
    /// Concatenates associated data with a ratchet message header and hashes them into a nonce.
    ///
    /// - Parameters:
    ///   - associatedData: Application-level associated data (AAD) for AEAD encryption.
    ///   - header: The encrypted message header.
    /// - Returns: A 32-byte nonce derived via SHA-256 hash.
    /// - Throws: Encoding errors during BSON serialization.
    private func concatenate(
        associatedData: Data,
        header: EncryptedHeader
    ) async throws -> Data {
        let headerData = try BSONEncoder().encode(header).makeData()
        let info = headerData + associatedData
        let digest = SHA256.hash(data: info)
        return digest.withUnsafeBytes { buffer in
            Data(buffer: buffer.bindMemory(to: UInt8.self))
        }
    }
    
    /// Executes a full Diffie-Hellman ratchet step, updating keys and session state based on a new remote public key.
    ///
    /// - Parameter header: The header containing the new remote public keys.
    /// - Returns: An updated `RatchetState` after applying the DH ratchet.
    /// - Throws: `RatchetError.stateUninitialized` if the ratchet state is unavailable.
    private func diffieHellmanRatchet(header: EncryptedHeader) async throws -> RatchetState {
        guard var state = try await sessionProps().state else {
            throw RatchetError.stateUninitialized
        }
        
        await state.updatePreviousMessagesCount(state.sentMessagesCount)
        await state.updateSentMessagesCount(0)
        await state.updateReceivedMessagesCount(0)
        await state.updateRemotePublicLongTermKey(header.remotePublicLongTermKey)
        await state.updateRemotePublicOneTimeKey(header.remotePublicOneTimeKey)
        try await updateSessionIdentity(state: state)
        
        let (newReceivingKey, _) = try await deriveNextMessageKey(
            localPrivateLongTermKey: state.localPrivateLongTermKey,
            remotePublicLongTermKey: header.remotePublicLongTermKey,
            localPrivateOneTimeKey: state.localPrivateOneTimeKey,
            remotePublicOneTimeKey: header.remotePublicOneTimeKey,
            remoteKyber1024PublicKey: header.remoteKyber1024PublicKey)
        await state.updateReceivingKey(newReceivingKey)
        try await updateSessionIdentity(state: state)
        
        let newLocalPrivateKey = crypto.generateCurve25519PrivateKey().rawRepresentation
        await state.updateLocalPrivateOneTimeKey(newLocalPrivateKey)
        try await updateSessionIdentity(state: state)
        
        let (newSendingKey, _) = try await deriveNextMessageKey(
            localPrivateLongTermKey: state.localPrivateLongTermKey,
            remotePublicLongTermKey: header.remotePublicLongTermKey,
            localPrivateOneTimeKey: state.localPrivateOneTimeKey,
            remotePublicOneTimeKey: header.remotePublicOneTimeKey,
            remoteKyber1024PublicKey: header.remoteKyber1024PublicKey)
        await state.updateSendingKey(newSendingKey)
        try await updateSessionIdentity(state: state)
        
        return state
    }
    
    /// Derives a classical ECDH shared secret using Curve25519 keys.
    ///
    /// - Parameters:
    ///   - localPrivateKeyData: Local Curve25519 private key (raw bytes).
    ///   - remotePublicKeyData: Remote Curve25519 public key (raw bytes).
    /// - Returns: The derived shared secret.
    /// - Throws: Errors during key initialization or agreement.
    private func deriveSharedSecret(
        localPrivateKey: LocalPrivateKey,
        remotePublicKey: RemotePublicKey
    ) async throws -> SharedSecret {
        let localPrivateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: localPrivateKey)
        let remotePublicKeyData = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: remotePublicKey)
        return try localPrivateKey.sharedSecretFromKeyAgreement(with: remotePublicKeyData)
    }
    
    /// A container for encapsulated Kyber ciphertext and resulting symmetric key.
    private struct PQXDHCipher: Sendable {
        let ciphertext: Data
        let symmetricKey: SymmetricKey
    }
    
    /// Derives a PQ-X3DH hybrid key (sender side), combining Curve25519 and Kyber-1024 key exchange.
    ///
    /// - Returns: A `PQXDHCipher` containing Kyber ciphertext and final symmetric key.
    /// - Throws: Errors during key agreement or encapsulation.
    private func derivePQXDHFinalKey(
        localPrivateLongTermKey: LocalPrivateLongTermKey,
        remotePublicLongTermKey: RemotePublicLongTermKey,
        localPrivateOneTimeKey: LocalPrivateOneTimeKey,
        remotePublicOneTimeKey: RemotePublicOneTimeKey,
        remoteKyber1024PublicKey: RemoteKyber1024PublicKey
    ) async throws -> PQXDHCipher {
        let K_A = try await deriveSharedSecret(localPrivateKey: localPrivateLongTermKey, remotePublicKey: remotePublicLongTermKey)
        let K_A_ot = try await deriveSharedSecret(localPrivateKey: localPrivateOneTimeKey, remotePublicKey: remotePublicOneTimeKey)
        
        let K_A_data = K_A.withUnsafeBytes { Data($0) }
        let K_A_ot_data = K_A_ot.withUnsafeBytes { Data($0) }
        
        let remoteKyber1024PK = Kyber1024.KeyAgreement.PublicKey(rawRepresentation: remoteKyber1024PublicKey)
        let (ciphertext, sharedSecret) = try remoteKyber1024PK.encapsulate()
        let concatenatedSecrets = K_A_data + K_A_ot_data + sharedSecret.bytes
        
        let symmetricKey = HKDF<SHA512>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: concatenatedSecrets),
            salt: remotePublicOneTimeKey,
            outputByteCount: 32)
        
        return PQXDHCipher(ciphertext: ciphertext, symmetricKey: symmetricKey)
    }
    
    /// Derives the PQ-X3DH final key from received ciphertext and Curve25519 keys (receiver side).
    ///
    /// - Throws: Errors during shared secret derivation or Kyber decapsulation.
    private func derivePQXDHFinalKeyReceiver(
        remotePublicLongTermKey: RemotePublicLongTermKey,
        remotePublicOneTimeKey: RemotePublicOneTimeKey,
        localPrivateLongTermKey: LocalPrivateLongTermKey,
        localPrivateOneTimeKey: LocalPrivateOneTimeKey,
        localKyber1024PrivateKey: LocalKyber1024PrivateKey,
        receivedCiphertext: Data
    ) async throws -> SymmetricKey {
        let K_B = try await deriveSharedSecret(localPrivateKey: localPrivateLongTermKey, remotePublicKey: remotePublicLongTermKey)
        let K_B_ot = try await deriveSharedSecret(localPrivateKey: localPrivateOneTimeKey, remotePublicKey: remotePublicOneTimeKey)
        
        let K_B_data = K_B.withUnsafeBytes { Data($0) }
        let K_B_ot_data = K_B_ot.withUnsafeBytes { Data($0) }
        
        let localKyber1024PK = localKyber1024PrivateKey.decodeKyber1024()
        let sharedSecret = try localKyber1024PK.sharedSecret(from: receivedCiphertext)
        
        let salt = try Curve25519PrivateKey(rawRepresentation: localPrivateOneTimeKey).publicKey.rawRepresentation
        let concatenatedSecrets = K_B_data + K_B_ot_data + sharedSecret.bytes
        
        return HKDF<SHA512>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: concatenatedSecrets),
            salt: salt,
            outputByteCount: 32)
    }
}

extension RatchetStateManager {
    /// Encrypts a message header using the current sending header key (`HKs`).
    ///
    /// This function is responsible for encrypting the `MessageHeader` structure under
    /// the sender's current header key. It does not rotate keys; header key rotation
    /// is managed by the Double Ratchet and only occurs on a DH ratchet step.
    ///
    /// - Parameters:
    ///   - header: The clear (unencrypted) message header to be encrypted.
    ///   - remotePublicLongTermKey: The recipient's Curve25519 public key.
    ///   - remotePublicOneTimeKey: The recipient's ephemeral Curve25519 public key.
    ///   - remoteKyber1024PublicKey: The recipient's Kyber-1024 public key.
    ///
    /// - Returns: An `EncryptedHeader` struct containing the ciphertext of the header and associated metadata.
    ///
    /// - Throws:
    ///   - `RatchetError.stateUninitialized` if the current session state is unavailable.
    ///   - `RatchetError.headerKeysNil` if the current sending header key is missing.
    ///   - `RatchetError.missingCipherText` if required ciphertext placeholders are missing.
    ///   - `RatchetError.headerEncryptionFailed` if header encryption fails.
    private func encryptHeader(
        _ header: MessageHeader,
        remotePublicLongTermKey: RemotePublicLongTermKey,
        remotePublicOneTimeKey: RemotePublicOneTimeKey,
        remoteKyber1024PublicKey: RemoteKyber1024PublicKey
    ) async throws -> EncryptedHeader {
        guard let state = try await sessionProps().state else {
            throw RatchetError.stateUninitialized
        }
        guard let sendingHeaderKey = state.sendingHeaderKey else {
            throw RatchetError.headerKeysNil
        }
        guard let headerCiphertext = state.headerCiphertext else {
            throw RatchetError.missingCipherText
        }
        guard let messageCiphertext = state.messageCiphertext else {
            throw RatchetError.missingCipherText
        }
        
        // 1. Serialize the message header using BSON.
        let headerPlain = try BSONEncoder().encodeData(header)
        
        // 2. Construct a 96-bit nonce using the message counter.
        let counter = state.sentMessagesCount
        var ctrBytes = withUnsafeBytes(of: UInt64(counter).bigEndian) { Data($0) }
        ctrBytes.append(contentsOf: [UInt8](repeating: 0, count: 12 - ctrBytes.count))
        let nonce = try AES.GCM.Nonce(data: ctrBytes)
        
        // 3. Encrypt the serialized header.
        guard let encrypted = try crypto.encrypt(
            data: headerPlain,
            symmetricKey: sendingHeaderKey,
            nonce: nonce
        ) else {
            throw RatchetError.headerEncryptionFailed
        }
        
        return EncryptedHeader(
            remotePublicLongTermKey: remotePublicLongTermKey,
            remotePublicOneTimeKey: remotePublicOneTimeKey,
            remoteKyber1024PublicKey: remoteKyber1024PublicKey,
            headerCiphertext: headerCiphertext,
            messageCiphertext: messageCiphertext,
            encrypted: encrypted
        )
    }
}

extension RatchetStateManager {
    /// Attempts to decrypt a received encrypted header using current and skipped keys.
    ///
    /// This function tries the following keys in order to decrypt the incoming `EncryptedHeader`:
    /// 1. Any previously stored skipped message keys.
    /// 2. The current receiving header key (`HKr`).
    /// 3. The next receiving header key (`NHKr`)—this path indicates a new DH ratchet step is needed.
    ///
    /// If successful, the decrypted `MessageHeader` is attached to the returned `EncryptedHeader`.
    ///
    /// - Parameter encryptedHeader: The received, encrypted header message.
    /// - Returns: The same `EncryptedHeader` structure with the decrypted header attached.
    ///
    /// - Throws:
    ///   - `RatchetError.stateUninitialized` if session state is not available.
    ///   - `RatchetError.headerDecryptFailed` if all decryption attempts fail.
    private func decryptHeader(_ encryptedHeader: EncryptedHeader) async throws -> EncryptedHeader {
        guard var state = try await sessionProps().state else {
            throw RatchetError.stateUninitialized
        }
        
        var encryptedHeader = encryptedHeader
        
        // 1. Try skipped keys first.
        for key in state.skippedMessageKeys {
            if let decryptedData = try crypto.decrypt(data: encryptedHeader.encrypted, symmetricKey: key.messageKey),
               let header = try? BSONDecoder().decodeData(MessageHeader.self, from: decryptedData),
               header.messageNumber == key.messageIndex {
                encryptedHeader.setDecrypted(header)
                return encryptedHeader
            }
        }
        
        // 2. Try the current receiving header key (HKr).
        if let messageKey = state.receivingHeaderKey,
           let decryptedData = try crypto.decrypt(data: encryptedHeader.encrypted, symmetricKey: messageKey),
           let header = try? BSONDecoder().decodeData(MessageHeader.self, from: decryptedData) {
            encryptedHeader.setDecrypted(header)
            return encryptedHeader
        }
        
        // 3. Try next receiving header key (NHKr), implying a DH ratchet step.
        guard let nextMessageKey = state.nextReceivingHeaderKey else {
            throw RatchetError.headerDecryptFailed
        }
        
        await state.updateReceivingHeaderKey(nextMessageKey)
        try await updateSessionIdentity(state: state)
        
        guard let headerData = try crypto.decrypt(data: encryptedHeader.encrypted, symmetricKey: nextMessageKey) else {
            throw RatchetError.headerDecryptFailed
        }
        
        let header = try BSONDecoder().decodeData(MessageHeader.self, from: headerData)
        encryptedHeader.setDecrypted(header)
        return encryptedHeader
    }
}

public struct Kyber1024PrivateKeyRepresentable: Sendable {
    
    public let rawRepresentation: Data
    
    public init (_ rawRepresentation: Data) throws {
        let key = rawRepresentation.decodeKyber1024()
        
        guard key.rawRepresentation.count == Int(kyber1024PrivateKeyLength) else {
            throw KyberError.invalidKeySize
        }
        self.rawRepresentation = rawRepresentation
    }
}

public struct Kyber1024PublicKeyRepresentable: Sendable {
    
    public let rawRepresentation: Data
    
    public init (_ rawRepresentation: Data) throws {
        guard rawRepresentation.count == Int(kyber1024PublicKeyLength) else {
            throw KyberError.invalidKeySize
        }
        self.rawRepresentation = rawRepresentation
    }
}


public struct Curve25519PrivateKeyRepresentable: Sendable {
    
    public let rawRepresentation: Data
    
    public init (_ rawRepresentation: Data) throws {
        guard rawRepresentation.count == 32 else {
            throw KyberError.invalidKeySize
        }
        self.rawRepresentation = rawRepresentation
    }
}


public struct Curve25519PublicKeyRepresentable: Sendable {
    
    public let rawRepresentation: Data
    
    public init (_ rawRepresentation: Data) throws {
        guard rawRepresentation.count == 32 else {
            throw KyberError.invalidKeySize
        }
        self.rawRepresentation = rawRepresentation
    }
}
