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
public typealias RemotePublicOneTimeKey = Curve25519PublicKeyRepresentable
public typealias RemoteKyber1024PublicKey = Data
public typealias LocalPrivateLongTermKey = Data
public typealias LocalPrivateOneTimeKey = Curve25519PrivateKeyRepresentable
public typealias LocalKyber1024PrivateKey = Data

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
    func fetchPrivateOneTimeKey(_ id: UUID) async throws -> Curve25519PrivateKeyRepresentable

    /// Notifies that a new one-time key should be generated and made available.
    ///
    /// This may trigger background key generation or publication to a server.
    func updateOneTimeKey() async

    /// Removes a stored private one-time key by its identifier.
    ///
    /// - Parameter id: The UUID of the private key to remove.
    func removePrivateOneTimeKey(_ id: UUID) async

    /// Removes a published public one-time key by its identifier.
    ///
    /// - Parameter id: The UUID of the public key to remove.
    func removePublicOneTimeKey(_ id: UUID) async
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
public struct EncryptedHeader: Sendable, Codable {
    /// Sender's long-term public key.
    public let remotePublicLongTermKey: RemotePublicLongTermKey
    
    /// Sender's one-time public key.
    public let remotePublicOneTimeKey: RemotePublicOneTimeKey
    
    /// Sender's Kyber1024 public key used for key agreement.
    public let remoteKyber1024PublicKey: RemoteKyber1024PublicKey
    
    /// Header encapsulated ciphertext.
    public let headerCiphertext: Data
    
    /// Message encapsulated ciphertext.
    public let messageCiphertext: Data
    
    public let oneTimeId: UUID
    
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
        case oneTimeId = "f"
        case encrypted = "g"
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
        oneTimeId: UUID,
        encrypted: Data
    ) {
        self.remotePublicLongTermKey = remotePublicLongTermKey
        self.remotePublicOneTimeKey = remotePublicOneTimeKey
        self.remoteKyber1024PublicKey = remoteKyber1024PublicKey
        self.headerCiphertext = headerCiphertext
        self.messageCiphertext = messageCiphertext
        self.oneTimeId = oneTimeId
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
        oneTimeId: UUID,
        decrypted: MessageHeader
    ) {
        self.remotePublicLongTermKey = remotePublicLongTermKey
        self.remotePublicOneTimeKey = remotePublicOneTimeKey
        self.remoteKyber1024PublicKey = remoteKyber1024PublicKey
        self.headerCiphertext = headerCiphertext
        self.messageCiphertext = messageCiphertext
        self.encrypted = encrypted
        self.oneTimeId = oneTimeId
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
        messageNumber: Int,
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
    private(set) fileprivate var localPrivateOneTimeKey: LocalPrivateOneTimeKey?
    
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
    private(set) fileprivate var rootKey: SymmetricKey?
    
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
        localKyber1024PrivateKey: LocalKyber1024PrivateKey
    ) {
        self.remotePublicLongTermKey = remotePublicLongTermKey
        self.remotePublicOneTimeKey = remotePublicOneTimeKey
        self.remoteKyber1024PublicKey = remoteKyber1024PublicKey
        self.localPrivateLongTermKey = localPrivateLongTermKey
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
    mutating func updateRemotePublicOneTimeKey(_ remotePublicOneTimeKey: Curve25519PublicKeyRepresentable) async {
        self.remotePublicOneTimeKey = remotePublicOneTimeKey
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
    mutating func updateLocalPrivateOneTimeKey(_ localOTPrivateKey: Curve25519PrivateKeyRepresentable) async {
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
    case missingNextHeaderKey
    case missingOneTimeKey// Next header key is missing.
    case delegateNotSet                     // Next header key is missing.
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

        init(remotePublicLongTermKey: RemotePublicLongTermKey, remotePublicOneTimeKey: RemotePublicOneTimeKey, remoteKyber1024PublicKey: RemoteKyber1024PublicKey, localPrivateLongTermKey: LocalPrivateLongTermKey, localPrivateOneTimeKey: LocalPrivateOneTimeKey, localKyber1024PrivateKey: LocalKyber1024PrivateKey) {
            self.remotePublicLongTermKey = remotePublicLongTermKey
            self.remotePublicOneTimeKey = remotePublicOneTimeKey
            self.remoteKyber1024PublicKey = remoteKyber1024PublicKey
            self.localPrivateLongTermKey = localPrivateLongTermKey
            self.localPrivateOneTimeKey = localPrivateOneTimeKey
            self.localKyber1024PrivateKey = localKyber1024PrivateKey
        }
        
        public init(remote: RemoteKeys, local: LocalKeys) {
            self.init(
                remotePublicLongTermKey: remote.longTerm.rawRepresentation, // ✅ Data
                remotePublicOneTimeKey: remote.oneTime,                    // ✅ Curve25519PublicKeyRepresentable
                remoteKyber1024PublicKey: remote.kyber.rawRepresentation,  // ✅ Data
                localPrivateLongTermKey: local.longTerm.rawRepresentation, // ✅ Data
                localPrivateOneTimeKey: local.oneTime,                     // ✅ Curve25519PrivateKeyRepresentable
                localKyber1024PrivateKey: local.kyber.rawRepresentation    // ✅ Data
            )
        }
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

            let state = try await setState(for: messageType)
            try await updateSessionIdentity(state: state)
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
    
    /// Sets a  ratchet state based on message direction and keying material.
    private func setState(for messageType: MessageType) async throws -> RatchetState {
        switch messageType {
        case .receiving(let recipientKeys):
            return RatchetState(
                remotePublicLongTermKey: recipientKeys.remotePublicLongTermKey,
                remotePublicOneTimeKey: recipientKeys.remotePublicOneTimeKey,
                remoteKyber1024PublicKey: recipientKeys.remoteKyber1024PublicKey,
                localPrivateLongTermKey: recipientKeys.localPrivateLongTermKey,
                localKyber1024PrivateKey: recipientKeys.localKyber1024PrivateKey)
            
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
    
    /// Initializes a new sending session using the provided cryptographic identities and keys.
    ///
    /// This method prepares the local device for sending encrypted messages in a new session.
    /// It loads and validates all necessary cryptographic keys, binds them to the session identity,
    /// and prepares the ratchet state for outbound communication.
    ///
    /// - Parameters:
    ///   - sessionIdentity: A unique identity used to bind the session cryptographically (e.g. user or device identity).
    ///   - sessionSymmetricKey: A symmetric key used to encrypt metadata or protect session state.
    ///   - remoteKeys: The recipient's public keys, including long-term, one-time, and Kyber keys.
    ///   - localKeys: The sender's private keys, including long-term, one-time, and Kyber keys.
    /// - Throws: An error if the session cannot be initialized (e.g. invalid keys, storage issues).
    public func senderInitialization(
        sessionIdentity: SessionIdentity,
        sessionSymmetricKey: SymmetricKey,
        remoteKeys: RemoteKeys,
        localKeys: LocalKeys
    ) async throws {
        let keys = EncryptionKeys(remote: remoteKeys, local: localKeys)
        try await loadDeviceIdentities(
            sessionIdentity: sessionIdentity,
            sessionSymmetricKey: sessionSymmetricKey,
            messageType: .sending(keys))
    }

    /// Initializes a receiving session using the initial incoming message and cryptographic identities.
    ///
    /// This method processes the first received message in a new session, establishing shared secrets
    /// and preparing the ratchet state for continued secure communication. It must be called exactly once
    /// when handling a new incoming session initialization message.
    ///
    /// - Parameters:
    ///   - sessionIdentity: A unique identity used to bind the session cryptographically (e.g. user or device identity).
    ///   - sessionSymmetricKey: A symmetric key used to decrypt or authenticate session metadata.
    ///   - remoteKeys: The sender’s public keys used to derive the shared secret.
    ///   - localKeys: The receiver’s private keys required for decryption and ratchet initialization.
    ///   - initialMessage: The encrypted initial message received from the sender.
    /// - Returns: The decrypted plaintext content of the initial message.
    /// - Throws: An error if the message cannot be decrypted or the session cannot be initialized.
    public func recipientInitialization(
        sessionIdentity: SessionIdentity,
        sessionSymmetricKey: SymmetricKey,
        remoteKeys: RemoteKeys,
        localKeys: LocalKeys,
        initialMessage: RatchetMessage
    ) async throws -> Data {
        let keys = EncryptionKeys(remote: remoteKeys, local: localKeys)
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
    
    /// Encrypts a plaintext message using the post-quantum hybrid Double Ratchet protocol.
    ///
    /// This method generates a `RatchetMessage` by performing a hybrid (PQXDH) key derivation using both
    /// classical (Curve25519) and post-quantum (Kyber1024) primitives, establishing ephemeral symmetric keys
    /// for message confidentiality. It also constructs and encrypts a new message header with metadata to
    /// enable recipient-side ratchet state synchronization.
    ///
    /// - Parameter plainText: The plaintext message payload to encrypt.
    /// - Returns: A `RatchetMessage` containing the encrypted payload and associated encrypted header.
    /// - Throws:
    ///   - `RatchetError.stateUninitialized`: If the ratchet session state is not yet established.
    ///   - `RatchetError.sendingKeyIsNil`: If the current sending key is missing, indicating ratchet desynchronization.
    ///   - `RatchetError.missingOneTimeKey`: If the local ephemeral key is unavailable, which breaks PQXDH.
    ///   - `RatchetError.encryptionFailed`: If symmetric encryption of the payload fails.
    ///   - `RatchetError.headerDataIsNil`: If the associated data for nonce derivation is unavailable.
    ///   - `RatchetError.invalidNonceLength`: If the constructed AEAD nonce is not the expected 32 bytes.
    ///
    /// - Note:
    ///   This method assumes that the session state already contains all the necessary long-term and ephemeral
    ///   key material, and that the recipient's public key set has been previously authenticated and stored.
    ///
    /// - Important:
    ///   After message encryption, the one-time key used in this ratchet step is removed from local storage
    ///   via delegate callbacks to preserve forward secrecy. This ensures that keys are never reused and
    ///   enforces strict ephemeral key hygiene in the hybrid cryptosystem.
    ///
    /// - Warning:
    ///   The method is sensitive to nonce construction, key reuse, and state consistency. Failure to meet
    ///   these constraints may compromise confidentiality or forward secrecy.
    ///
    /// - SeeAlso:
    ///   `derivePQXDHFinalKey`, `encryptHeader`, `updateSessionIdentity`, `RatchetMessage`
    public func ratchetEncrypt(plainText: Data) async throws -> RatchetMessage {
        // Step 1: Load and validate current ratchet state.
        guard var state = try await sessionProps().state else {
            throw RatchetError.stateUninitialized
        }

        guard let sendingKey = state.sendingKey else {
            throw RatchetError.sendingKeyIsNil
        }

        guard let localPrivateOneTimeKey = state.localPrivateOneTimeKey else {
            throw RatchetError.missingOneTimeKey
        }

        // Step 2: Construct ratchet header metadata.
        let messageHeader = MessageHeader(
            previousChainLength: state.previousMessagesCount,
            messageNumber: state.sentMessagesCount)

        // Step 3: Derive symmetric header encryption key using hybrid PQXDH.
        let headerCipher = try await derivePQXDHFinalKey(
            localPrivateLongTermKey: state.localPrivateLongTermKey,
            remotePublicLongTermKey: state.remotePublicLongTermKey,
            localPrivateOneTimeKey: localPrivateOneTimeKey,
            remotePublicOneTimeKey: state.remotePublicOneTimeKey,
            remoteKyber1024PublicKey: state.remoteKyber1024PublicKey)

        await state.updateHeaderCiphertext(headerCipher.ciphertext)
        await state.updateSendingHeaderKey(headerCipher.symmetricKey)

        // Step 4: Preemptively derive the next header key for forward secrecy.
        let nextSendingHeaderKey = try await derivePQXDHFinalKey(
            localPrivateLongTermKey: state.localPrivateLongTermKey,
            remotePublicLongTermKey: state.remotePublicLongTermKey,
            localPrivateOneTimeKey: localPrivateOneTimeKey,
            remotePublicOneTimeKey: state.remotePublicOneTimeKey,
            remoteKyber1024PublicKey: state.remoteKyber1024PublicKey)

        await state.updateSendingNextHeaderKey(nextSendingHeaderKey.symmetricKey)

        try await updateSessionIdentity(state: state)

        // Step 5: Reconstruct local public keys to embed into the header.
        let localPublicLongTermKey = try Curve25519PrivateKey(rawRepresentation: state.localPrivateLongTermKey)
            .publicKey.rawRepresentation

        let localPublicOneTimeKey = try Curve25519PrivateKey(rawRepresentation: localPrivateOneTimeKey.rawRepresentation)
            .publicKey.rawRepresentation

        let localKyber1024PublicKey = state.localKyber1024PrivateKey.decodeKyber1024()
            .publicKey.rawRepresentation

        // Step 6: Encrypt the message header using AEAD.
        let encryptedHeader = try await encryptHeader(
            messageHeader,
            remotePublicLongTermKey: localPublicLongTermKey,
            remotePublicOneTimeKey: .init(id: localPrivateOneTimeKey.id, localPublicOneTimeKey),
            remoteKyber1024PublicKey: localKyber1024PublicKey,
            oneTimeId: state.remotePublicOneTimeKey.id)

        // Step 7: Encrypt the payload using AEAD with the current sending key.
        guard let encryptedData = try crypto.encrypt(
            data: plainText,
            symmetricKey: sendingKey
        ) else {
            throw RatchetError.encryptionFailed
        }

        // Step 8: Derive the next symmetric sending key in the message chain.
        let (newSendingKey, _) = try await deriveNextMessageKey(
            localPrivateLongTermKey: state.localPrivateLongTermKey,
            remotePublicLongTermKey: state.remotePublicLongTermKey,
            localPrivateOneTimeKey: localPrivateOneTimeKey,
            remotePublicOneTimeKey: state.remotePublicOneTimeKey,
            remoteKyber1024PublicKey: state.remoteKyber1024PublicKey)

        // Step 9: Construct nonce and validate its integrity.
        guard let associatedData = await configuration?.associatedData else {
            throw RatchetError.headerDataIsNil
        }

        let nonce = try await concatenate(
            associatedData: associatedData,
            header: encryptedHeader)

        guard nonce.count == 32 else {
            throw RatchetError.invalidNonceLength
        }

        // Step 10: Finalize state update and remove ephemeral keys.
        guard var state = try await sessionProps().state else {
            throw RatchetError.stateUninitialized
        }

        await state.updateSendingKey(newSendingKey)
        await state.incrementSentMessagesCount()
        try await updateSessionIdentity(state: state)

        await delegate?.removePublicOneTimeKey(localPrivateOneTimeKey.id)
        await delegate?.removePrivateOneTimeKey(localPrivateOneTimeKey.id)
        await delegate?.updateOneTimeKey()

        // Step 11: Package and return the full ratcheted message.
        return RatchetMessage(
            header: encryptedHeader,
            encryptedData: encryptedData)
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
    
    /// Represents the type of key change that occurred in the Double Ratchet protocol.
    ///
    /// This enum helps track changes in the key material used for message encryption, specifically
    /// differentiating between long-term and one-time key changes. It ensures that the correct ratchet state
    /// is updated depending on the type of key change detected, which is crucial for maintaining the security
    /// and integrity of the encrypted communication.
    ///
    /// - `none`: No key change occurred. The current keys (long-term and/or one-time) are still valid.
    /// - `longTermKeyChanged`: The long-term public key of the remote party has changed. This requires updating
    ///   the receiving key and other associated state parameters.
    /// - `oneTimeKeyChanged`: The one-time public key of the remote party has changed. This may also require updating
    ///   receiving keys and resetting ephemeral state for the session.

    private enum KeyChangeType {
        case none
        case longTermKeyChanged
        case oneTimeKeyChanged
    }

    
    /// Decrypts an incoming ratcheted message using the Double Ratchet and PQXDH mechanisms.
    ///
    /// This method processes a single incoming `RatchetMessage` by performing the necessary post-quantum hybrid
    /// key derivation (PQXDH), state synchronization, skipped message handling, and message decryption.
    ///
    /// It ensures that the session is initialized, applies appropriate header and message ratchets,
    /// and gracefully handles key changes (e.g. identity rotation or one-time key usage).
    ///
    /// - Parameter message: The encrypted ratchet message to be decrypted.
    /// - Returns: The decrypted message payload as `Data`.
    /// - Throws:
    ///   - `RatchetError.stateUninitialized` if the session state is missing.
    ///   - `RatchetError.delegateNotSet` if no delegate is configured to fetch private keys.
    ///   - `RatchetError.headerDecryptFailed` if header decryption fails.
    ///   - `RatchetError.expiredKey` if a message is received with an outdated key.
    ///   - `RatchetError.missingNextHeaderKey` if the expected next header key is not present.
    ///   - `RatchetError.missingConfiguration` if configuration is unavailable when required.
    ///
    /// - Important:
    ///   This method supports out-of-order message handling and ensures forward secrecy by discarding old keys
    ///   and rotating to new ones upon detection of a key change (e.g., long-term or one-time key updates).
    ///   If a message is received before a ratchet step completes, it will be handled via the skipped message mechanism.
    public func ratchetDecrypt(_ message: RatchetMessage) async throws -> Data {
        guard var state = try await sessionProps().state else {
            throw RatchetError.stateUninitialized
        }

        guard let delegate else {
            throw RatchetError.delegateNotSet
        }

        // Step 1: Retrieve and apply local private one-time key.
        let localPrivateOneTimeKey = try await delegate.fetchPrivateOneTimeKey(message.header.oneTimeId)
        await state.updateLocalPrivateOneTimeKey(localPrivateOneTimeKey)
        try await updateSessionIdentity(state: state)

        // Step 2: Derive final header receiving key using PQXDH.
        let finalHeaderReceivingKey = try await derivePQXDHFinalKeyReceiver(
            remotePublicLongTermKey: message.header.remotePublicLongTermKey,
            remotePublicOneTimeKey: message.header.remotePublicOneTimeKey,
            localPrivateLongTermKey: state.localPrivateLongTermKey,
            localPrivateOneTimeKey: localPrivateOneTimeKey,
            localKyber1024PrivateKey: state.localKyber1024PrivateKey,
            receivedCiphertext: message.header.headerCiphertext)

        await state.updateReceivingHeaderKey(finalHeaderReceivingKey)
        try await updateSessionIdentity(state: state)

        // Step 3: Decrypt header to extract metadata.
        let header = try await decryptHeader(message.header)

        // Step 4: Determine whether key change occurred.
        let keyChangeType: KeyChangeType = {
            if message.header.remotePublicLongTermKey != state.remotePublicLongTermKey {
                return .longTermKeyChanged
            } else if message.header.remotePublicOneTimeKey.id != state.remotePublicOneTimeKey.id {
                return .oneTimeKeyChanged
            } else {
                return .none
            }
        }()

        switch keyChangeType {
        case .longTermKeyChanged, .oneTimeKeyChanged:
            guard let nextReceivingHeaderKey = state.nextReceivingHeaderKey else {
                throw RatchetError.missingNextHeaderKey
            }
            await state.updateReceivingHeaderKey(nextReceivingHeaderKey)

            let newNextReceivingHeaderKey = try await derivePQXDHFinalKey(
                localPrivateLongTermKey: state.localPrivateLongTermKey,
                remotePublicLongTermKey: state.remotePublicLongTermKey,
                localPrivateOneTimeKey: localPrivateOneTimeKey,
                remotePublicOneTimeKey: state.remotePublicOneTimeKey,
                remoteKyber1024PublicKey: state.remoteKyber1024PublicKey)
            await state.updateReceivingNextHeaderKey(newNextReceivingHeaderKey.symmetricKey)

            state = try await diffieHellmanRatchet(header: header)

        case .none:
            let newNextReceivingHeaderKey = try await derivePQXDHFinalKey(
                localPrivateLongTermKey: state.localPrivateLongTermKey,
                remotePublicLongTermKey: state.remotePublicLongTermKey,
                localPrivateOneTimeKey: localPrivateOneTimeKey,
                remotePublicOneTimeKey: state.remotePublicOneTimeKey,
                remoteKyber1024PublicKey: state.remoteKyber1024PublicKey)
            await state.updateReceivingNextHeaderKey(newNextReceivingHeaderKey.symmetricKey)
        }

        guard let decrypted = header.decrypted else {
            throw RatchetError.headerDecryptFailed
        }

        // Step 5: Handle skipped or out-of-order messages.
        let (foundMessage, _state) = try await checkForSkippedMessages(
            message,
            header: decrypted,
            skippedMessageKeys: state.skippedMessageKeys)
        try await updateSessionIdentity(state: _state)

        if let foundMessage {
            return try await processFoundMessage(decodedMessage: foundMessage)
        }

        // Step 6: Handle ratchet advancement on simultaneous key change.
        if message.header.remotePublicLongTermKey != state.remotePublicLongTermKey &&
           message.header.remotePublicOneTimeKey.id != state.remotePublicOneTimeKey.id {
            guard let configuration = await configuration else {
                throw RatchetError.missingConfiguration
            }
            state = try await trySkipMessageKeys(header: header, configuration: configuration)
            await state.updateSkippedMessages(with: state.skippedMessageKeys)
            try await updateSessionIdentity(state: state)
            state = try await diffieHellmanRatchet(header: header)
        } else if decrypted.messageNumber < state.receivedMessagesCount {
            throw RatchetError.expiredKey
        }

        // Step 7: Final PQXDH to decrypt message content.
        guard let configuration = await configuration else {
            throw RatchetError.missingConfiguration
        }
        state = try await trySkipMessageKeys(header: header, configuration: configuration)
        await state.updateSkippedMessages(with: state.skippedMessageKeys)
        try await updateSessionIdentity(state: state)

        let finalReceivingKey = try await derivePQXDHFinalKeyReceiver(
            remotePublicLongTermKey: message.header.remotePublicLongTermKey,
            remotePublicOneTimeKey: message.header.remotePublicOneTimeKey,
            localPrivateLongTermKey: state.localPrivateLongTermKey,
            localPrivateOneTimeKey: localPrivateOneTimeKey,
            localKyber1024PrivateKey: state.localKyber1024PrivateKey,
            receivedCiphertext: message.header.messageCiphertext)

        await state.updateRemotePublicLongTermKey(message.header.remotePublicLongTermKey)
        await state.updateRemotePublicOneTimeKey(message.header.remotePublicOneTimeKey)
        try await updateSessionIdentity(state: state)

        // Step 8: Derive message key and decrypt payload.
        let newReceivingKey = try await deriveChainKey(from: finalReceivingKey, configuration: configuration)
        let messageKey = try await symmetricKeyRatchet(from: newReceivingKey)
        await state.updateRootKey(finalReceivingKey)
        await state.updateReceivingKey(messageKey)

        let newNextReceivingHeaderKey = try await derivePQXDHFinalKey(
            localPrivateLongTermKey: state.localPrivateLongTermKey,
            remotePublicLongTermKey: state.remotePublicLongTermKey,
            localPrivateOneTimeKey: localPrivateOneTimeKey,
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
                remotePublicOneTimeKey: header.remotePublicOneTimeKey.rawRepresentation,
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
            symmetricKey: decodedMessage.messageKey) else {
            throw RatchetError.decryptionFailed
        }
        
        await delegate?.removePublicOneTimeKey(decodedMessage.ratchetMessage.header.oneTimeId)
        await delegate?.removePrivateOneTimeKey(decodedMessage.ratchetMessage.header.oneTimeId)
        await delegate?.updateOneTimeKey()
        
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
        guard let localPrivateOneTimeKey = state.localPrivateOneTimeKey else {
            throw RatchetError.missingOneTimeKey
        }
        
        for skippedMessageKey in skippedMessageKeys {
            if skippedMessageKey.messageIndex == header.messageNumber,
               message.header.remotePublicLongTermKey == skippedMessageKey.remotePublicLongTermKey &&
                message.header.remotePublicOneTimeKey.rawRepresentation == skippedMessageKey.remotePublicOneTimeKey {
                
                await state.removeSkippedMessages(at: skippedMessageKey.messageIndex)
                try await updateSessionIdentity(state: state)
                
                let finalReceivingKey = try await derivePQXDHFinalKeyReceiver(
                    remotePublicLongTermKey: message.header.remotePublicLongTermKey,
                    remotePublicOneTimeKey: message.header.remotePublicOneTimeKey,
                    localPrivateLongTermKey: state.localPrivateLongTermKey,
                    localPrivateOneTimeKey: localPrivateOneTimeKey,
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
        guard let localPrivateOneTimeKey = state.localPrivateOneTimeKey else {
            throw RatchetError.missingOneTimeKey
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
            localPrivateOneTimeKey: localPrivateOneTimeKey,
            remotePublicOneTimeKey: header.remotePublicOneTimeKey,
            remoteKyber1024PublicKey: header.remoteKyber1024PublicKey)
        await state.updateReceivingKey(newReceivingKey)
        try await updateSessionIdentity(state: state)
        
        guard let delegate else {
            throw RatchetError.delegateNotSet
        }
        
        //Get the next one time key from the local bundle
        let newLocalPrivateKey = try await delegate.fetchPrivateOneTimeKey(header.oneTimeId)
        await state.updateLocalPrivateOneTimeKey(newLocalPrivateKey)
        
        try await updateSessionIdentity(state: state)
        
        let (newSendingKey, _) = try await deriveNextMessageKey(
            localPrivateLongTermKey: state.localPrivateLongTermKey,
            remotePublicLongTermKey: header.remotePublicLongTermKey,
            localPrivateOneTimeKey: localPrivateOneTimeKey,
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
        let K_A_ot = try await deriveSharedSecret(localPrivateKey: localPrivateOneTimeKey.rawRepresentation, remotePublicKey: remotePublicOneTimeKey.rawRepresentation)
        
        let K_A_data = K_A.withUnsafeBytes { Data($0) }
        let K_A_ot_data = K_A_ot.withUnsafeBytes { Data($0) }
        
        let remoteKyber1024PK = Kyber1024.KeyAgreement.PublicKey(rawRepresentation: remoteKyber1024PublicKey)
        let (ciphertext, sharedSecret) = try remoteKyber1024PK.encapsulate()
        let concatenatedSecrets = K_A_data + K_A_ot_data + sharedSecret.bytes
        
        let symmetricKey = HKDF<SHA512>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: concatenatedSecrets),
            salt: remotePublicOneTimeKey.rawRepresentation,
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
        let K_B_ot = try await deriveSharedSecret(localPrivateKey: localPrivateOneTimeKey.rawRepresentation, remotePublicKey: remotePublicOneTimeKey.rawRepresentation)
        
        let K_B_data = K_B.withUnsafeBytes { Data($0) }
        let K_B_ot_data = K_B_ot.withUnsafeBytes { Data($0) }
        
        let localKyber1024PK = localKyber1024PrivateKey.decodeKyber1024()
        let sharedSecret = try localKyber1024PK.sharedSecret(from: receivedCiphertext)
        let salt = try Curve25519PrivateKey(rawRepresentation: localPrivateOneTimeKey.rawRepresentation).publicKey.rawRepresentation
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
        remoteKyber1024PublicKey: RemoteKyber1024PublicKey,
        oneTimeId: UUID
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
            oneTimeId: oneTimeId,
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

/// A representation of a Kyber1024 private key.
///
/// This struct wraps the raw `Data` of a Kyber1024 private key and ensures it is valid upon initialization.
public struct Kyber1024PrivateKeyRepresentable: Codable, Sendable {
    
    /// The raw key data.
    public let rawRepresentation: Data
    
    /// Initializes a new Kyber1024 private key wrapper.
    ///
    /// - Parameter rawRepresentation: The raw Kyber1024 private key bytes.
    /// - Throws: `KyberError.invalidKeySize` if the key size is incorrect.
    public init(_ rawRepresentation: Data) throws {
        let key = rawRepresentation.decodeKyber1024()
        
        guard key.rawRepresentation.count == Int(kyber1024PrivateKeyLength) else {
            throw KyberError.invalidKeySize
        }
        self.rawRepresentation = rawRepresentation
    }
}

/// A representation of a Kyber1024 public key.
///
/// This struct validates and stores the raw public key data for Kyber1024.
public struct Kyber1024PublicKeyRepresentable: Codable, Sendable {
    
    /// The raw key data.
    public let rawRepresentation: Data
    
    /// Initializes a new Kyber1024 public key wrapper.
    ///
    /// - Parameter rawRepresentation: The raw Kyber1024 public key bytes.
    /// - Throws: `KyberError.invalidKeySize` if the key size is incorrect.
    public init(_ rawRepresentation: Data) throws {
        guard rawRepresentation.count == Int(kyber1024PublicKeyLength) else {
            throw KyberError.invalidKeySize
        }
        self.rawRepresentation = rawRepresentation
    }
}

/// A representation of a Curve25519 private key with an associated UUID.
///
/// This is useful for identifying specific device keys across sessions.
public struct Curve25519PrivateKeyRepresentable: Codable, Sendable, Equatable {
    
    /// A unique identifier for the key (e.g. device or session key).
    public let id: UUID
    
    /// The raw key data.
    public let rawRepresentation: Data
    
    /// Initializes a new Curve25519 private key wrapper.
    ///
    /// - Parameters:
    ///   - id: An optional UUID to tag this key. A new UUID is generated if not provided.
    ///   - rawRepresentation: The raw 32-byte Curve25519 private key data.
    /// - Throws: `KyberError.invalidKeySize` if the key size is not 32 bytes.
    public init(id: UUID = UUID(), _ rawRepresentation: Data) throws {
        guard rawRepresentation.count == 32 else {
            throw KyberError.invalidKeySize
        }
        self.id = id
        self.rawRepresentation = rawRepresentation
    }
}

/// A representation of a Curve25519 public key with an associated UUID.
public struct Curve25519PublicKeyRepresentable: Codable, Sendable {
    
    /// A unique identifier for the key.
    public let id: UUID
    
    /// The raw key data.
    public let rawRepresentation: Data
    
    /// Initializes a new Curve25519 public key wrapper.
    ///
    /// - Parameters:
    ///   - id: An optional UUID to tag this key. A new UUID is generated if not provided.
    ///   - rawRepresentation: The raw 32-byte Curve25519 public key data.
    /// - Throws: `KyberError.invalidKeySize` if the key size is not 32 bytes.
    public init(id: UUID = UUID(), _ rawRepresentation: Data) throws {
        guard rawRepresentation.count == 32 else {
            throw KyberError.invalidKeySize
        }
        self.id = id
        self.rawRepresentation = rawRepresentation
    }
}

/// A container for all remote public keys used during session setup.
public struct RemoteKeys {
    
    /// The remote party's long-term Curve25519 public key.
    let longTerm: Curve25519PublicKeyRepresentable
    
    /// The remote party's one-time Curve25519 public key.
    let oneTime: Curve25519PublicKeyRepresentable
    
    /// The remote party's Kyber1024 public key.
    let kyber: Kyber1024PublicKeyRepresentable
    
    /// Initializes a container of remote keys for session initialization.
    public init(
        longTerm: Curve25519PublicKeyRepresentable,
        oneTime: Curve25519PublicKeyRepresentable,
        kyber: Kyber1024PublicKeyRepresentable
    ) {
        self.longTerm = longTerm
        self.oneTime = oneTime
        self.kyber = kyber
    }
}

/// A container for all local private keys used during session setup.
public struct LocalKeys {
    
    /// The local party's long-term Curve25519 private key.
    let longTerm: Curve25519PrivateKeyRepresentable
    
    /// The local party's one-time Curve25519 private key.
    let oneTime: Curve25519PrivateKeyRepresentable
    
    /// The local party's Kyber1024 private key.
    let kyber: Kyber1024PrivateKeyRepresentable
    
    /// Initializes a container of local keys for session initialization.
    public init(
        longTerm: Curve25519PrivateKeyRepresentable,
        oneTime: Curve25519PrivateKeyRepresentable,
        kyber: Kyber1024PrivateKeyRepresentable
    ) {
        self.longTerm = longTerm
        self.oneTime = oneTime
        self.kyber = kyber
    }
}
