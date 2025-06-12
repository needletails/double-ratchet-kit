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
import NeedleTailQueue


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



/*INITIAL MESSAGE (Handshake Phase)
 ------------------------------
 Sender Side:                            Receiver Side:
 
 1. PQXDH (hybrid DH) derives            1. PQXDH (hybrid DH) derives
 root key + initial sending key          root key + initial receiving key
 (derivePQXDHFinalKey)                   (derivePQXDHFinalKeyReceiver)
 
 2. Update sending header key            2. Update receiving header key
 (state.sendingHeaderKey)                (state.receivingHeaderKey)
 
 3. Derive chain key from root key      3. Derive chain key from root key
 (deriveChainKey)                       (deriveChainKey)
 
 4. Ratchet sending key (symmetric      4. Ratchet receiving key (symmetric
 KDF step)                             KDF step)
 
 5. Encrypt message header and payload  5. Decrypt message header and payload
 
 6. Mark handshake finished             6. Mark handshake finished
 
 ---
 
 SUBSEQUENT MESSAGES (Post-handshake)
 ----------------------------------
 
 Sender Side:                            Receiver Side:
 
 1. Ratchet sending header key          1. Ratchet receiving header key
 (symmetricKeyRatchet)                  (symmetricKeyRatchet)
 
 2. Ratchet sending key (chain key)    2. Ratchet receiving key (chain key)
 
 3. Update root key (optional, if       3. Update root key (optional, if
 new DH or PQXDH done)                  new DH or PQXDH done)
 
 4. Encrypt message header and payload  4. Decrypt message header and payload
 
 5. Increment message count             5. Increment message count
 
 6. Handle skipped/out-of-order msgs   6. Handle skipped/out-of-order msgs
 
 ---
 
 KEY FLOW SUMMARY:
 
 Root Key (PQXDH DH secret) ──► deriveChainKey ──► Chain Key ──► symmetricKeyRatchet (per message)
 
 Header Keys ratcheted similarly to maintain header encryption/decryption keys.
 */



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
    
    /// Last Skipped Message
    private(set) fileprivate var lastSkippedIndex: Int = 0
    
    /// A list of Skipped Header Message
    private(set) fileprivate var skippedHeaderMesages = [SkippedHeaderMessage]()
    
    /// The Index of the Skipped Header
    private(set) fileprivate var headerIndex: Int = 0
    
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
    
    /// Indicates if the sending hanshake has finished
    private(set) fileprivate var sendingHandshakeFinished: Bool = false
    
    /// Indicates if the receiving hanshake has finished
    private(set) fileprivate var receivingHandshakeFinished: Bool = false
    
    /// Indicates if the receiving hanshake has finished
    private(set) fileprivate var lastDecryptedMessageNumber: Int = 0
    
    private(set) fileprivate var alreadyDecryptedMessageNumbers = Set<Int>()
    
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
    /// Tracks whether `shutdown()` has been called.
    private nonisolated(unsafe) var didShutdown = false
    /// Holds all known session configurations keyed by session identity.
    private(set) public var sessionConfigurations = [SessionConfiguration]()
    
    /// The currently active session configuration.
    private var currentConfiguration: SessionConfiguration?
    private var state: RatchetState?
    public weak var delegate: SessionIdentityDelegate?
    public func setDelegate(_ delegate: SessionIdentityDelegate) {
        self.delegate = delegate
    }
    
    // Working with the set locally for performance.
    private var alreadyDecryptedMessageNumbers = Set<Int>()
    
    // MARK: - Initialization
    
    /// Initializes the ratchet state manager.
    /// - Parameter executor: A `SerialExecutor` used to coordinate concurrent operations within the actor.
    public init(executor: any SerialExecutor) {
        self.executor = executor
    }
    
    deinit {
        precondition(didShutdown, "⛔️ RatchetStateManager was deinitialized without calling shutdown(). ")
    }
    
    ///This must be called when the manager is done being used
    public func shutdown() async throws {
        guard let state else {
            return
        }
        await state.setAlreadyDecryptedMessageNumbers(alreadyDecryptedMessageNumbers)
        try await updateSessionIdentity(state: state)
        sessionConfigurations.removeAll()
        currentConfiguration = nil
        self.state = nil
        didShutdown = true
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
        let remotePublicOneTimeKey: RemotePublicOneTimeKey?
        let remoteKyber1024PublicKey: RemoteKyber1024PublicKey
        let localPrivateLongTermKey: LocalPrivateLongTermKey
        let localPrivateOneTimeKey: LocalPrivateOneTimeKey?
        let localKyber1024PrivateKey: LocalKyber1024PrivateKey
        
        init(remotePublicLongTermKey: RemotePublicLongTermKey, remotePublicOneTimeKey: RemotePublicOneTimeKey?, remoteKyber1024PublicKey: RemoteKyber1024PublicKey, localPrivateLongTermKey: LocalPrivateLongTermKey, localPrivateOneTimeKey: LocalPrivateOneTimeKey?, localKyber1024PrivateKey: LocalKyber1024PrivateKey) {
            self.remotePublicLongTermKey = remotePublicLongTermKey
            self.remotePublicOneTimeKey = remotePublicOneTimeKey
            self.remoteKyber1024PublicKey = remoteKyber1024PublicKey
            self.localPrivateLongTermKey = localPrivateLongTermKey
            self.localPrivateOneTimeKey = localPrivateOneTimeKey
            self.localKyber1024PrivateKey = localKyber1024PrivateKey
        }
        
        public init(remote: RemoteKeys, local: LocalKeys) {
            self.init(
                remotePublicLongTermKey: remote.longTerm.rawRepresentation,
                remotePublicOneTimeKey: remote.oneTime,
                remoteKyber1024PublicKey: remote.kyber,
                localPrivateLongTermKey: local.longTerm.rawRepresentation,
                localPrivateOneTimeKey: local.oneTime,
                localKyber1024PrivateKey: local.kyber)
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
    private func loadConfigurations(
        sessionIdentity: SessionIdentity,
        sessionSymmetricKey: SymmetricKey,
        messageType: MessageType
    ) async throws {
        
        //1. Check if we have a currently loaded session
        if let index = sessionConfigurations.firstIndex(where: {
            $0.sessionIdentity.id == sessionIdentity.id
        }) {
            
            guard var currentProps = await currentConfiguration?
                .sessionIdentity
                .props(symmetricKey: sessionSymmetricKey) else {
                throw RatchetError.missingProps
            }
            guard var props = await sessionIdentity.props(symmetricKey: sessionSymmetricKey) else {
                throw RatchetError.missingProps
            }
            
            //If we have a session and we call this method again we need to check if it is a new type
            switch messageType {
            case .sending(let keys):
                if let state = currentProps.state, state.sendingHandshakeFinished == false {
                    //Do intial sending setup and update the state with the ciphertext and sending key
                    
                    var lastKey: SymmetricKey
                    
                    if let sendingkey = currentProps.state?.sendingKey {
                        lastKey = sendingkey
                    } else {
                        guard let rootKey = state.rootKey else {
                            throw RatchetError.rootKeyIsNil
                        }
                        lastKey = rootKey
                    }
                    
                    var sendingKey = try await deriveChainKey(
                        from: lastKey,
                        configuration: defaultRatchetConfiguration)
                    
                    for _ in 0..<state.receivedMessagesCount {
                        sendingKey = try await deriveChainKey(
                            from: sendingKey,
                            configuration: defaultRatchetConfiguration)
                        
                        currentProps.state = await state.updateSendingKey(sendingKey)
                    }
                    
                    props.state = await state.updateSendingKey(sendingKey)
                }
                //Just update the keys
                currentProps.state = await currentProps.state?.updateRemotePublicLongTermKey(keys.remotePublicLongTermKey)
                currentProps.state = await currentProps.state?.updateRemotePublicOneTimeKey(keys.remotePublicOneTimeKey)
                currentProps.state = await currentProps.state?.updateRemoteKyber1024PublicKey(keys.remoteKyber1024PublicKey)
                currentProps.state = await currentProps.state?.updateLocalPrivateLongTermKey(keys.localPrivateLongTermKey)
                currentProps.state = await currentProps.state?.updateLocalPrivateOneTimeKey(keys.localPrivateOneTimeKey)
                currentProps.state = await currentProps.state?.updatelocalKyber1024PrivateKey(keys.localKyber1024PrivateKey)
            case .receiving(let keys):
                //Just update the keys on state since we dont generate a receiving key on configuration
                currentProps.state = await currentProps.state?.updateRemotePublicLongTermKey(keys.remotePublicLongTermKey)
                currentProps.state = await currentProps.state?.updateRemotePublicOneTimeKey(keys.remotePublicOneTimeKey)
                currentProps.state = await currentProps.state?.updateRemoteKyber1024PublicKey(keys.remoteKyber1024PublicKey)
                currentProps.state = await currentProps.state?.updateLocalPrivateLongTermKey(keys.localPrivateLongTermKey)
                currentProps.state = await currentProps.state?.updateLocalPrivateOneTimeKey(keys.localPrivateOneTimeKey)
                currentProps.state = await currentProps.state?.updatelocalKyber1024PrivateKey(keys.localKyber1024PrivateKey)
            }
            
            //Check if keys Changed
            if props.publicLongTermKey != currentProps.publicLongTermKey ||
                props.kyber1024PublicKey != currentProps.kyber1024PublicKey ||
                props.publicOneTimeKey != currentProps.publicOneTimeKey {
                var newState = await props.state?.updateSendingHandshakeFinished(false)
                newState = await props.state?.updateReceivingHandshakeFinished(false)
                props.state = newState
            }
            self.state = props.state
            try await sessionIdentity.updateIdentityProps(symmetricKey: sessionSymmetricKey, props: props)
            
            var config = sessionConfigurations[index]
            config.sessionIdentity = sessionIdentity
            config.sessionSymmetricKey = sessionSymmetricKey
            sessionConfigurations[index] = config
            currentConfiguration = config
            try await delegate?.updateSessionIdentity(sessionIdentity)
            
            
        } else {
            let configuration = SessionConfiguration(
                sessionIdentity: sessionIdentity,
                sessionSymmetricKey: sessionSymmetricKey)
            
            currentConfiguration = configuration
            
            let state = try await setState(for: messageType)
            self.alreadyDecryptedMessageNumbers = state.alreadyDecryptedMessageNumbers
            self.state = state
            guard var props = await sessionIdentity.props(symmetricKey: sessionSymmetricKey) else {
                throw RatchetError.missingProps
            }
            props.state = state
            try await sessionIdentity.updateIdentityProps(symmetricKey: sessionSymmetricKey, props: props)
            currentConfiguration?.sessionIdentity = sessionIdentity
            guard let currentConfiguration else {
                throw RatchetError.missingConfiguration
            }
            sessionConfigurations.append(currentConfiguration)
            try await delegate?.updateSessionIdentity(sessionIdentity)
        }
    }
    
    /// Returns unwrapped properties from the current session identity.
    private func sessionProps() async throws -> SessionIdentity.UnwrappedProps {
        guard let currentConfiguration else {
            throw RatchetError.missingConfiguration
        }
        
        guard let props = await currentConfiguration.sessionIdentity.props(
            symmetricKey: currentConfiguration.sessionSymmetricKey
        ) else {
            throw RatchetError.missingProps
        }
        return props
    }
    
    private func getRatchetState() async throws -> RatchetState {
        guard let state = state else {
            throw RatchetError.stateUninitialized
        }
        return state
    }
    
    /// Updates the session identity with a new ratchet state.
    private func updateSessionIdentity(state: RatchetState) async throws {
        guard let currentConfiguration else {
            throw RatchetError.missingConfiguration
        }
        
        var props = try await sessionProps()
        props.state = state
        try await currentConfiguration.sessionIdentity.updateIdentityProps(
            symmetricKey: currentConfiguration.sessionSymmetricKey,
            props: props)
        try await delegate?.updateSessionIdentity(currentConfiguration.sessionIdentity)
        if let index = sessionConfigurations.firstIndex(where: { $0.sessionIdentity.id == currentConfiguration.sessionIdentity.id }) {
            sessionConfigurations[index] = currentConfiguration
            self.currentConfiguration = currentConfiguration
        }
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
                localPrivateOneTimeKey: recipientKeys.localPrivateOneTimeKey,
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
        try await loadConfigurations(
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
    /// - Throws: An error if the message cannot be decrypted or the session cannot be initialized.
    public func recipientInitialization(
        sessionIdentity: SessionIdentity,
        sessionSymmetricKey: SymmetricKey,
        remoteKeys: RemoteKeys,
        localKeys: LocalKeys
    ) async throws {
        let keys = EncryptionKeys(remote: remoteKeys, local: localKeys)
        try await loadConfigurations(
            sessionIdentity: sessionIdentity,
            sessionSymmetricKey: sessionSymmetricKey,
            messageType: .receiving(keys))
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
        var state = try await getRatchetState()
        
        // Step 2: Construct ratchet header metadata.
        let messageHeader = MessageHeader(
            previousChainLength: state.previousMessagesCount,
            messageNumber: state.sentMessagesCount)
        
        if !state.sendingHandshakeFinished {
            // Step 3: Derive symmetric header encryption key using hybrid PQXDH.
            let headerCipher = try await derivePQXDHFinalKey(
                localPrivateLongTermKey: state.localPrivateLongTermKey,
                remotePublicLongTermKey: state.remotePublicLongTermKey,
                localPrivateOneTimeKey: state.localPrivateOneTimeKey,
                remotePublicOneTimeKey: state.remotePublicOneTimeKey,
                remoteKyber1024PublicKey: state.remoteKyber1024PublicKey)
            state = await state.updateHeaderCiphertext(headerCipher.ciphertext)
            state = await state.updateSendingHeaderKey(headerCipher.symmetricKey)
            
        } else {
            guard let sendingHeaderKey = state.sendingHeaderKey else {
                throw RatchetError.sendingKeyIsNil
            }
            
            let newSendingHeaderKey = try await deriveChainKey(
                from: sendingHeaderKey,
                configuration: defaultRatchetConfiguration)
            state = await state.updateSendingHeaderKey(newSendingHeaderKey)
        }
        
        guard let sendingHeaderKey = state.sendingHeaderKey else {
            throw RatchetError.sendingKeyIsNil
        }
        
        let nextSendingHeaderKey = try await deriveChainKey(
            from: sendingHeaderKey,
            configuration: defaultRatchetConfiguration)
        state = await state.updateSendingNextHeaderKey(nextSendingHeaderKey)
        
        // Step 5: Reconstruct local public keys to embed into the header.
        let localPublicLongTermKey = try Curve25519PrivateKey(rawRepresentation: state.localPrivateLongTermKey)
            .publicKey.rawRepresentation
        
        var remotePublicOneTimeKey: RemotePublicOneTimeKey?
        if let localPrivateOneTimeKey = state.localPrivateOneTimeKey {
            let localPublicOneTimeKey = try Curve25519PrivateKey(rawRepresentation: localPrivateOneTimeKey.rawRepresentation).publicKey.rawRepresentation
            remotePublicOneTimeKey = try RemotePublicOneTimeKey(id: localPrivateOneTimeKey.id, localPublicOneTimeKey)
        }
        let localKyber1024PublicKey = state.localKyber1024PrivateKey.rawRepresentation.decodeKyber1024()
            .publicKey.rawRepresentation
        self.state = state
        // Step 6: Encrypt the message header using AEAD.
        let encryptedHeader = try await encryptHeader(
            messageHeader,
            remotePublicLongTermKey: localPublicLongTermKey,
            remotePublicOneTimeKey: remotePublicOneTimeKey,
            remoteKyber1024PublicKey: .init(id: state.localKyber1024PrivateKey.id, localKyber1024PublicKey),
            curveOneTimeKeyId: state.remotePublicOneTimeKey?.id,
            kyberOneTimeKeyId: state.remoteKyber1024PublicKey.id)
        
        guard let sendingKey = state.sendingKey else {
            throw RatchetError.sendingKeyIsNil
        }
        
        // Step 7: Encrypt the payload using AEAD with the current sending key.
        let messageKey = try await symmetricKeyRatchet(from: sendingKey)
        guard let encryptedData = try crypto.encrypt(
            data: plainText,
            symmetricKey: messageKey
        ) else {
            throw RatchetError.encryptionFailed
        }
        
        if !state.sendingHandshakeFinished {
            state = await state.updateSendingHandshakeFinished(true)
        }
        
        let newChainKey = try await deriveChainKey(
            from: sendingKey,
            configuration: defaultRatchetConfiguration)
        
        state = await state.updateSendingKey(newChainKey)
        state = await state.incrementSentMessagesCount()
        
        let nonce = try await concatenate(
            associatedData: defaultRatchetConfiguration.associatedData,
            header: encryptedHeader)
        
        guard nonce.count == 32 else {
            throw RatchetError.invalidNonceLength
        }
        self.state = state
        try await updateSessionIdentity(state: state)
        return RatchetMessage(
            header: encryptedHeader,
            encryptedData: encryptedData)
    }
    
    
    /// Runs PQXDH, then HKDF chain-key, then HMAC ratchet to get the next message key.
    private func deriveNextMessageKey(localPrivateLongTermKey: LocalPrivateLongTermKey,
                                      remotePublicLongTermKey: RemotePublicLongTermKey,
                                      localPrivateOneTimeKey: LocalPrivateOneTimeKey?,
                                      remotePublicOneTimeKey: RemotePublicOneTimeKey?,
                                      remoteKyber1024PublicKey: RemoteKyber1024PublicKey
    ) async throws -> (SymmetricKey, PQXDHCipher) {
        let cipher = try await derivePQXDHFinalKey(
            localPrivateLongTermKey: localPrivateLongTermKey,
            remotePublicLongTermKey: remotePublicLongTermKey,
            localPrivateOneTimeKey: localPrivateOneTimeKey,
            remotePublicOneTimeKey: remotePublicOneTimeKey,
            remoteKyber1024PublicKey: remoteKyber1024PublicKey)
        
        let newChainKey = try await deriveChainKey(
            from: cipher.symmetricKey,
            configuration: defaultRatchetConfiguration)
        
        if var state = try await sessionProps().state {
            state = await state.updateRootKey(cipher.symmetricKey)
            state = await state.updateCiphertext(cipher.ciphertext)
        }
        
        return (newChainKey, cipher)
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
    
    /// Decrypts a received ratchet message according to the Double Ratchet protocol combined with PQXDH.
    ///
    /// This function processes both the handshake phase and subsequent encrypted messages.
    /// It manages ratchet state transitions, key derivations, skipped messages, and ratchet advancement securely.
    ///
    /// - Parameter message: The incoming `RatchetMessage` containing the encrypted payload and associated header.
    /// - Throws:
    ///   - `RatchetError.stateUninitialized` if the ratchet session state is missing.
    ///   - `RatchetError.delegateNotSet` if a delegate to fetch keys is not assigned.
    ///   - `RatchetError.sendingKeyIsNil` if required keys are missing during ratcheting.
    ///   - `RatchetError.missingNextHeaderKey` if a next header key is not available when needed.
    ///   - `RatchetError.headerDecryptFailed` if the header cannot be decrypted correctly.
    ///   - `RatchetError.expiredKey` if the message uses an expired key (replay or out-of-order).
    ///   - Other errors from cryptographic operations and key derivations.
    /// - Returns: The decrypted plaintext message data.
    ///
    /// - Important:
    ///   - Chain keys are advanced *only after* successful decryption to prevent desynchronization.
    ///   - The handshake completion triggers derivation and storage of root and chain keys.
    ///   - Key changes in the header (long-term or one-time keys) cause a Diffie-Hellman ratchet step.
    ///   - Skipped message keys are checked and processed to support out-of-order messages.
    ///
    /// - SeeAlso: `derivePQXDHFinalKeyReceiver(_:)`, `diffieHellmanRatchet(header:)`, `symmetricKeyRatchet(from:)`
    public func ratchetDecrypt(_ message: RatchetMessage) async throws -> Data {
        // Load current session state; error if uninitialized.
        var state = try await getRatchetState()
        
        // HEADER DECRYPTION PHASE
        if !state.receivingHandshakeFinished {
            // If handshake not finished, derive header receiving key using PQXDH final key receiver.
            // This combines multiple DH operations to produce the symmetric key for header encryption.
            let finalHeaderReceivingKey = try await derivePQXDHFinalKeyReceiver(
                remotePublicLongTermKey: state.remotePublicLongTermKey,
                remotePublicOneTimeKey: state.remotePublicOneTimeKey,
                localPrivateLongTermKey: state.localPrivateLongTermKey,
                localPrivateOneTimeKey: state.localPrivateOneTimeKey,
                localKyber1024PrivateKey: state.localKyber1024PrivateKey,
                receivedCiphertext: message.header.headerCiphertext)
            
            // Update state with new receiving header key and persist changes.
            state = await state.updateReceivingHeaderKey(finalHeaderReceivingKey)
        } else {
            
            // If handshake completed, ratchet receiving header key forward to derive next header key.
            if state.headerIndex == 0 {
                guard let receivingHeaderKey = state.receivingHeaderKey else {
                    throw RatchetError.receivingHeaderKeyIsNil
                }
                let newReceivingHeaderKey = try await deriveChainKey(from: receivingHeaderKey, configuration: defaultRatchetConfiguration)
                state = await state.updateReceivingHeaderKey(newReceivingHeaderKey)
            }
        }
        
        self.state = state
        // Decrypt the header now that the appropriate key is available.
        let header = try await decryptHeader(message.header)
        
        state = try await self.getRatchetState()
        
        // Ensure header was successfully decrypted before continuing.
        guard let decrypted = header.decrypted else {
            throw RatchetError.headerDecryptFailed
        }
        
        // Determine if key rotation occurred by comparing received header keys to stored keys.
        let keyChangeType: KeyChangeType = {
            if message.header.remotePublicLongTermKey != state.remotePublicLongTermKey {
                return .longTermKeyChanged
            } else if message.header.remotePublicOneTimeKey?.id != state.remotePublicOneTimeKey?.id {
                return .oneTimeKeyChanged
            } else {
                return .none
            }
        }()
        
        switch keyChangeType {
        case .longTermKeyChanged, .oneTimeKeyChanged:
            
            if let key = state.skippedMessageKeys.first(where: {
                $0.messageIndex == decrypted.messageNumber &&
                $0.remotePublicLongTermKey == header.remotePublicLongTermKey &&
                $0.remoteKyber1024PublicKey == header.remoteKyber1024PublicKey.rawRepresentation
            }) {
                if let oneTimeKey = key.remotePublicOneTimeKey, oneTimeKey != header.remotePublicOneTimeKey?.rawRepresentation {
                    throw RatchetError.expiredKey
                }
                state = await state.removeSkippedMessages(at: key.messageIndex)
                self.state = state
                try await updateSessionIdentity(state: state)
                
                return try await processFoundMessage(
                    decodedMessage: .init(ratchetMessage: message, chainKey: key.chainKey),
                    state: state,
                    messageNumber: decrypted.messageNumber)
            }
            
            state = try await generateSkippedMessageKeys(
                header: header,
                configuration: defaultRatchetConfiguration,
                state: state)
            self.state = state
            try await updateSessionIdentity(state: state)
            
            // On key change, advance receiving header key to next and perform DH ratchet step.
            guard let nextReceivingHeaderKey = state.nextReceivingHeaderKey else {
                throw RatchetError.missingNextHeaderKey
            }
            state = await state.updateReceivingNextHeaderKey(nextReceivingHeaderKey)
            self.state = state
            
            // Perform Diffie-Hellman ratchet to update root key, chain keys, and ratchet state.
            state = try await diffieHellmanRatchet(header: header)
            
            // After ratchet, derive next header key and update state.
            let newNextReceivingHeaderKey = try await derivePQXDHFinalKey(
                localPrivateLongTermKey: state.localPrivateLongTermKey,
                remotePublicLongTermKey: state.remotePublicLongTermKey,
                localPrivateOneTimeKey: state.localPrivateOneTimeKey,
                remotePublicOneTimeKey: state.remotePublicOneTimeKey,
                remoteKyber1024PublicKey: state.remoteKyber1024PublicKey)
            
            state = await state.updateReceivingNextHeaderKey(newNextReceivingHeaderKey.symmetricKey)
            
        case .none:
            // No key change detected:
            if !state.receivingHandshakeFinished {
                // During handshake, derive and store next receiving header key for upcoming messages.
                let newNextReceivingHeaderKey = try await derivePQXDHFinalKey(
                    localPrivateLongTermKey: state.localPrivateLongTermKey,
                    remotePublicLongTermKey: state.remotePublicLongTermKey,
                    localPrivateOneTimeKey: state.localPrivateOneTimeKey,
                    remotePublicOneTimeKey: state.remotePublicOneTimeKey,
                    remoteKyber1024PublicKey: state.remoteKyber1024PublicKey)
                
                state = await state.updateReceivingNextHeaderKey(newNextReceivingHeaderKey.symmetricKey)
            } else {
                // After handshake, advance next receiving header key by ratcheting it forward.
                guard let nextReceivingHeaderKey = state.nextReceivingHeaderKey else {
                    throw RatchetError.receivingHeaderKeyIsNil
                }
                let newReceivingHeaderKey = try await deriveChainKey(from: nextReceivingHeaderKey, configuration: defaultRatchetConfiguration)
                state = await state.updateReceivingNextHeaderKey(newReceivingHeaderKey)
            }
        }
        //Before this is header decryption and keys change logic(Keys are not changing in this scenario)
        if let key = state.skippedMessageKeys.first(where: {
            $0.messageIndex == decrypted.messageNumber &&
            $0.remotePublicLongTermKey == header.remotePublicLongTermKey &&
            $0.remoteKyber1024PublicKey == header.remoteKyber1024PublicKey.rawRepresentation
        }) {
            if let oneTimeKey = key.remotePublicOneTimeKey, oneTimeKey != header.remotePublicOneTimeKey?.rawRepresentation {
                throw RatchetError.expiredKey
            }
            state = await state.removeSkippedMessages(at: key.messageIndex)
            self.state = state
            try await updateSessionIdentity(state: state)
            return try await processFoundMessage(
                decodedMessage: .init(ratchetMessage: message, chainKey: key.chainKey),
                state: state,
                messageNumber: decrypted.messageNumber)
        }
        if decrypted.messageNumber >= state.receivedMessagesCount && state.receivedMessagesCount != 0 {
            //If we call again and only key 1 and 2 were derived, 3 was the target, yet we want to find key 5, we need to have a starting point of 4(Next Receiving Key) iterate once, return and the derive 5.
            state = try await generateSkippedMessageKeys(
                header: header,
                configuration: defaultRatchetConfiguration,
                state: state)
            self.state = state
            try await updateSessionIdentity(state: state)
        }
        //We then handle decryption logic.. at this point the keys must be in order
        // MESSAGE DECRYPTION PHASE
        if !state.receivingHandshakeFinished {
            
            var chainKey: SymmetricKey
            if state.rootKey == nil {
                if decrypted.messageNumber != 0 {
                    throw RatchetError.initialMessageNotReceived
                }
                // First message after handshake:
                // Derive root and chain keys from PQXDH final key receiver function.
                let finalReceivingKey = try await derivePQXDHFinalKeyReceiver(
                    remotePublicLongTermKey: state.remotePublicLongTermKey,
                    remotePublicOneTimeKey: state.remotePublicOneTimeKey,
                    localPrivateLongTermKey: state.localPrivateLongTermKey,
                    localPrivateOneTimeKey: state.localPrivateOneTimeKey,
                    localKyber1024PrivateKey: state.localKyber1024PrivateKey,
                    receivedCiphertext: message.header.messageCiphertext)
                
                if state.messageCiphertext == nil {
                    state = await state.updateCiphertext(message.header.messageCiphertext)
                }
                
                // Update remote public keys in state for future messages.
                state = await state.updateRemotePublicLongTermKey(message.header.remotePublicLongTermKey)
                if let remoteOneTime = message.header.remotePublicOneTimeKey {
                    state = await state.updateRemotePublicOneTimeKey(remoteOneTime)
                }
                
                // Derive chain key from the new root key.
                chainKey = try await deriveChainKey(from: finalReceivingKey, configuration: defaultRatchetConfiguration)
                let nextChainKey = try await deriveChainKey(from: chainKey, configuration: defaultRatchetConfiguration)
                // Update root and receiving chain key in state for ratchet progression.
                state = await state.updateRootKey(finalReceivingKey)
                state = await state.updateReceivingKey(nextChainKey)
            } else {
                
                var lastKey: SymmetricKey
                
                if let receivingKey = state.receivingKey {
                    lastKey = receivingKey
                } else {
                    guard let rootKey = state.rootKey else {
                        throw RatchetError.rootKeyIsNil
                    }
                    lastKey = rootKey
                }
                
                var receivingKey = try await deriveChainKey(
                    from: lastKey,
                    configuration: defaultRatchetConfiguration)
                
                for _ in 0..<state.sentMessagesCount {
                    receivingKey = try await deriveChainKey(
                        from: receivingKey,
                        configuration: defaultRatchetConfiguration)
                    state = await state.updateReceivingKey(receivingKey)
                }
                chainKey = receivingKey
                
                let nextChainKey = try await deriveChainKey(from: chainKey, configuration: defaultRatchetConfiguration)
                state = await state.updateReceivingKey(nextChainKey)
            }
            
            // Update State
            self.state = state
            try await updateSessionIdentity(state: state)
            
            // Process the decrypted message with derived message key.
            return try await processFoundMessage(
                decodedMessage: DecodedMessage(ratchetMessage: message, chainKey: chainKey),
                state: state,
                messageNumber: decrypted.messageNumber)
        } else {
            // Subsequent messages after handshake:
            guard let currentChainKey = state.receivingKey else {
                throw RatchetError.receivingKeyIsNil
            }
            
            // After successful decryption, advance the receiving chain key for the next message.
            let nextChainKey = try await deriveChainKey(from: currentChainKey, configuration: defaultRatchetConfiguration)
            state = await state.updateReceivingKey(nextChainKey)
            self.state = state
            try await updateSessionIdentity(state: state)
            // Process and return decrypted message.
            return try await processFoundMessage(
                decodedMessage: DecodedMessage(ratchetMessage: message, chainKey: currentChainKey),
                state: state,
                messageNumber: decrypted.messageNumber)
        }
    }
    
    /// Generates and stores skipped message keys for any missing messages up to the current header's message number.
    ///
    /// - Parameters:
    ///   - header: The incoming encrypted message header containing metadata and the decrypted payload.
    ///   - configuration: The ratchet configuration parameters (e.g., recursion depth, maximum skipped keys).
    ///   - state: The current ratchet state which holds chain keys, message counts, and skipped-key history.
    /// - Returns: An updated `RatchetState` with newly generated skipped message keys and an updated receiving chain key.
    /// - Throws: `RatchetError` if required keys are missing or if skipped-key storage is exhausted.
    private func generateSkippedMessageKeys(
        header: EncryptedHeader,
        configuration: RatchetConfiguration,
        state initialState: RatchetState
    ) async throws -> RatchetState {
        var state = initialState
        
        // Ensure we have a starting chain key and decrypted header data
        guard var chainKey = state.receivingKey else {
            throw RatchetError.receivingKeyIsNil
        }
        guard let decrypted = header.decrypted else {
            throw RatchetError.decryptionFailed
        }
        
        // If a skipped-key at the last skipped index exists, derive its next chain key
        if let matched = state.skippedMessageKeys
            .first(where: { $0.messageIndex == state.lastSkippedIndex }) {
            chainKey = try await deriveChainKey(from: matched.chainKey,
                                                configuration: configuration)
        }
        
        // Determine the starting index for gap-filling
        let startIndex: Int
        if state.skippedMessageKeys.isEmpty {
            startIndex = state.receivedMessagesCount
        } else if state.lastDecryptedMessageNumber > state.lastSkippedIndex {
            // Fill gaps between last skipped and last decrypted
            startIndex = state.lastDecryptedMessageNumber
        } else {
            // All previous messages have been decrypted; resume from last skipped
            guard let last = state.skippedMessageKeys.last else {
                throw RatchetError.skippedKeysDrained
            }
            // Reset chainKey to the last skipped key
            chainKey = last.chainKey
            startIndex = last.messageIndex
        }
        
        // Generate and store each skipped message key up to the incoming messageNumber
        for index in startIndex ..< decrypted.messageNumber {
            let skipped = SkippedMessageKey(
                remotePublicLongTermKey: header.remotePublicLongTermKey,
                remotePublicOneTimeKey: header.remotePublicOneTimeKey?.rawRepresentation,
                remoteKyber1024PublicKey: header.remoteKyber1024PublicKey.rawRepresentation,
                messageIndex: index,
                chainKey: chainKey
            )
            
            if !state.skippedMessageKeys.contains(where: { $0.messageIndex == index }) && !alreadyDecryptedMessageNumbers.contains(index) {
                state = await state.updateSkippedMessage(skippedMessageKey: skipped)
            }
            
            // Advance the chain key for the next skipped index
            chainKey = try await deriveChainKey(from: chainKey,
                                                configuration: configuration)
            state = await state.incrementSkippedMessageIndex()
            state = await state.updateReceivingKey(chainKey)
        }
        
        // Trim oldest skipped keys if exceeding the configured maximum
        let excess = state.skippedMessageKeys.count - configuration.maxSkippedMessageKeys
        if excess > 0 {
            state = await state.removeFirstSkippedMessages(count: excess)
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
    private func processFoundMessage(
        decodedMessage: DecodedMessage,
        state: RatchetState,
        messageNumber: Int
    ) async throws -> Data {
        var state = state
        let nonce = try await concatenate(
            associatedData: defaultRatchetConfiguration.associatedData,
            header: decodedMessage.ratchetMessage.header
        )
        guard nonce.count == 32 else {
            throw RatchetError.invalidNonceLength
        }
        
        let messageKey = try await symmetricKeyRatchet(from: decodedMessage.chainKey)
        if state.receivingHandshakeFinished == false  {
            guard let decryptedMessage = try crypto.decrypt(
                data: decodedMessage.ratchetMessage.encryptedData,
                symmetricKey: messageKey) else {
                throw RatchetError.decryptionFailed
            }
            // Increment count of received messages.
            state = await state.incrementReceivedMessagesCount()
            state = await state.updateReceivingHandshakeFinished(true)
            self.state = state
            try await updateSessionIdentity(state: state)
            return decryptedMessage
        } else {
            guard let decryptedMessage = try crypto.decrypt(
                data: decodedMessage.ratchetMessage.encryptedData,
                symmetricKey: messageKey) else {
                throw RatchetError.decryptionFailed
            }
            state = await state.incrementReceivedMessagesCount()
            state = await state.updateLastDecryptedMessageNumber(messageNumber)
            
//            state = await state.updateAlreadyDecryptedMessageNumber(messageNumber)
            alreadyDecryptedMessageNumbers.insert(messageNumber)

            self.state = state
            try await updateSessionIdentity(state: state)
            return decryptedMessage
        }
    }
    
    /// A container for a decrypted ratchet message and its corresponding symmetric key.
    private struct DecodedMessage: Sendable {
        let ratchetMessage: RatchetMessage
        let chainKey: SymmetricKey
    }
    
    
    /// Performs a symmetric-key ratchet step to derive the next message key.
    ///
    /// - Parameter symmetricKey: The current symmetric key in the ratchet chain.
    /// - Returns: A newly derived symmetric message key.
    /// - Throws: `RatchetError.missingConfiguration` if configuration is not available.
    private func symmetricKeyRatchet(from symmetricKey: SymmetricKey) async throws -> SymmetricKey {
        let chainKey = HMAC<SHA256>.authenticationCode(for: defaultRatchetConfiguration.messageKeyData, using: symmetricKey)
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
        var state = try await getRatchetState()
        
        state = await state.updatePreviousMessagesCount(state.sentMessagesCount)
        state = await state.updateSentMessagesCount(0)
        state = await state.updateReceivedMessagesCount(0)
        state = await state.resetAlreadyDecryptedMessageNumber()
        state = await state.removeAllSkippedHeaderMessage()
        state = await state.removeAllSkippedMessages()
        state = await state.updateRemotePublicLongTermKey(header.remotePublicLongTermKey)
        if let remotePublicOneTimeKey = header.remotePublicOneTimeKey {
            state = await state.updateRemotePublicOneTimeKey(remotePublicOneTimeKey)
        }
        
        // STEP 1: Derive receiving key using current local private key
        let (receivingKey, _) = try await deriveNextMessageKey(
            localPrivateLongTermKey: state.localPrivateLongTermKey,
            remotePublicLongTermKey: header.remotePublicLongTermKey,
            localPrivateOneTimeKey: state.localPrivateOneTimeKey,
            remotePublicOneTimeKey: header.remotePublicOneTimeKey,
            remoteKyber1024PublicKey: header.remoteKyber1024PublicKey)
        
        state = await state.updateReceivingKey(receivingKey)
        // STEP 2: Rotate local private key
        if let oneTimeId = header.remotePublicOneTimeKey?.id {
            guard let delegate else {
                throw RatchetError.delegateNotSet
            }
            let newLocalPrivateKey = try await delegate.fetchPrivateOneTimeKey(oneTimeId)
            state = await state.updateLocalPrivateOneTimeKey(newLocalPrivateKey)
        }
        
        // STEP 3: Derive sending key using the new local private key
        let (sendingKey, _) = try await deriveNextMessageKey(
            localPrivateLongTermKey: state.localPrivateLongTermKey,
            remotePublicLongTermKey: header.remotePublicLongTermKey,
            localPrivateOneTimeKey: state.localPrivateOneTimeKey, // <- this is now the *new* one
            remotePublicOneTimeKey: header.remotePublicOneTimeKey,
            remoteKyber1024PublicKey: header.remoteKyber1024PublicKey)
        
        state = await state.updateSendingKey(sendingKey)
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
        localPrivateOneTimeKey: LocalPrivateOneTimeKey?,
        remotePublicOneTimeKey: RemotePublicOneTimeKey?,
        remoteKyber1024PublicKey: RemoteKyber1024PublicKey
    ) async throws -> PQXDHCipher {
        let K_A = try await deriveSharedSecret(localPrivateKey: localPrivateLongTermKey, remotePublicKey: remotePublicLongTermKey)
        
        var K_A_ot_data = Data()
        if let localOTKey = localPrivateOneTimeKey, let remoteOTKey = remotePublicOneTimeKey {
            let K_A_ot = try await deriveSharedSecret(localPrivateKey: localOTKey.rawRepresentation, remotePublicKey: remoteOTKey.rawRepresentation)
            K_A_ot_data = K_A_ot.bytes
        }
        
        let K_A_data = K_A.bytes
        
        let remoteKyber1024PK = Kyber1024.KeyAgreement.PublicKey(rawRepresentation: remoteKyber1024PublicKey.rawRepresentation)
        let (ciphertext, sharedSecret) = try remoteKyber1024PK.encapsulate()
        let concatenatedSecrets = K_A_data + K_A_ot_data + sharedSecret.bytes
        
        let salt: Data
        if let remoteOTKey = remotePublicOneTimeKey {
            salt = remoteOTKey.rawRepresentation + remoteKyber1024PublicKey.rawRepresentation
        } else {
            // Use the remote long-term public key as a fallback salt (stable, non-empty)
            salt = remotePublicLongTermKey + remoteKyber1024PublicKey.rawRepresentation
        }
        let symmetricKey = HKDF<SHA512>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: concatenatedSecrets),
            salt: salt,
            outputByteCount: 32)
        
        return PQXDHCipher(ciphertext: ciphertext, symmetricKey: symmetricKey)
    }
    
    /// Derives the PQ-X3DH final key from received ciphertext and Curve25519 keys (receiver side).
    ///
    /// - Throws: Errors during shared secret derivation or Kyber decapsulation.
    private func derivePQXDHFinalKeyReceiver(
        remotePublicLongTermKey: RemotePublicLongTermKey,
        remotePublicOneTimeKey: RemotePublicOneTimeKey?,
        localPrivateLongTermKey: LocalPrivateLongTermKey,
        localPrivateOneTimeKey: LocalPrivateOneTimeKey?,
        localKyber1024PrivateKey: LocalKyber1024PrivateKey,
        receivedCiphertext: Data
    ) async throws -> SymmetricKey {
        
        // Derive shared secret for long-term keys
        let K_B = try await deriveSharedSecret(localPrivateKey: localPrivateLongTermKey, remotePublicKey: remotePublicLongTermKey)
        let K_B_data = K_B.bytes
        
        // Derive shared secret for one-time keys if both are present
        var K_B_ot_data = Data()
        if let localOTKey = localPrivateOneTimeKey, let remoteOTKey = remotePublicOneTimeKey {
            let K_B_ot = try await deriveSharedSecret(localPrivateKey: localOTKey.rawRepresentation, remotePublicKey: remoteOTKey.rawRepresentation)
            K_B_ot_data = K_B_ot.bytes
        }
        
        // Derive Kyber shared secret from ciphertext
        let localKyber1024PK = localKyber1024PrivateKey.rawRepresentation.decodeKyber1024()
        let sharedSecret = try localKyber1024PK.sharedSecret(from: receivedCiphertext)
        
        // Use local private one-time public key as salt if available, else fallback to long-term public key
        let salt: Data
        if let localOTKey = localPrivateOneTimeKey {
            let curveKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: localOTKey.rawRepresentation)
            let kyberKey = localKyber1024PrivateKey.rawRepresentation.decodeKyber1024()
            salt = curveKey.publicKey.rawRepresentation + kyberKey.publicKey.rawRepresentation
        } else {
            let curveKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: localPrivateLongTermKey)
            let kyberKey = localKyber1024PrivateKey.rawRepresentation.decodeKyber1024()
            salt = curveKey.publicKey.rawRepresentation + kyberKey.publicKey.rawRepresentation
        }
        
        // Concatenate secrets
        let concatenatedSecrets = K_B_data + K_B_ot_data + sharedSecret.bytes
        
        // Derive final symmetric key using HKDF with SHA512
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
        remotePublicOneTimeKey: RemotePublicOneTimeKey?,
        remoteKyber1024PublicKey: RemoteKyber1024PublicKey,
        curveOneTimeKeyId: UUID?,
        kyberOneTimeKeyId: UUID
    ) async throws -> EncryptedHeader {
        let state = try await getRatchetState()
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
        let messageKey = try await symmetricKeyRatchet(from: sendingHeaderKey)
        // 3. Encrypt the serialized header.
        guard let encrypted = try crypto.encrypt(
            data: headerPlain,
            symmetricKey: messageKey,
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
            curveOneTimeKeyId: curveOneTimeKeyId,
            kyberOneTimeKeyId: kyberOneTimeKeyId,
            encrypted: encrypted)
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
    func decryptHeader(_ encryptedHeader: EncryptedHeader) async throws -> EncryptedHeader {
        let state = try await getRatchetState()
        
        // If we have skipped header messages try and decrypt
        for headerMessage in state.skippedHeaderMesages {
            guard let (decrypted, newState) = try? await decryptHeaderMessage(
                encryptedHeader: encryptedHeader,
                chainKey: headerMessage.chainKey,
                index: headerMessage.index,
                state: state) else {
                continue
            }
            
            self.state = newState
            return decrypted
        }
        
        return try await decryptHeader(encryptedHeader: encryptedHeader, state: state)
    }
    
    private func decryptHeader(encryptedHeader: EncryptedHeader, state: RatchetState) async throws -> EncryptedHeader {
        var state = state
        guard let chainKey = state.receivingHeaderKey else {
            throw RatchetError.receivingHeaderKeyIsNil
        }
        
        do {
            let (ratchet, newState) = try await decryptHeaderMessage(
                encryptedHeader: encryptedHeader,
                chainKey: chainKey,
                index: nil,
                state: state)
            self.state = newState
            return ratchet
        } catch {
            
            if state.skippedHeaderMesages.count >= defaultRatchetConfiguration.maxSkippedMessageKeys {
                throw RatchetError.maxSkippedHeadersExceeded
            }
            
            for skipped in state.skippedHeaderMesages {
                if let (decrypted, newState) = try? await decryptHeaderMessage(
                    encryptedHeader: encryptedHeader,
                    chainKey: skipped.chainKey,
                    index: skipped.index,
                    state: state) {
                    self.state = newState
                    return decrypted
                }
            }
            
            state = try await headerRatchet(chainKey: chainKey, state: state)
            self.state = state
            return try await decryptHeader(encryptedHeader)
        }
    }
    
    private func headerRatchet(chainKey: SymmetricKey, state: RatchetState) async throws -> RatchetState {
        var state = try await getRatchetState()
        var chainKey = chainKey
        
        //If we fail ratchet
        if state.skippedHeaderMesages.count > 0 {
            chainKey = try await deriveChainKey(from: chainKey, configuration: defaultRatchetConfiguration)
        }
        
        state = await state.incrementSkippedHeaderIndex()
        
        let skippedHeader = SkippedHeaderMessage(
            chainKey: chainKey,
            index: state.headerIndex)
        
        state = await state.updateSkippedHeaderMessage(skippedHeader)
        state = await state.updateReceivingHeaderKey(chainKey)
        return state
    }
    
    private func decryptHeaderMessage(
        encryptedHeader: EncryptedHeader,
        chainKey: SymmetricKey,
        index: Int?,
        state: RatchetState
    ) async throws -> (EncryptedHeader, RatchetState) {
        var encryptedHeader = encryptedHeader
        var state = state
        
        let messageKey = try await symmetricKeyRatchet(from: chainKey)
        guard let decryptedData = try crypto.decrypt(data: encryptedHeader.encrypted, symmetricKey: messageKey) else {
            throw CryptoError.decryptionFailed
        }
        
        let header = try BSONDecoder().decodeData(MessageHeader.self, from: decryptedData)
        
        encryptedHeader.setDecrypted(header)
        
        if state.skippedHeaderMesages.count > 0 {
            if let headerMessage = state.skippedHeaderMesages.first(where: { $0.chainKey == chainKey }) {
                state = await state.removeSkippedHeaderMessage(headerMessage)
            }
        }
        return (encryptedHeader, state)
    }
}

/// A representation of a Kyber1024 private key.
///
/// This struct wraps the raw `Data` of a Kyber1024 private key and ensures it is valid upon initialization.
public struct Kyber1024PrivateKeyRepresentable: Codable, Sendable, Equatable {
    /// A unique identifier for the key (e.g. device or session key).
    public let id: UUID
    
    /// The raw key data.
    public let rawRepresentation: Data
    
    /// Initializes a new Kyber1024 private key wrapper.
    ///
    /// - Parameter rawRepresentation: The raw Kyber1024 private key bytes.
    /// - Throws: `KyberError.invalidKeySize` if the key size is incorrect.
    public init(id: UUID = UUID(), _ rawRepresentation: Data) throws {
        let key = rawRepresentation.decodeKyber1024()
        
        guard key.rawRepresentation.count == Int(kyber1024PrivateKeyLength) else {
            throw KyberError.invalidKeySize
        }
        self.id = id
        self.rawRepresentation = rawRepresentation
    }
}

/// A representation of a Kyber1024 public key.
///
/// This struct validates and stores the raw public key data for Kyber1024.
public struct Kyber1024PublicKeyRepresentable: Codable, Sendable, Equatable, Hashable {
    /// A unique identifier for the key (e.g. device or session key).
    public let id: UUID
    
    /// The raw key data.
    public let rawRepresentation: Data
    
    /// Initializes a new Kyber1024 public key wrapper.
    ///
    /// - Parameter rawRepresentation: The raw Kyber1024 public key bytes.
    /// - Throws: `KyberError.invalidKeySize` if the key size is incorrect.
    public init(id: UUID = UUID(), _ rawRepresentation: Data) throws {
        guard rawRepresentation.count == Int(kyber1024PublicKeyLength) else {
            throw KyberError.invalidKeySize
        }
        self.id = id
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
public struct Curve25519PublicKeyRepresentable: Codable, Sendable, Hashable {
    
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
    let oneTime: Curve25519PublicKeyRepresentable?
    
    /// The remote party's Kyber1024 public key.
    let kyber: Kyber1024PublicKeyRepresentable
    
    /// Initializes a container of remote keys for session initialization.
    public init(
        longTerm: Curve25519PublicKeyRepresentable,
        oneTime: Curve25519PublicKeyRepresentable?,
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
    let oneTime: Curve25519PrivateKeyRepresentable?
    
    /// The local party's Kyber1024 private key.
    let kyber: Kyber1024PrivateKeyRepresentable
    
    /// Initializes a container of local keys for session initialization.
    public init(
        longTerm: Curve25519PrivateKeyRepresentable,
        oneTime: Curve25519PrivateKeyRepresentable?,
        kyber: Kyber1024PrivateKeyRepresentable
    ) {
        self.longTerm = longTerm
        self.oneTime = oneTime
        self.kyber = kyber
    }
}
