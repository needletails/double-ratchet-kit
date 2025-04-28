//  DoubleRatchet.swift
//  needletail-crypto
//
//  Created by Cole M on 9/12/24.
//

@preconcurrency import Crypto
import Foundation
import BSON
import NeedleTailCrypto
import SwiftKyber

//TODO: -
/*
 1. **Header Encryption**
 4. Double Ratchet with header encryption - https://signal.org/docs/specifications/doubleratchet/doubleratchet.pdf
 
 2. **Deletion of skipped message keys**
 Storing skipped message keys introduces some risks:
 • A malicious sender could induce recipients to store large numbers of skipped message keys, possibly causing denial-of-service due to consuming storage space.
 • The lost messages may have been seen (and recorded) by an attacker, even though they didn’t reach the recipient. The attacker can compromise the intended recipient at a later time to retrieve the skipped message keys.
 
 To mitigate the first risk parties should set reasonable per-session limits on the number of skipped message keys that will be stored (e.g. 1000). To mitigate the second risk parties should delete skipped message keys after an appropriate interval. Deletion could be triggered by a timer, or by counting a number of events (messages received, DH ratchet steps, etc.).
 
 3. **Deferring new ratchet key generation**
 During each DH ratchet step a new ratchet key pair and sending chain are generated. As the sending chain is not needed right away, these steps could be deferred until the party is about to send a new message. This would slightly increase security by shortening the lifetime of ratchet keys, at the cost of some complexity.
 
 4. **Recovery from compromise**
 The DH ratchet is designed to recover security against a passive eavesdropper who observes encrypted messages after compromising one (or both) of the parties to a session. Despite this mitigation, a compromise of secret keys or of device integrity will have a devastating effect on the security of future communications. For example:
 • The attacker could use the compromised keys to impersonate the compro- mised party (e.g. using the compromised party’s identity private key with X3DH to create new sessions).
 • The attacker could substitute her own ratchet keys via continuous active man-in-the-middle attack, to maintain eavesdropping on the compromised session.
 • The attacker could modify a compromised party’s RNG so that future ratchet private keys are predictable.
 
 If a party suspects its keys or devices have been compromised, it must replace them immediately.
 
 5. **Integration with PQXDH** (The X3DH Key Agreement Protocol is out of date use the upgraded The PQXDH Key Agreement Protocol)
 https://signal.org/docs/specifications/x3dh/
 https://signal.org/docs/specifications/pqxdh/
 https://security.apple.com/blog/imessage-pq3/
 The Double Ratchet algorithm can be used in combination with the X3DH key agreement protocol [1]. The Double Ratchet plays the role of a “post-X3DH” protocol which takes the session key SK negotiated by X3DH and uses it as the Double Ratchet’s initial root key.
 The following outputs from X3DH are used by the Double Ratchet:
 • The SK output from X3DH becomes the SK input to Double Ratchet initialization (see Section 3.3).
 • The AD output from X3DH becomes the AD input to Double Ratchet encryption and decryption (see Section 3.4 and Section 3.5).
 • Bob’s signed prekey from X3DH (SPKB) becomes Bob’s initial ratchet public key (and corresponding key pair) for Double Ratchet initialization.
 Any Double Ratchet message encrypted using Alice’s initial sending chain can serve as an “initial ciphertext” for X3DH. To deal with the possibility of lost or out-of-order messages, a recommended pattern is for Alice to repeatedly send the same X3DH initial message prepended to all of her Double Ratchet messages until she receives Bob’s first Double Ratchet response message.
 */

/// Represents a set of skipped message keys for later processing in the Double Ratchet protocol.
public struct SkippedMessageKey: Codable, Sendable {
    let senderPublicLongTermKey: Data              // The public key of the sender associated with the skipped message.
    let senderPublicOneTimeKey: Data              // The public key of the sender associated with the skipped message.
    let messageIndex: Int            // The index of the skipped message.
    let messageKey: SymmetricKey     // The symmetric key used to encrypt the skipped message.
    
    private enum CodingKeys: String, CodingKey, Sendable {
        case senderPublicLongTermKey = "a"
        case senderPublicOneTimeKey = "b"
        case messageIndex = "c"
        case messageKey = "d"
    }
}

/// Represents an encrypted message along with its header in the Double Ratchet protocol.
public struct RatchetMessage: Codable, Sendable {
    let header: EncryptedHeader        // The header containing metadata about the message.
    let encryptedData: Data          // The encrypted content of the message.
    
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

public struct EncryptedHeader: Sendable, Codable {
    let remotePublicLongTermKey: Data  // Sender's long-term public key
    let remotePublicOneTimeKey: Data   // Sender's one-time public key
    let remoteKyber1024PublicKey: Kyber1024.KeyAgreement.PublicKey  // Sender's Kyber1024 public key
    let headerCiphertext: Data         // Header encapsulated ciphertext
    let messageCiphertext: Data        // Message encapsulated ciphertext
    let encrypted: Data                // Encrypted header body (e.g., BSON)
    
    // Only exists at runtime after decryption
    public private(set) var decrypted: MessageHeader?
    
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
    public init(
        remotePublicLongTermKey: Data,
        remotePublicOneTimeKey: Data,
        remoteKyber1024PublicKey: Kyber1024.KeyAgreement.PublicKey,
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
    public init(
        remotePublicLongTermKey: Data,
        remotePublicOneTimeKey: Data,
        remoteKyber1024PublicKey: Kyber1024.KeyAgreement.PublicKey,
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
    let previousChainLength: Int      // The length of the previous message chain.
    let messageNumber: Int            // The sequence number of the message.
    
    private enum CodingKeys: String, CodingKey, Sendable {
        case previousChainLength = "a"
        case messageNumber = "b"
    }
    
    /// Initializes a new MessageHeader with the specified parameters.
    /// - Parameters:
    ///   - senderPublicKey: The public key of the sender.
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

// Default configuration for the Double Ratchet protocol.
let defaultRatchetConfiguration = RatchetConfiguration(
    messageKeyData: Data([0x00]),                // Data for message key derivation.
    chainKeyData: Data([0x01]),                  // Data for chain key derivation.
    rootKeyData: Data([0x02, 0x03]),             // Data for root key derivation.
    associatedData: "NeedleTail DoubleRatchet".data(using: .ascii)!, // Associated data for messages.
    maxSkippedMessageKeys: 80                     // Maximum number of skipped message keys to retain.
)

/// Represents the state of the Double Ratchet protocol.
public struct RatchetState: Sendable, Codable {
    
    enum CodingKeys: String, CodingKey, Sendable, Codable {
        case localPrivateLongTermKey = "a"
        case localPrivateOneTimeKey = "b"
        case localPQKEMPrivateKey = "c"
        case remotePublicLongTermKey = "d"
        case remotePublicOneTimeKey = "e"
        case remotePQKEMPublicKey = "f"
        case messageCiphertext = "g"
        case rootKey = "h"
        case sendingKey = "i"
        case receivingKey = "j"
        case sentMessagesCount = "k"
        case receivedMessagesCount = "l"
        case previousMessagesCount = "m"
        case skippedMessageKeys = "n"
        case headerCiphertext = "o"
        case sendingHeaderKey = "p"
        case nextSendingHeaderKey = "q"
        case receivingHeaderKey = "r"
        case nextReceivingHeaderKey = "s"
    }
    
    // DHs - DH Ratchet key pair (the “sending” or “self” ratchet key)
    private(set) fileprivate var localPrivateLongTermKey: Data
    
    // X3DH DH Ratchet key pair (one-time) private key (the “sending” or “self” ratchet key per session)
    private(set) fileprivate var localPrivateOneTimeKey: Data
    
    // PQXDH DH Ratchet key pair (Post Quantum) private key (the “sending” or “self” ratchet key per session)
    private(set) fileprivate var localPQKEMPrivateKey: Kyber1024.KeyAgreement.PrivateKey
    
    // DHr - DH Ratchet public key (the “received” or “remote” key)
    private(set) fileprivate var remotePublicLongTermKey: Data?
    
    // X3DH DH Ratchet (one-time) public key (the once per session “received” or “remote” key)
    private(set) fileprivate var remotePublicOneTimeKey: Data?
    
    // PQXDH DH Ratchet key pair (Post Quantum) private key (the “sending” or “self” ratchet key per session)
    private(set) fileprivate var remotePQKEMPublicKey: Kyber1024.KeyAgreement.PublicKey
    
    // PQXDH CipherText
    private(set) fileprivate var messageCiphertext: Data?
    
    // RK - Root Key
    private(set) fileprivate var rootKey: SymmetricKey
    
    // CKs - Chain Key for sending
    private(set) fileprivate var sendingKey: SymmetricKey?
    
    // CKr - Chain Key for receiving
    private(set) fileprivate var receivingKey: SymmetricKey?
    
    // Ns - Message number for sending
    private(set) fileprivate var sentMessagesCount: Int = 0
    
    // Nr - Message number for receiving
    private(set) fileprivate var receivedMessagesCount: Int = 0
    
    // PN - Number of messages in previous sending chain
    private(set) fileprivate var previousMessagesCount: Int = 0
    
    // MKSKIPPED - Dictionary of skipped-over message keys
    private(set) fileprivate var skippedMessageKeys = [SkippedMessageKey]()
    
    // PQXDH Header CipherText
    private(set) fileprivate var headerCiphertext: Data?
    // HKs current sending header key
    private(set) fileprivate var sendingHeaderKey: SymmetricKey?
    // NHKs next sending header key
    private(set) fileprivate var nextSendingHeaderKey: SymmetricKey?
    // HKr current receiving header key
    private(set) fileprivate var receivingHeaderKey: SymmetricKey?
    // NHKr next receiving header key
    private(set) fileprivate var nextReceivingHeaderKey: SymmetricKey?
    
    init(
        remotePublicLongTermKey: Data,
        remotePublicOneTimeKey: Data,
        remotePQKEMPublicKey: Kyber1024.KeyAgreement.PublicKey,
        localPrivateLongTermKey: Data,
        localPrivateOneTimeKey: Data,
        localPQKEMPrivateKey: Kyber1024.KeyAgreement.PrivateKey,
        rootKey: SymmetricKey,
        messageCiphertext: Data,
        receivingKey: SymmetricKey,
    ) {
        self.remotePublicLongTermKey = remotePublicLongTermKey
        self.remotePublicOneTimeKey = remotePublicOneTimeKey
        self.remotePQKEMPublicKey = remotePQKEMPublicKey
        self.localPrivateLongTermKey = localPrivateLongTermKey
        self.localPrivateOneTimeKey = localPrivateOneTimeKey
        self.localPQKEMPrivateKey = localPQKEMPrivateKey
        self.rootKey = rootKey
        self.messageCiphertext = messageCiphertext
        self.receivingKey = receivingKey
    }
    
    init(
        remotePublicLongTermKey: Data,
        remotePublicOneTimeKey: Data,
        remotePQKEMPublicKey: Kyber1024.KeyAgreement.PublicKey,
        localPrivateLongTermKey: Data,
        localPrivateOneTimeKey: Data,
        localPQKEMPrivateKey: Kyber1024.KeyAgreement.PrivateKey,
        rootKey: SymmetricKey,
        messageCiphertext: Data,
        sendingKey: SymmetricKey,
    ) {
        self.remotePublicLongTermKey = remotePublicLongTermKey
        self.remotePublicOneTimeKey = remotePublicOneTimeKey
        self.remotePQKEMPublicKey = remotePQKEMPublicKey
        self.localPrivateLongTermKey = localPrivateLongTermKey
        self.localPrivateOneTimeKey = localPrivateOneTimeKey
        self.localPQKEMPrivateKey = localPQKEMPrivateKey
        self.rootKey = rootKey
        self.messageCiphertext = messageCiphertext
        self.sendingKey = sendingKey
    }
    
    mutating func updateSkippedMessages(skippedMessageKeys: SkippedMessageKey) async {
        self.skippedMessageKeys.append(skippedMessageKeys)
    }
    
    mutating func updateSkippedMessages(with newKeys: [SkippedMessageKey]) async {
        self.skippedMessageKeys = newKeys
    }
    
    mutating func removeFirstSkippedMessages() async {
        skippedMessageKeys.removeFirst()
    }
    
    mutating func removeSkippedMessages(at index: Int) async {
        skippedMessageKeys.remove(at: index)
    }
    
    mutating func incrementReceivedMessagesCount() async {
        receivedMessagesCount += 1
    }
    
    mutating func incrementSentMessagesCount() async {
        sentMessagesCount += 1
    }
    
    mutating func updateRemotePublicLongTermKey(_ remotePublicKey: Data) async {
        self.remotePublicLongTermKey = remotePublicKey
    }
    
    mutating func updateRemotePublicOneTimeKey(_ remoteOTPublicKey: Data) async {
        self.remotePublicOneTimeKey = remoteOTPublicKey
    }
    
    mutating func updateRemotePQKEMPublicKey(_ remotePQKEMPublicKey: Kyber1024.KeyAgreement.PublicKey) async {
        self.remotePQKEMPublicKey = remotePQKEMPublicKey
    }
    
    mutating func updateSendingKey(_ sendingKey: SymmetricKey) async {
        self.sendingKey = sendingKey
    }
    
    mutating func updateReceivingKey(_ receivingKey: SymmetricKey) async {
        self.receivingKey = receivingKey
    }
    
    mutating func updateLocalPrivateLongTermKey(_ localPrivateKey: Data) async {
        self.localPrivateLongTermKey = localPrivateKey
    }
    
    mutating func updateLocalPrivateOneTimeKey(_ localOTPrivateKey: Data) async {
        self.localPrivateOneTimeKey = localOTPrivateKey
    }
    
    mutating func updateLocalPQKEMPrivateKey(_ localPQKEMPrivateKey: Kyber1024.KeyAgreement.PrivateKey) async {
        self.localPQKEMPrivateKey = localPQKEMPrivateKey
    }
    
    mutating func updateSentMessagesCount(_ sentMessagesCount: Int) async {
        self.sentMessagesCount = sentMessagesCount
    }
    
    mutating func updateReceivedMessagesCount(_ receivedMessagesCount: Int) async {
        self.receivedMessagesCount = receivedMessagesCount
    }
    
    mutating func updatePreviousMessagesCount(_ previousMessagesCount: Int) async {
        self.previousMessagesCount = previousMessagesCount
    }
    
    mutating func updateRootKey(_ rootKey: SymmetricKey) async {
        self.rootKey = rootKey
    }
    
    mutating func updateCiphertext(_ cipherText: Data) async {
        self.messageCiphertext = cipherText
    }
    
    mutating func updateHeaderCiphertext(_ cipherText: Data) async {
        self.headerCiphertext = cipherText
    }
    
    mutating func updateSendingHeaderKey(_ HKs: SymmetricKey) async {
        self.sendingHeaderKey = HKs
    }
    
    mutating func updateSendingNextHeaderKey(_ NHKs: SymmetricKey) async {
        self.nextSendingHeaderKey = NHKs
    }
    
    mutating func updateReceivingHeaderKey(_ HKr: SymmetricKey) async {
        self.receivingHeaderKey = HKr
    }
    
    mutating func updateReceivingNextHeaderKey(_ NHKr: SymmetricKey) async {
        self.nextReceivingHeaderKey = NHKr
    }
}

internal enum RatchetError: Error {
    case missingConfiguration, missingDeviceIdentity, sendingKeyIsNil, headerDataIsNil, invalidNonceLength, encryptionFailed, decryptionFailed, expiredKey, receivingKeyIsNil, stateUninitialized, missingCipherText, headerKeysNil, missingLocalKeys, headerEncryptionFailed, headerDecryptFailed, missingNextHeaderKey
}

/// Manages the state of the Double Ratchet protocol for encryption sessions. We must inject the **RatchetState** object into the manager for state management of this devices cryptographic payload. We do that via `loadDeviceIdentities()` where the **DoubleRatchet** on that model is maped into our initialization. Each time we initalize a **RatchetState** via the sender or recipient we get the cached object. Therefor we must make sure that the cache is alway up to date.
public actor RatchetStateManager<Hash: HashFunction & Sendable> {
    
    let executor: any SerialExecutor
    
    public init(executor: any SerialExecutor) {
        self.executor = executor
    }
    
    public nonisolated var unownedExecutor: UnownedSerialExecutor {
        executor.asUnownedSerialExecutor()
    }
    
    private let crypto = NeedleTailCrypto()
    
    //Only should be used to set. do not get from this property
    private var privateState: RatchetState?
    private var currentState: RatchetState? {
        get async {
            privateState
        }
    }
    
    var configuration: RatchetConfiguration? {
        get async {
            defaultRatchetConfiguration
        }
    }
    
    enum MessageType: Sendable {
        case sending(EncryptionKeys), receiving(EncryptionKeys)
    }
    
    struct EncryptionKeys: Sendable {
        let remotePublicLongTermKey: Curve25519PublicKey
        let remotePublicOneTimeKey: Curve25519PublicKey
        let remotePQKEMPublicKey: Kyber1024.KeyAgreement.PublicKey
        let localPrivateLongTermKey: Curve25519PrivateKey
        let localPrivateOneTimeKey: Curve25519PrivateKey
        let localPQKEMPrivateKey: Kyber1024.KeyAgreement.PrivateKey
    }
    
    var sessionIdentity: SessionIdentity?
    var sessionSymmetricKey: SymmetricKey?
    
    // Load cached device identities
    private func loadDeviceIdentities(
        sessionIdentity: SessionIdentity,
        sessionSymmetricKey: SymmetricKey,
        messageType: MessageType
    ) async throws {
        if sessionIdentity.id != self.sessionIdentity?.id {
            self.sessionIdentity = sessionIdentity
            self.sessionSymmetricKey = sessionSymmetricKey
        }
        guard var props = await self.sessionIdentity?.props(symmetricKey: sessionSymmetricKey) else {
            throw RatchetError.missingDeviceIdentity
        }
        
        if let state = props.state {
            // Update the state based on the message type
            self.privateState = await updateState(state, for: messageType)
        } else {
            // Create a new state if none exists
            privateState = try await createNewState(for: messageType)
            props.state = privateState
            _ = try await sessionIdentity.updateProps(symmetricKey: sessionSymmetricKey, props: props)
        }
    }
    
    private func updateSessionIdentity(
        sessionIdentity: SessionIdentity,
        sessionSymmetricKey: SymmetricKey
    ) async throws {
        guard var props = await sessionIdentity.props(symmetricKey: sessionSymmetricKey) else {
            throw RatchetError.missingDeviceIdentity
        }
        
        props.state = privateState
        self.sessionIdentity = try await sessionIdentity.updateIdentityProps(symmetricKey: sessionSymmetricKey, props: props)
    }

    
    // Helper method to update the state based on the message type
    private func updateState(_
                             state: RatchetState,
                             for messageType: MessageType,
    ) async -> RatchetState {
        var updatedState = state
        switch messageType {
        case .receiving(let recipientKeys):
            await updatedState.updateLocalPrivateLongTermKey(recipientKeys.localPrivateLongTermKey.rawRepresentation)
            await updatedState.updateLocalPrivateOneTimeKey(recipientKeys.localPrivateOneTimeKey.rawRepresentation)
            await updatedState.updateLocalPQKEMPrivateKey(recipientKeys.localPQKEMPrivateKey)
            await updatedState.updateRemotePublicLongTermKey(recipientKeys.remotePublicLongTermKey.rawRepresentation)
            await updatedState.updateRemotePublicOneTimeKey(recipientKeys.remotePublicOneTimeKey.rawRepresentation)
            await updatedState.updateRemotePQKEMPublicKey(recipientKeys.remotePQKEMPublicKey)
        case .sending(let senderKeys):
            await updatedState.updateLocalPrivateLongTermKey(senderKeys.localPrivateLongTermKey.rawRepresentation)
            await updatedState.updateLocalPrivateOneTimeKey(senderKeys.localPrivateOneTimeKey.rawRepresentation)
            await updatedState.updateLocalPQKEMPrivateKey(senderKeys.localPQKEMPrivateKey)
            await updatedState.updateRemotePublicLongTermKey(senderKeys.remotePublicLongTermKey.rawRepresentation)
            await updatedState.updateRemotePublicOneTimeKey(senderKeys.remotePublicOneTimeKey.rawRepresentation)
            await updatedState.updateRemotePQKEMPublicKey(senderKeys.remotePQKEMPublicKey)
        }
        return updatedState
    }
    
    // Helper method to create a new state based on the message type
    private func createNewState(for messageType: MessageType) async throws -> RatchetState {
        switch messageType {
        case .receiving(let recipientKeys):
            let cipher = try await derivePQXDHFinalKey(
                localPrivateLongTermKey: recipientKeys.localPrivateLongTermKey.rawRepresentation,
                remotePublicLongTermKey: recipientKeys.remotePublicLongTermKey.rawRepresentation,
                localPrivateOneTimeKey: recipientKeys.localPrivateOneTimeKey.rawRepresentation,
                remotePublicOneTimeKey: recipientKeys.remotePublicOneTimeKey.rawRepresentation,
                remoteKyber1024PublicKey: recipientKeys.remotePQKEMPublicKey)
            return await RatchetState(
                remotePublicLongTermKey: recipientKeys.remotePublicLongTermKey.rawRepresentation,
                remotePublicOneTimeKey: recipientKeys.remotePublicOneTimeKey.rawRepresentation,
                remotePQKEMPublicKey: recipientKeys.remotePQKEMPublicKey,
                localPrivateLongTermKey: recipientKeys.localPrivateLongTermKey.rawRepresentation,
                localPrivateOneTimeKey: recipientKeys.localPrivateOneTimeKey.rawRepresentation,
                localPQKEMPrivateKey: recipientKeys.localPQKEMPrivateKey,
                rootKey: cipher.symmetricKey,
                messageCiphertext: cipher.ciphertext,
                receivingKey: try deriveChainKey(from: cipher.symmetricKey, configuration: defaultRatchetConfiguration))
            
        case .sending(let senderKeys):
            let (sendingKey, cipher) = try await deriveNextMessageKey(
                localPrivateLongTermKey: senderKeys.localPrivateLongTermKey.rawRepresentation,
                remotePublicLongTermKey: senderKeys.remotePublicLongTermKey.rawRepresentation,
                localPrivateOneTimeKey: senderKeys.localPrivateOneTimeKey.rawRepresentation,
                remotePublicOneTimeKey: senderKeys.remotePublicOneTimeKey.rawRepresentation,
                remoteKyber1024PublicKey: senderKeys.remotePQKEMPublicKey)
            return RatchetState(
                remotePublicLongTermKey: senderKeys.remotePublicLongTermKey.rawRepresentation,
                remotePublicOneTimeKey: senderKeys.remotePublicOneTimeKey.rawRepresentation,
                remotePQKEMPublicKey: senderKeys.remotePQKEMPublicKey,
                localPrivateLongTermKey: senderKeys.localPrivateLongTermKey.rawRepresentation,
                localPrivateOneTimeKey: senderKeys.localPrivateOneTimeKey.rawRepresentation,
                localPQKEMPrivateKey: senderKeys.localPQKEMPrivateKey,
                rootKey: cipher.symmetricKey,
                messageCiphertext: cipher.ciphertext,
                sendingKey: sendingKey)
        }
    }
    
    
    /// This function initializes a sender's session for double ratchet encryption.
    /// It sets up the necessary state for the sender to encrypt messages using
    /// the double ratchet algorithm.
    ///
    /// - Parameters:
    ///   - deviceId: An instance of `SessionIdentityModel` that represents
    ///     the identity of the device for which the session is being initialized.
    ///   - secretKey: A `SymmetricKey` used for encryption and decryption processes.
    ///   - localPrivateKey: A `Curve25519PrivateKey` representing the local private key
    ///     for the Curve25519 elliptic curve, which is used in the double ratchet protocol.
    ///
    /// - Throws: This function can throw errors related to loading device identities,
    ///   which should be handled by the caller.
    ///
    /// - Important:
    ///   1. We need to first initialize a Ratchet Session.
    ///   2. Then we can call `ratchetEncrypt()`.
    ///   3. We must make sure each time we want to use the ratchet, we are in the proper state.
    public func senderInitialization(
        sessionIdentity: SessionIdentity,
        sessionSymmetricKey: SymmetricKey,
        remotePublicLongTermKey: Curve25519PublicKey,
        remotePublicOneTimeKey: Curve25519PublicKey,
        remotePQKEMPublicKey: Kyber1024.KeyAgreement.PublicKey,
        localPrivateLongTermKey: Curve25519PrivateKey,
        localPrivateOneTimeKey: Curve25519PrivateKey,
        localPQDHPrivateKey: Kyber1024.KeyAgreement.PrivateKey
    ) async throws {
        try await loadDeviceIdentities(
            sessionIdentity: sessionIdentity,
            sessionSymmetricKey: sessionSymmetricKey,
            messageType: .sending(
                EncryptionKeys(
                    remotePublicLongTermKey: remotePublicLongTermKey,
                    remotePublicOneTimeKey: remotePublicOneTimeKey,
                    remotePQKEMPublicKey: remotePQKEMPublicKey,
                    localPrivateLongTermKey: localPrivateLongTermKey,
                    localPrivateOneTimeKey: localPrivateOneTimeKey,
                    localPQKEMPrivateKey: localPQDHPrivateKey)))
    }
    
    /// This function initializes a recipient's session for double ratchet encryption.
    /// It sets up the necessary state for the recipient to decrypt incoming messages
    /// using the double ratchet algorithm.
    ///
    /// - Parameters:
    ///   - deviceId: An instance of `SessionIdentityModel` that represents
    ///     the identity of the device for which the session is being initialized.
    ///   - secretKey: A `SymmetricKey` used for encryption and decryption processes.
    ///   - localPrivateKey: A `Curve25519PrivateKey` representing the local private key
    ///     for the Curve25519 elliptic curve, which is used in the double ratchet protocol.
    ///   - initialMessage: An `RatchetMessage` that contains the first message to be
    ///     decrypted as part of the session initialization.
    ///
    /// - Returns: A `Data` object that represents the decrypted content of the
    ///   `initialMessage`. We must decode and verify this message before we save to the database and forward the message to the client
    ///
    /// - Throws: This function can throw errors related to loading device identities
    ///   or decrypting the initial message, which should be handled by the caller.
    ///
    /// - Important:
    ///   1. Before calling this function, ensure that the double ratchet session
    ///      is properly initialized and that the device identity is valid.
    ///   2. Each time the ratchet is used, the proper state must be maintained
    ///      to ensure secure encryption and decryption.
    public func recipientInitialization(
        sessionIdentity: SessionIdentity,
        sessionSymmetricKey: SymmetricKey,
        remotePublicLongTermKey: Curve25519PublicKey,
        remotePublicOneTimeKey: Curve25519PublicKey,
        remotePQKEMPublicKey: Kyber1024.KeyAgreement.PublicKey,
        localPrivateLongTermKey: Curve25519PrivateKey,
        localPrivateOneTimeKey: Curve25519PrivateKey,
        localPQKEMPrivateKey: Kyber1024.KeyAgreement.PrivateKey,
        initialMessage: RatchetMessage
    ) async throws -> Data {
        let keys = EncryptionKeys(
            remotePublicLongTermKey: remotePublicLongTermKey,
            remotePublicOneTimeKey: remotePublicOneTimeKey,
            remotePQKEMPublicKey: remotePQKEMPublicKey,
            localPrivateLongTermKey: localPrivateLongTermKey,
            localPrivateOneTimeKey: localPrivateOneTimeKey,
            localPQKEMPrivateKey: localPQKEMPrivateKey)
        try await loadDeviceIdentities(
            sessionIdentity: sessionIdentity,
            sessionSymmetricKey: sessionSymmetricKey,
            messageType: .receiving(keys))
        return try await ratchetDecrypt(initialMessage)
    }
    
    struct DiffieHellmanKeyPair: Sendable {
        let privateKey: Curve25519PrivateKey
        let publicKey: Curve25519PublicKey
    }
    
    /// Generates a new Diffie-Hellman key pair.
    func generateDHKeyPair() async -> DiffieHellmanKeyPair {
        let privateKey = crypto.generateCurve25519PrivateKey()
        return DiffieHellmanKeyPair(privateKey: privateKey, publicKey: privateKey.publicKey)
    }
    
    /// Derives a root key using HKDF.
    func deriveHKDFSymmetricKey(
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
    
    private func updateState(to newState: RatchetState) async -> RatchetState {
        self.privateState = newState
        try! await updateSessionIdentity(sessionIdentity: self.sessionIdentity!, sessionSymmetricKey: self.sessionSymmetricKey!)
        return self.privateState ?? newState // Return the new state, ensuring safety
    }
    
    /// Encrypts plaintext data and returns a RatchetMessage.
    public func ratchetEncrypt(plainText: Data) async throws -> RatchetMessage {
        guard var state = await currentState else {
            throw RatchetError.stateUninitialized
        }
        guard let sendingKey = state.sendingKey else { throw RatchetError.sendingKeyIsNil }

        let messageHeader = MessageHeader(
            previousChainLength: state.previousMessagesCount,
            messageNumber: state.sentMessagesCount)
        let headerCipher = try await derivePQXDHFinalKey(
            localPrivateLongTermKey: state.localPrivateLongTermKey,
            remotePublicLongTermKey: state.remotePublicLongTermKey!,
            localPrivateOneTimeKey: state.localPrivateOneTimeKey,
            remotePublicOneTimeKey: state.remotePublicOneTimeKey!,
            remoteKyber1024PublicKey: state.remotePQKEMPublicKey)
        
        await state.updateHeaderCiphertext(headerCipher.ciphertext)
        await state.updateSendingHeaderKey(headerCipher.symmetricKey)
        
        // Step 3. Derive and store the NEXT sending header key for future ratchet transitions.
        let nextSendingHeaderKey = try await derivePQXDHFinalKey(
            localPrivateLongTermKey: state.localPrivateLongTermKey,
            remotePublicLongTermKey: state.remotePublicLongTermKey!,
            localPrivateOneTimeKey: state.localPrivateOneTimeKey,
            remotePublicOneTimeKey: state.remotePublicOneTimeKey!,
            remoteKyber1024PublicKey: state.remotePQKEMPublicKey)
        
        await state.updateSendingNextHeaderKey(nextSendingHeaderKey.symmetricKey)
        state = await updateState(to: state)
        
        let localPublicLongTermKey = try Curve25519PrivateKey(rawRepresentation: state.localPrivateLongTermKey).publicKey.rawRepresentation
        let localPublicOneTimeKey = try Curve25519PrivateKey(rawRepresentation: state.localPrivateOneTimeKey).publicKey.rawRepresentation
        
        let encryptedHeader = try await encryptHeader(
            messageHeader,
            remotePublicLongTermKey: localPublicLongTermKey,
            remotePublicOneTimeKey: localPublicOneTimeKey,
            remoteKyber1024PublicKey: state.localPQKEMPrivateKey.publicKey)
        
        guard let encryptedData = try crypto.encrypt(
            data: plainText,
            symmetricKey: sendingKey
        ) else { throw RatchetError.encryptionFailed }

                let (newSendingKey, _) = try await deriveNextMessageKey(
                    localPrivateLongTermKey: state.localPrivateLongTermKey,
                    remotePublicLongTermKey: state.remotePublicLongTermKey!,
                    localPrivateOneTimeKey: state.localPrivateOneTimeKey,
                    remotePublicOneTimeKey: state.remotePublicOneTimeKey!,
                    remoteKyber1024PublicKey: state.remotePQKEMPublicKey)
                
        
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
        
        guard var state = await currentState else {
            throw RatchetError.stateUninitialized
        }
        
        await state.updateSendingKey(newSendingKey)
        await state.incrementSentMessagesCount()
        state = await updateState(to: state)
        return RatchetMessage(header: encryptedHeader, encryptedData: encryptedData)
    }
    
    /// Runs PQXDH, then HKDF chain-key, then HMAC ratchet to get the next message key.
        /// Returns both the raw PQXDH ciphertext (for header rotation) and the new message key.
    private func deriveNextMessageKey(localPrivateLongTermKey: Data,
                                      remotePublicLongTermKey: Data,
                                      localPrivateOneTimeKey: Data,
                                      remotePublicOneTimeKey: Data,
                                      remoteKyber1024PublicKey: Kyber1024.KeyAgreement.PublicKey) async throws -> (SymmetricKey, PQXDHCipher) {
       
        // 1) PQXDH encaps
        let cipher = try await derivePQXDHFinalKey(
            localPrivateLongTermKey: localPrivateLongTermKey,
            remotePublicLongTermKey: remotePublicLongTermKey,
            localPrivateOneTimeKey: localPrivateOneTimeKey,
            remotePublicOneTimeKey: remotePublicOneTimeKey,
            remoteKyber1024PublicKey: remoteKyber1024PublicKey)
        
        // 2) HKDF chain key from PQXDH shared secret
        let ck = try await deriveChainKey(
            from: cipher.symmetricKey,
            configuration: defaultRatchetConfiguration
        )
        
        if var state = await currentState {
            await state.updateRootKey(cipher.symmetricKey)
            await state.updateCiphertext(cipher.ciphertext)
            self.privateState = await updateState(to: state)
        }
        
        // 3) HMAC ratchet to get the per-message key
        return (try await symmetricKeyRatchet(from: ck), cipher)
    }
    
    enum KeyChangeType {
        case none
        case longTermKeyChanged
        case oneTimeKeyChanged
    }

    public func ratchetDecrypt(_ message: RatchetMessage) async throws -> Data {
        guard var state = await currentState else {
            throw RatchetError.missingDeviceIdentity
        }

        let finalHeaderReceivingKey = try await derivePQXDHFinalKeyReceiver(
            remotePublicLongTermKey: message.header.remotePublicLongTermKey,
            remotePublicOneTimeKey: message.header.remotePublicOneTimeKey,
            localPrivateLongTermKey: state.localPrivateLongTermKey,
            localPrivateOneTimeKey: state.localPrivateOneTimeKey,
            localKyberPrivateKey: state.localPQKEMPrivateKey,
            receivedCiphertext: message.header.headerCiphertext)
        
        await state.updateReceivingHeaderKey(finalHeaderReceivingKey)
        state = await updateState(to: state)
        
        let header = try await decryptHeader(message.header)
        
        // Check if this header was encrypted using a next header key.
        // (Assume that your header structure or protocol indicates if the header was encrypted
        // with the "next" key, for example via a flag or by comparing with the current stored key.)
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
            // The protocol dictates that successful decryption with the NEXT header key triggers a Diffie–Hellman ratchet.
            // Shift the next header key into the current header key slot.
            if let nextReceivingHeaderKey = state.nextReceivingHeaderKey {
                await state.updateReceivingHeaderKey(nextReceivingHeaderKey)
            } else {
                throw RatchetError.missingNextHeaderKey
            }
            // After the shift, derive a new next receiving header key.
            let newNextReceivingHeaderKey = try await derivePQXDHFinalKey(
                localPrivateLongTermKey: state.localPrivateLongTermKey,
                remotePublicLongTermKey: state.remotePublicLongTermKey!,
                localPrivateOneTimeKey: state.localPrivateOneTimeKey,
                remotePublicOneTimeKey: state.remotePublicOneTimeKey!,
                remoteKyber1024PublicKey: state.remotePQKEMPublicKey)
            await state.updateReceivingNextHeaderKey(newNextReceivingHeaderKey.symmetricKey)
            // Additionally, perform a DH ratchet step.
            state = try await diffieHellmanRatchet(header: header)
        case .none:
            // After the shift, derive a new next receiving header k
            // Even if no ratchet is triggered, you may want to update the next receiving header key.
            // This ensures that if a future header is marked as a ratchet trigger,
            // you have a "next" key available.
            let newNextReceivingHeaderKey = try await derivePQXDHFinalKey(
                localPrivateLongTermKey: state.localPrivateLongTermKey,
                remotePublicLongTermKey: state.remotePublicLongTermKey!,
                localPrivateOneTimeKey: state.localPrivateOneTimeKey,
                remotePublicOneTimeKey: state.remotePublicOneTimeKey!,
                remoteKyber1024PublicKey: state.remotePQKEMPublicKey)
            await state.updateReceivingNextHeaderKey(newNextReceivingHeaderKey.symmetricKey)
        }
        
        guard let decrypted = header.decrypted else {
            throw RatchetError.headerDecryptFailed
        }

        // Process a message if it was skipped first.
        let (foundMessage, _state) = try await checkForSkippedMessages(
            message,
            header: decrypted,
            skippedMessageKeys: state.skippedMessageKeys)
        state = await updateState(to: _state)
        
        if let foundMessage = foundMessage {
            return try await processFoundMessage(decodedMessage: foundMessage)
        }
        
        // Check if the message key is valid.
        if message.header.remotePublicLongTermKey != state.remotePublicLongTermKey && message.header.remotePublicOneTimeKey != state.remotePublicOneTimeKey {
            // Process out-of-date (skipped) message.
            guard let configuration = await configuration else { throw RatchetError.missingConfiguration }
            state = try await trySkipMessageKeys(
                header: header,
                configuration: configuration)
            
            // Update the local list of skipped message keys.
            await state.updateSkippedMessages(with: state.skippedMessageKeys)
            state = await updateState(to: state)
            
            // Ratchet on decryption.
            state = try await diffieHellmanRatchet(header: header)
        } else if decrypted.messageNumber < state.receivedMessagesCount {
            throw RatchetError.expiredKey
        }
        guard let configuration = await configuration else { throw RatchetError.missingConfiguration }
        state = try await trySkipMessageKeys(
            header: header,
            configuration: configuration)
        
        // Update the local list of skipped message keys.
        await state.updateSkippedMessages(with: state.skippedMessageKeys)
        state = await updateState(to: state)
        
        let finalReceivingKey = try await derivePQXDHFinalKeyReceiver(
            remotePublicLongTermKey: message.header.remotePublicLongTermKey,
            remotePublicOneTimeKey: message.header.remotePublicOneTimeKey,
            localPrivateLongTermKey: state.localPrivateLongTermKey,
            localPrivateOneTimeKey: state.localPrivateOneTimeKey,
            localKyberPrivateKey: state.localPQKEMPrivateKey,
            receivedCiphertext: message.header.messageCiphertext)
        
        await state.updateRemotePublicLongTermKey(message.header.remotePublicLongTermKey)
        await state.updateRemotePublicOneTimeKey(message.header.remotePublicOneTimeKey)
        
        state = await updateState(to: state)
       
        let newReceivingKey = try await deriveChainKey(from: finalReceivingKey, configuration: configuration)
        let messageKey = try await symmetricKeyRatchet(from: newReceivingKey)
        await state.updateReceivingKey(messageKey)
        
        // Similarly, derive a new next receiving header key based on the new receiving header key,
        // if you want to be conservative about future ratchets.
        let newNextReceivingHeaderKey = try await derivePQXDHFinalKey(
            localPrivateLongTermKey: state.localPrivateLongTermKey,
            remotePublicLongTermKey: state.remotePublicLongTermKey!,
            localPrivateOneTimeKey: state.localPrivateOneTimeKey,
            remotePublicOneTimeKey: state.remotePublicOneTimeKey!,
            remoteKyber1024PublicKey: state.remotePQKEMPublicKey)
        await state.updateReceivingNextHeaderKey(newNextReceivingHeaderKey.symmetricKey)
        
        state = await updateState(to: state)
        
        await state.incrementReceivedMessagesCount()
        state = await updateState(to: state)
        
        return try await processFoundMessage(
            decodedMessage: DecodedMessage(
                ratchetMessage: message,
                messageKey: messageKey))
    }
    
    /// Attempts to skip message keys based on the received message.
    /// - Parameter message: The encrypted message to process.
    /// - Throws: An error if the device identity is missing or if key derivation fails.
    private func trySkipMessageKeys(
        header: EncryptedHeader,
        configuration: RatchetConfiguration
    ) async throws -> RatchetState {
        guard var state = await currentState else {
            throw RatchetError.stateUninitialized
        }
        guard let receivingKey = state.receivingKey else {
            return state
        }
        guard let decryptedHeader = header.decrypted else {
            throw RatchetError.decryptionFailed
        }
        
        // Process until the received messages count is less than the previous chain length
        while state.receivedMessagesCount < decryptedHeader.previousChainLength {
            // Derive the message key and new receiving key
            let messageKey = try await symmetricKeyRatchet(from: receivingKey)
            let newReceivingKey = try await deriveChainKey(from: receivingKey, configuration: configuration)
            
            await state.updateReceivingKey(newReceivingKey)
            state = await updateState(to: state)
            
            // Append the new skipped message key directly to the state
            await state.updateSkippedMessages(skippedMessageKeys: SkippedMessageKey(
                senderPublicLongTermKey: header.remotePublicLongTermKey,
                senderPublicOneTimeKey: header.remotePublicOneTimeKey,
                messageIndex: state.receivedMessagesCount,
                messageKey: messageKey
            ))
            state = await updateState(to: state)
            
            // Ensure the skipped keys do not exceed the maximum allowed
            if state.skippedMessageKeys.count > configuration.maxSkippedMessageKeys {
                await state.removeFirstSkippedMessages()
                state = await updateState(to: state)
            }
            
            // Increment the received messages count
            await state.incrementReceivedMessagesCount()
            state = await updateState(to: state)
        }
        return state
    }
    
    /// Processes a found message and returns the decrypted data.
    func processFoundMessage(decodedMessage: DecodedMessage) async throws -> Data {
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
    
    struct DecodedMessage: Sendable {
        let ratchetMessage: RatchetMessage
        let messageKey: SymmetricKey
    }
    
    func checkForSkippedMessages(
        _ message: RatchetMessage,
        header: MessageHeader,
        skippedMessageKeys: [SkippedMessageKey]
    ) async throws -> (DecodedMessage?, RatchetState) {
        guard var state = await currentState else {
            throw RatchetError.stateUninitialized
        }
        
        for skippedMessageKey in skippedMessageKeys {
            if skippedMessageKey.messageIndex == header.messageNumber,
               message.header.remotePublicLongTermKey == skippedMessageKey.senderPublicLongTermKey && message.header.remotePublicOneTimeKey == skippedMessageKey.senderPublicOneTimeKey {
                
                // Modify the skippedMessageKeys
                await state.removeSkippedMessages(at: skippedMessageKey.messageIndex)
                state = await updateState(to: state)
                
                let finalReceivingKey = try await derivePQXDHFinalKeyReceiver(
                    remotePublicLongTermKey: message.header.remotePublicLongTermKey,
                    remotePublicOneTimeKey: message.header.remotePublicOneTimeKey,
                    localPrivateLongTermKey: state.localPrivateLongTermKey,
                    localPrivateOneTimeKey: state.localPrivateOneTimeKey,
                    localKyberPrivateKey: state.localPQKEMPrivateKey,
                    receivedCiphertext:  message.header.messageCiphertext)
                
                await state.updateReceivingKey(finalReceivingKey)
                await state.updateRemotePublicLongTermKey(message.header.remotePublicLongTermKey)
                await state.updateRemotePublicOneTimeKey(message.header.remotePublicOneTimeKey)
                
                state = await updateState(to: state)
                
                let messageKey = try await symmetricKeyRatchet(from: finalReceivingKey)
                
                return (DecodedMessage(
                    ratchetMessage: message,
                    messageKey: messageKey
                ), state)
            }
        }
        return (nil, state)
    }
    
    /// Applies a symmetric-key ratchet step to derive a new message key.
    func symmetricKeyRatchet(from symmetricKey: SymmetricKey) async throws -> SymmetricKey {
        guard let configuration = await configuration else { throw RatchetError.missingConfiguration }
        let chainKey = HMAC<SHA256>.authenticationCode(for: configuration.messageKeyData, using: symmetricKey)
        return SymmetricKey(data: chainKey)
    }
    
    /// Derives a new chain key from the given symmetric key.
    func deriveChainKey(
        from symmetricKey: SymmetricKey,
        configuration: RatchetConfiguration
    ) async throws -> SymmetricKey {
        let chainKey = HMAC<SHA256>.authenticationCode(for: configuration.chainKeyData, using: symmetricKey)
        return SymmetricKey(data: chainKey)
    }
    
    
    /// Concatenates associated data and message header to create a nonce.
    func concatenate(
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
    
    /// Performs a Diffie-Hellman ratchet step when a new public key is received.
    private func diffieHellmanRatchet(header: EncryptedHeader) async throws -> RatchetState {
        guard var state = await currentState else {
            throw RatchetError.stateUninitialized
        }
        
        // Update message counts and remote public key
        await state.updatePreviousMessagesCount(state.sentMessagesCount)
        await state.updateSentMessagesCount(0)
        await state.updateReceivedMessagesCount(0)
        await state.updateRemotePublicLongTermKey(header.remotePublicLongTermKey)
        await state.updateRemotePublicOneTimeKey(header.remotePublicOneTimeKey)
        state = await updateState(to: state)
        
        
        let (newReceivingKey, _) = try await deriveNextMessageKey(
            localPrivateLongTermKey: state.localPrivateLongTermKey,
            remotePublicLongTermKey: header.remotePublicLongTermKey,
            localPrivateOneTimeKey: state.localPrivateOneTimeKey,
            remotePublicOneTimeKey: header.remotePublicOneTimeKey,
            remoteKyber1024PublicKey: header.remoteKyber1024PublicKey)
        await state.updateReceivingKey(newReceivingKey)
        state = await updateState(to: state)
        
        
        /// These next steps are purposed to derive a new Sending Key
        // Generate new local private key
        let newLocalPrivateKey = crypto.generateCurve25519PrivateKey().rawRepresentation
        await state.updateLocalPrivateOneTimeKey(newLocalPrivateKey)
        state = await updateState(to: state)

        let (newSendingKey, _) = try await deriveNextMessageKey(
            localPrivateLongTermKey: state.localPrivateLongTermKey,
            remotePublicLongTermKey: header.remotePublicLongTermKey,
            localPrivateOneTimeKey: state.localPrivateOneTimeKey,
            remotePublicOneTimeKey: header.remotePublicOneTimeKey,
            remoteKyber1024PublicKey: header.remoteKyber1024PublicKey)
        await state.updateSendingKey(newSendingKey)
        state = await updateState(to: state)
        
        return state
    }
    
    // Helper method to derive shared secret
    private func deriveSharedSecret(
        localPrivateKeyData: Data,
        senderPublicKeyData: Data
    ) async throws -> SharedSecret {
        let localPrivateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: localPrivateKeyData)
        let senderPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: senderPublicKeyData)
        return try localPrivateKey.sharedSecretFromKeyAgreement(with: senderPublicKey)
    }
    
    struct PQXDHCipher: Sendable {
        let ciphertext: Data
        let symmetricKey: SymmetricKey
    }
    
    func derivePQXDHFinalKey(
        localPrivateLongTermKey: Data,
        remotePublicLongTermKey: Data,
        localPrivateOneTimeKey: Data,
        remotePublicOneTimeKey: Data,
        remoteKyber1024PublicKey: Kyber1024.KeyAgreement.PublicKey
    ) async throws -> PQXDHCipher {
        
        let K_A = try await deriveSharedSecret(localPrivateKeyData: localPrivateLongTermKey, senderPublicKeyData: remotePublicLongTermKey)
        let K_A_ot = try await deriveSharedSecret(localPrivateKeyData: localPrivateOneTimeKey, senderPublicKeyData: remotePublicOneTimeKey)
        
        let K_A_data = K_A.withUnsafeBytes { Data($0) }
        let K_A_ot_data = K_A_ot.withUnsafeBytes { Data($0) }

        // Encapsulate Kyber
        let (ciphertext, sharedSecret) = try remoteKyber1024PublicKey.encapsulate()

        // Concatenate X3DH secrets
        let concatenatedSecrets = K_A_data + K_A_ot_data + sharedSecret.bytes

        let symmetricKey = HKDF<SHA512>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: concatenatedSecrets),
            salt: remotePublicOneTimeKey,
            outputByteCount: 32)
        
        return PQXDHCipher(ciphertext: ciphertext, symmetricKey: symmetricKey)
    }
    
//    3. Kyber Decapsulation Error Handling
//    Right now, if decapsulation (derivePQXDHFinalKeyReceiver) fails (e.g., ciphertext invalid), you'll just throw an error.
//    That's good — but some ratchets (like Signal) treat "can't decapsulate" as "maybe a skipped message" and try skipping before throwing.
//
//    🔵 You could in the future improve UX by catching decapsulation failure and trying skipped keys automatically — but it's optional and out of scope for now.
//    You can always do that later if needed.
    func derivePQXDHFinalKeyReceiver(
        remotePublicLongTermKey: Data,
        remotePublicOneTimeKey: Data,
        localPrivateLongTermKey: Data,
        localPrivateOneTimeKey: Data,
        localKyberPrivateKey: Kyber1024.KeyAgreement.PrivateKey,
        receivedCiphertext: Data
    ) async throws -> SymmetricKey {

        // Step 1: Derive X3DH shared secrets
        let K_B = try await deriveSharedSecret(localPrivateKeyData: localPrivateLongTermKey, senderPublicKeyData: remotePublicLongTermKey)
        let K_B_ot = try await deriveSharedSecret(localPrivateKeyData: localPrivateOneTimeKey, senderPublicKeyData: remotePublicOneTimeKey)
        
        let K_B_data = K_B.withUnsafeBytes { Data($0) }
        let K_B_ot_data = K_B_ot.withUnsafeBytes { Data($0) }
        
        // Step 2: Decapsulate Kyber ciphertext using private key
        let sharedSecret = try localKyberPrivateKey.sharedSecret(from: receivedCiphertext)
        // Step 3: Concatenate all secrets
        let concatenatedSecrets = K_B_data + K_B_ot_data + sharedSecret.bytes
        
        let salt = try Curve25519PrivateKey(rawRepresentation: localPrivateOneTimeKey).publicKey.rawRepresentation
        let symmetricKey = HKDF<SHA512>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: concatenatedSecrets),
            salt: salt,
            outputByteCount: 32)
        
        return symmetricKey
    }
}

extension RatchetStateManager {
    /// Encrypts a clear header under the *current* sending header key HKs.
    /// - Precondition: `state.HKs` is non-nil.
    func encryptHeader(_
                       header: MessageHeader,
                       remotePublicLongTermKey: Data,
                       remotePublicOneTimeKey: Data,
                       remoteKyber1024PublicKey: Kyber1024.KeyAgreement.PublicKey
    ) async throws -> EncryptedHeader {
        guard let currentState = await currentState else {
            throw RatchetError.stateUninitialized
        }
        guard let sendingHeaderKey = currentState.sendingHeaderKey else {
            throw RatchetError.headerKeysNil
        }
        
        guard let headerCiphertext = currentState.headerCiphertext else {
            throw RatchetError.missingCipherText
        }
        
        guard let messageCiphertext = currentState.messageCiphertext else {
            throw RatchetError.missingCipherText
        }
        
        // 1. Serialize the clear header
        let headerPlain = try BSONEncoder().encodeData(header)
        
        // 2. Build a nonce: e.g. 96-bit counter from Ns
        let counter = currentState.sentMessagesCount  // or separate headerCounter
        var ctrBytes = withUnsafeBytes(of: UInt64(counter).bigEndian) { Data($0) }
        // pad to 12 bytes:
        ctrBytes.append(contentsOf: [UInt8](repeating: 0, count: 12 - ctrBytes.count))
        
        
        let nonce = try AES.GCM.Nonce(data: ctrBytes)
        
        guard let encrypted = try crypto.encrypt(
            data: headerPlain,
            symmetricKey: sendingHeaderKey,
            nonce: nonce) else {
            throw RatchetError.headerEncryptionFailed
        }

        // 4. Rotate header keys?  In HE variant, you only rotate on DH ratchet.
        //    So do *not* touch HKs/NHKs here.
        return EncryptedHeader(
            remotePublicLongTermKey: remotePublicLongTermKey,
            remotePublicOneTimeKey: remotePublicOneTimeKey,
            remoteKyber1024PublicKey: remoteKyber1024PublicKey,
            headerCiphertext: headerCiphertext,
            messageCiphertext: messageCiphertext,
            encrypted: encrypted)
    }
}

extension RatchetStateManager {
    /// Attempts to decrypt `encrypedHeader` under HKr, then under NHKr, then under skipped HKs.
    /// Returns the clear `MessageHeader` plus whether a DH ratchet step is needed.
    func decryptHeader(_ encryptedHeader: EncryptedHeader) async throws -> EncryptedHeader {
        guard var currentState = await currentState else {
            throw RatchetError.stateUninitialized
        }
        
        var encryptedHeader = encryptedHeader
        
        // 1) Try skipped keys first {
        for key in currentState.skippedMessageKeys {
            if let header = try crypto.decrypt(data: encryptedHeader.encrypted, symmetricKey: key.messageKey) {
                let header = try BSONDecoder().decodeData(MessageHeader.self, from: header)
                guard header.messageNumber == key.messageIndex else { continue }
                encryptedHeader.setDecrypted(header)
                return encryptedHeader
            }
        }
        
        // 2) Try current receiving header key
        if let messageKey = currentState.receivingHeaderKey {
            if let header = try crypto.decrypt(data: encryptedHeader.encrypted, symmetricKey: messageKey) {
                let header = try BSONDecoder().decodeData(MessageHeader.self, from: header)
                encryptedHeader.setDecrypted(header)
                return encryptedHeader
            }
        }
        
        // 3) Try next receiving header key → DH ratchet
        guard let nextMessageKey = currentState.nextReceivingHeaderKey else {
            throw RatchetError.headerDecryptFailed
        }
        await currentState.updateReceivingHeaderKey(nextMessageKey)
        currentState = await updateState(to: currentState)
        
        guard let headerData = try crypto.decrypt(data: encryptedHeader.encrypted, symmetricKey: nextMessageKey) else {
            throw RatchetError.headerDecryptFailed
        }
        let header = try BSONDecoder().decodeData(MessageHeader.self, from: headerData)
        encryptedHeader.setDecrypted(header)
        return encryptedHeader
    }
}

/// Extension to make SymmetricKey conform to Codable for easy encoding and decoding.
extension SymmetricKey: Codable {
    /// Encodes the SymmetricKey to the given encoder.
    /// - Parameter encoder: The encoder to write data to.
    public func encode(to encoder: Encoder) throws {
        let data = self.withUnsafeBytes { buffer in
            Data(buffer: buffer.bindMemory(to: UInt8.self))
        }
        try data.encode(to: encoder) // Encode the key data.
    }
    
    /// Initializes a SymmetricKey from the given decoder.
    /// - Parameter decoder: The decoder to read data from.
    public init(from decoder: Decoder) throws {
        let data = try Data(from: decoder) // Decode the key data.
        self.init(data: data) // Initialize the SymmetricKey with the decoded data.
    }
}

extension SharedSecret {
    public var bytes: Data {
        self.withUnsafeBytes { pointer in
            Data(pointer)
        }
    }
}
