//  DoubleRatchet.swift
//  needletail-crypto
//
//  Created by Cole M on 9/12/24.
//

@preconcurrency import Crypto
import Foundation
import BSON
import NeedleTailCrypto

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
    let publicKey: Data              // The public key of the sender associated with the skipped message.
    let messageIndex: Int            // The index of the skipped message.
    let messageKey: SymmetricKey     // The symmetric key used to encrypt the skipped message.
    
    private enum CodingKeys: String, CodingKey, Sendable {
        case publicKey = "a"
        case messageIndex = "b"
        case messageKey = "c"
    }
}

/// Represents an encrypted message along with its header in the Double Ratchet protocol.
public struct EncryptedMessage: Codable, Sendable {
    let header: MessageHeader        // The header containing metadata about the message.
    let encryptedData: Data          // The encrypted content of the message.
    
    private enum CodingKeys: String, CodingKey, Sendable {
        case header = "a"
        case encryptedData = "b"
    }
    
    /// Initializes a new EncryptedMessage with the specified header and encrypted data.
    /// - Parameters:
    ///   - header: The header of the encrypted message.
    ///   - encryptedData: The encrypted content of the message.
    public init(header: MessageHeader, encryptedData: Data) {
        self.header = header
        self.encryptedData = encryptedData
    }
}

/// Represents the header of a message in the Double Ratchet protocol.
public struct MessageHeader: Sendable, Codable {
    let senderPublicKey: Data        // The public key of the sender.
    let previousChainLength: Int      // The length of the previous message chain.
    let messageNumber: Int            // The sequence number of the message.
    
    private enum CodingKeys: String, CodingKey, Sendable {
        case senderPublicKey = "a"
        case previousChainLength = "b"
        case messageNumber = "c"
    }
    
    /// Initializes a new MessageHeader with the specified parameters.
    /// - Parameters:
    ///   - senderPublicKey: The public key of the sender.
    ///   - previousChainLength: The length of the previous message chain.
    ///   - messageNumber: The sequence number of the message.
    public init(senderPublicKey: Data, previousChainLength: Int, messageNumber: Int) {
        self.senderPublicKey = senderPublicKey
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
        case localPrivateKey = "a"
        case remotePublicKey = "s"
        case rootKey = "d"
        case sendingKey = "e"
        case receivingKey = "f"
        case sentMessagesCount = "g"
        case receivedMessagesCount = "h"
        case previousMessagesCount = "i"
        case skippedMessageKeys = "j"
    }
    
    // DHs - DH Ratchet key pair (the “sending” or “self” ratchet key)
    private(set) fileprivate var localPrivateKey: Data
    
    // DHr - DH Ratchet public key (the “received” or “remote” key)
    private(set) fileprivate var remotePublicKey: Data?
    
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
    
    init(
        localPrivateKey: Data,
        rootKey: SymmetricKey
    ) {
        self.localPrivateKey = localPrivateKey
        self.rootKey = rootKey
    }
    
    init(
        remotePublicKey: Data,
        localPrivateKey: Curve25519PrivateKey,
        rootKey: SymmetricKey,
        sendingKey: SymmetricKey
    ) {
        self.remotePublicKey = remotePublicKey
        self.rootKey = rootKey
        self.localPrivateKey = localPrivateKey.rawRepresentation
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
    
    mutating func updateRemotePublicKey(_ remotePublicKey: Data) async {
        self.remotePublicKey = remotePublicKey
    }
    
    mutating func updateSendingKey(_ sendingKey: SymmetricKey) async {
        self.sendingKey = sendingKey
    }
    
    mutating func updateReceivingKey(_ receivingKey: SymmetricKey) async {
        self.receivingKey = receivingKey
    }
    
    mutating func updateLocalPrivateKey(_ localPrivateKey: Data) async {
        self.localPrivateKey = localPrivateKey
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
    
}

private enum RatchetError: Error {
    case missingConfiguration, missingDeviceIdentity, sendingKeyIsNil, headerDataIsNil, invalidNonceLength, encryptionFailed, decryptionFailed, expiredKey, receivingKeyIsNil, stateUninitialized
}

/// Manages the state of the Double Ratchet protocol for encryption sessions. We must inject the DoubleRatchet object into the manager for state management of this devices cryptographic payload. We do that via `loadDeviceIdentities()` where the **DoubleRatchet** on that model is maped into our initialization. Each time we initalize a **DoubleRatchet** via the sender or recipient we get the cached object. Therefor we must make sure that the cache is alway up to date.
public actor RatchetStateManager<Hash: HashFunction & Sendable> {
    // Static shared instance of the actor.
    public static var shared: RatchetStateManager<Hash> {
        return RatchetStateManager<Hash>()
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
        case sending(Curve25519PublicKey), receiving(Curve25519PrivateKey)
    }
    
    // Load cached device identities (to be implemented).
    private func loadDeviceIdentities(
        deviceId: SessionIdentity,
        sessionSymmetricKey: SymmetricKey,
        secretKey: SymmetricKey,
        messageType: MessageType
    ) async throws {
        guard let props = await deviceId.props(symmetricKey: sessionSymmetricKey) else {
            fatalError("Device identity properties are missing.")
        }
        
        if let state = props.state {
            // Update the state based on the message type
            self.privateState = await updateState(state, for: messageType)
        } else {
            // Create a new state if none exists
            privateState = try await createNewState(for: messageType, using: secretKey)
        }
    }
    
    // Helper method to update the state based on the message type
    private func updateState(_ state: RatchetState, for messageType: MessageType) async -> RatchetState {
        var updatedState = state
        switch messageType {
        case .receiving(let localPrivateKey):
            await updatedState.updateLocalPrivateKey(localPrivateKey.rawRepresentation)
        case .sending(let localPublicKey):
            await updatedState.updateRemotePublicKey(localPublicKey.rawRepresentation)
        }
        return updatedState
    }
    
    // Helper method to create a new state based on the message type
    private func createNewState(for messageType: MessageType, using secretKey: SymmetricKey) async throws -> RatchetState {
        
        switch messageType {
        case .receiving(let localPrivateKey):
            return RatchetState(
                localPrivateKey: localPrivateKey.rawRepresentation,
                rootKey: secretKey
            )
            
        case .sending(let recipientPublicKey):
            let localPrivateKey = crypto.generateCurve25519PrivateKey()
            let sharedSecret = try localPrivateKey.sharedSecretFromKeyAgreement(with: recipientPublicKey)
            let rootKey = try await deriveHKDFSymmetricKey(
                sharedSecret: sharedSecret,
                symmetricKey: secretKey,
                configuration: defaultRatchetConfiguration
            )
            
            return await RatchetState(
                remotePublicKey: recipientPublicKey.rawRepresentation,
                localPrivateKey: localPrivateKey,
                rootKey: rootKey,
                sendingKey: try deriveChainKey(from: rootKey, configuration: defaultRatchetConfiguration)
            )
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
        deviceId: SessionIdentity,
        secretKey: SymmetricKey,
        sessionSymmetricKey: SymmetricKey,
        recipientPublicKey: Curve25519PublicKey
    ) async throws {
        try await loadDeviceIdentities(
            deviceId: deviceId,
            sessionSymmetricKey: sessionSymmetricKey,
            secretKey: secretKey,
            messageType: .sending(recipientPublicKey)
        )
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
    ///   - initialMessage: An `EncryptedMessage` that contains the first message to be
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
        deviceId: SessionIdentity,
        sessionSymmetricKey: SymmetricKey,
        secretKey: SymmetricKey,
        localPrivateKey: Curve25519PrivateKey,
        initialMessage: EncryptedMessage
    ) async throws -> Data {
        try await loadDeviceIdentities(
            deviceId: deviceId,
            sessionSymmetricKey: sessionSymmetricKey,
            secretKey: secretKey,
            messageType: .receiving(localPrivateKey))
        return try! await ratchetDecrypt(initialMessage)
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
        return self.privateState ?? newState // Return the new state, ensuring safety
    }
    
    /// Encrypts plaintext data and returns a RatchetMessage.
    public func ratchetEncrypt(plainText: Data) async throws -> EncryptedMessage {
        guard var state = await currentState else {
            throw RatchetError.missingDeviceIdentity
        }
        guard let sendingKey = state.sendingKey else { throw RatchetError.sendingKeyIsNil }
        
        let newSendingKey = try await symmetricKeyRatchet(from: sendingKey)
        await state.updateSendingKey(newSendingKey)
        state = await updateState(to: state)
        let localPublicKey = try Curve25519PrivateKey(rawRepresentation: state.localPrivateKey).publicKey
        let messageHeader = await createMessageHeader(
            publicKey: localPublicKey.rawRepresentation,
            previousChainLength: state.previousMessagesCount,
            messageNumber: state.sentMessagesCount
        )
        
        guard let associatedData = await configuration?.associatedData else { throw RatchetError.headerDataIsNil }
        let nonce = try await concatenate(
            associatedData: associatedData,
            header: messageHeader
        )
        guard nonce.count == 32 else {
            throw RatchetError.invalidNonceLength
        }
        
        await state.incrementSentMessagesCount()
        state = await updateState(to: state)
        
        guard let encryptedData = try crypto.encrypt(data: plainText, symmetricKey: newSendingKey) else { throw RatchetError.encryptionFailed }
        return EncryptedMessage(header: messageHeader, encryptedData: encryptedData)
    }
    
    public func ratchetDecrypt(_ message: EncryptedMessage) async throws -> Data {
        guard var state = await currentState else {
            throw RatchetError.missingDeviceIdentity
        }
        
        // Process a message if it was skipped first.
        let (foundMessage, _state) = try await checkForSkippedMessages(
            message,
            skippedMessageKeys: state.skippedMessageKeys)
        state = await updateState(to: _state)
        
        if let foundMessage = foundMessage {
            return try await processFoundMessage(decodedMessage: foundMessage)
        }
        
        
        // Check if the message key is valid.
        if message.header.senderPublicKey != state.remotePublicKey {
            // Process out-of-date (skipped) message.
            guard let configuration = await configuration else { throw RatchetError.missingConfiguration }
            state = try await trySkipMessageKeys(message: message, configuration: configuration)
            
            // Update the local list of skipped message keys.
            await state.updateSkippedMessages(with: state.skippedMessageKeys)
            state = await updateState(to: state)
            
            // Ratchet on decryption.
            state = try await diffieHellmanRatchet(message: message)
        } else if message.header.messageNumber < state.receivedMessagesCount {
            throw RatchetError.expiredKey
        }
        
        guard let configuration = await configuration else { throw RatchetError.missingConfiguration }
        state = try await trySkipMessageKeys(message: message, configuration: configuration)
        
        // Update the local list of skipped message keys.
        await state.updateSkippedMessages(with: state.skippedMessageKeys)
        state = await updateState(to: state)
        
        
        // The key is not valid and the message number is greater than the amount of messages we have stashed.
        guard let receivingKey = state.receivingKey else {
            throw RatchetError.receivingKeyIsNil
        }
        
        let messageKey = try await symmetricKeyRatchet(from: receivingKey)
        let newReceivingKey = try await deriveChainKey(from: receivingKey, configuration: configuration)
        
        await state.updateReceivingKey(newReceivingKey)
        state = await updateState(to: state)
        
        await state.incrementReceivedMessagesCount()
        state = await updateState(to: state)
        
        return try await processFoundMessage(
            decodedMessage: DecodedMessage(
                ratchetMessage: message,
                messageKey: messageKey
            )
        )
    }
    
    /// Attempts to skip message keys based on the received message.
    /// - Parameter message: The encrypted message to process.
    /// - Throws: An error if the device identity is missing or if key derivation fails.
    private func trySkipMessageKeys(
        message: EncryptedMessage,
        configuration: RatchetConfiguration
    ) async throws -> RatchetState {
        guard var state = await currentState else {
            throw RatchetError.stateUninitialized
        }
        guard let receivingKey = state.receivingKey else {
            return state
        }
        
        // Process until the received messages count is less than the previous chain length
        while state.receivedMessagesCount < message.header.previousChainLength {
            // Derive the message key and new receiving key
            let messageKey = try await symmetricKeyRatchet(from: receivingKey)
            let newReceivingKey = try await deriveChainKey(from: receivingKey, configuration: configuration)
            
            await state.updateReceivingKey(newReceivingKey)
            state = await updateState(to: state)
            
            // Append the new skipped message key directly to the state
            await state.updateSkippedMessages(skippedMessageKeys: SkippedMessageKey(
                publicKey: message.header.senderPublicKey,
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
        let ratchetMessage: EncryptedMessage
        let messageKey: SymmetricKey
    }
    
    func checkForSkippedMessages(
        _ message: EncryptedMessage,
        skippedMessageKeys: [SkippedMessageKey]
    ) async throws -> (DecodedMessage?, RatchetState) {
        guard var state = await currentState else {
            throw RatchetError.stateUninitialized
        }
        
        for skippedMessageKey in skippedMessageKeys {
            if skippedMessageKey.messageIndex == message.header.messageNumber,
               message.header.senderPublicKey == skippedMessageKey.publicKey {
                
                // Modify the skippedMessageKeys
                await state.removeSkippedMessages(at: skippedMessageKey.messageIndex)
                state = await updateState(to: state)
                
                return (DecodedMessage(
                    ratchetMessage: message,
                    messageKey: skippedMessageKey.messageKey
                ), state)
            }
        }
        return (nil, state)
    }
    
    /// Creates a message header for the Double Ratchet protocol.
    func createMessageHeader(
        publicKey: Data,
        previousChainLength: Int,
        messageNumber: Int
    ) async -> MessageHeader {
        MessageHeader(
            senderPublicKey: publicKey,
            previousChainLength: previousChainLength,
            messageNumber: messageNumber
        )
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
        header: MessageHeader
    ) async throws -> Data {
        let headerData = try BSONEncoder().encode(header).makeData()
        let info = headerData + associatedData
        let digest = SHA256.hash(data: info)
        return digest.withUnsafeBytes { buffer in
            Data(buffer: buffer.bindMemory(to: UInt8.self))
        }
    }
    
    /// Performs a Diffie-Hellman ratchet step when a new public key is received.
    private func diffieHellmanRatchet(message: EncryptedMessage) async throws -> RatchetState {
        guard var state = await currentState else {
            throw RatchetError.stateUninitialized
        }
        guard let configuration = await configuration else {
            throw RatchetError.missingConfiguration
        }
        
        // Update message counts and remote public key
        await state.updatePreviousMessagesCount(state.sentMessagesCount)
        await state.updateSentMessagesCount(0)
        await state.updateReceivedMessagesCount(0)
        await state.updateRemotePublicKey(message.header.senderPublicKey)
        state = await updateState(to: state)
        
        
        /// These next steps are purposed to derive a new Sending Key 
        // Derive shared secret and update keys
        let sharedSecret = try await deriveSharedSecret(
            localPrivateKeyData: state.localPrivateKey,
            senderPublicKeyData: message.header.senderPublicKey)
        
        let newRootKey = try await deriveHKDFSymmetricKey(
            sharedSecret: sharedSecret,
            symmetricKey: state.rootKey,
            configuration: configuration
        )
        
        await state.updateRootKey(newRootKey)
        state = await updateState(to: state)
        
        let newReceivingKey = try await deriveChainKey(
            from: state.rootKey,
            configuration: configuration)
        
        await state.updateReceivingKey(newReceivingKey)
        state = await updateState(to: state)
        
        
        /// These next steps are purposed to derive a new Sending Key
        // Generate new local private key
        let newLocalPrivateKey = crypto.generateCurve25519PrivateKey().rawRepresentation
        await state.updateLocalPrivateKey(newLocalPrivateKey)
        state = await updateState(to: state)
        
        // Derive shared secret again with the new local private key
        let newSharedSecret = try await deriveSharedSecret(
            localPrivateKeyData: state.localPrivateKey,
            senderPublicKeyData: message.header.senderPublicKey)
        
        let _newRootKey = try await deriveHKDFSymmetricKey(
            sharedSecret: newSharedSecret,
            symmetricKey: state.rootKey,
            configuration: configuration
        )
        await state.updateRootKey(_newRootKey)
        state = await updateState(to: state)
        
        let newSendingKey = try await deriveChainKey(
            from: state.rootKey,
            configuration: configuration)
        await state.updateSendingKey(newSendingKey)
        state = await updateState(to: state)
        
        return state
    }
    
    // Helper method to derive shared secret
    private func deriveSharedSecret(localPrivateKeyData: Data, senderPublicKeyData: Data) async throws -> SharedSecret {
        let localPrivateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: localPrivateKeyData)
        let senderPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: senderPublicKeyData)
        return try localPrivateKey.sharedSecretFromKeyAgreement(with: senderPublicKey)
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
