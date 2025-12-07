//
//  RatchetStateCore.swift
//  double-ratchet-kit
//
//  Created by Cole M on 11/23/25.
//
//  Copyright (c) 2025 NeedleTails Organization.
//
//  This project is licensed under the AGPL-3.0 License.
//
//  See the LICENSE file for more information.
//
//  This file is part of the Double Ratchet Kit SDK, which provides
//  post-quantum secure messaging with Double Ratchet Algorithm and PQXDH integration.
//

import Foundation
import NeedleTailCrypto
import NeedleTailLogger


actor RatchetStateCore<Hash: HashFunction & Sendable> {
    
    /// Default configuration for the Double Ratchet protocol.
    var defaultRatchetConfiguration = RatchetConfiguration(
        messageKeyData: Data([0x00]), // Data for message key derivation.
        chainKeyData: Data([0x01]), // Data for chain key derivation.
        rootKeyData: Data([0x02, 0x03]), // Data for root key derivation.
        associatedData: "DoubleRatchetKit".data(using: .ascii)!, // Associated data for messages.
        maxSkippedMessageKeys: 100)
    
    // MARK: - Private Properties
    
    /// The executor responsible for serialized task execution within the actor.
    private let executor: any SerialExecutor
    
    /// The executor used for non-isolated tasks.
    ///
    /// This property provides access to the underlying `SerialExecutor` for use
    /// in non-isolated contexts where you need to coordinate with the actor's executor.
    ///
    /// ## Use Cases
    /// - Creating tasks that need to execute on the actor's executor
    /// - Coordinating with other actors that use the same executor
    /// - Implementing custom concurrency patterns
    ///
    /// ## Example
    /// ```swift
    /// let executor = manager.unownedExecutor
    /// Task { @MainActor in
    ///     // Use executor for coordination
    /// }
    /// ```
    public nonisolated var unownedExecutor: UnownedSerialExecutor {
        executor.asUnownedSerialExecutor()
    }
    
    private var logger: NeedleTailLogger
    
    /// Tracks whether `shutdown()` has been called.
    private nonisolated(unsafe) var didShutdown = false
    
    /// Represents session identity and associated symmetric key for key derivation.
    public struct SessionConfiguration: Sendable {
        /// The session identity for this configuration.
        var sessionIdentity: SessionIdentity
        /// The symmetric key used for session encryption/decryption.
        var sessionSymmetricKey: SymmetricKey
        /// The current ratchet state, if initialized.
        var state: RatchetState?
    }
    
    /// All known session configurations keyed by session identity UUID.
    ///
    /// This dictionary contains all active session configurations managed by this
    /// ratchet state manager. Each configuration includes the session identity,
    /// symmetric key, and current ratchet state.
    public var sessionConfigurations: [UUID: SessionConfiguration] = [:]
    
    /// The delegate for session identity management.
    ///
    /// The delegate handles persistence of session identities and one-time key management.
    /// Set this property using `setDelegate(_:)` method.
    ///
    /// - SeeAlso: `SessionIdentityDelegate` protocol
    /// - SeeAlso: `setDelegate(_:)` method
    public weak var delegate: SessionIdentityDelegate?
    
    /// When enabled, enforce that one-time prekeys (OTK) are used exactly as indicated by the
    /// incoming header during the initial handshake.
    ///
    /// ## Behavior
    /// - **When enabled**: If the header signals an OTK but the corresponding local private OTK
    ///   cannot be loaded (either from state or via delegate), decryption will fail fast with
    ///   `RatchetError.missingOneTimeKey` during initialization or key derivation.
    /// - **When disabled**: Decryption proceeds even if the OTK is missing, potentially failing
    ///   later during the actual decryption operation.
    public var enforceOTKConsistency: Bool = false
    
    public init(
        executor: any SerialExecutor,
        logger: NeedleTailLogger = NeedleTailLogger(),
        ratchetConfiguration: RatchetConfiguration? = nil
    ) {
        self.executor = executor
        self.logger = logger
        self.logger.setLogLevel(.trace)
        if let ratchetConfiguration {
            defaultRatchetConfiguration = ratchetConfiguration
        }
    }
    
    deinit {
        precondition(didShutdown, "⛔️ RatchetStateCore was deinitialized without calling shutdown(). ")
    }
    
    /// Sets the delegate for session identity management.
    ///
    /// The delegate handles persistence of session identities and one-time key management.
    ///
    /// - Parameter delegate: An object conforming to `SessionIdentityDelegate`.
    ///   Pass `nil` to remove the current delegate.
    ///
    /// - SeeAlso: `SessionIdentityDelegate` protocol
    public func setDelegate(_ delegate: SessionIdentityDelegate) {
        self.delegate = delegate
    }
    
    /// Enable or disable strict one-time-prekey (OTK) consistency enforcement.
    ///
    /// - Parameter value: `true` to enable strict validation, `false` to disable.
    ///
    /// - SeeAlso: `enforceOTKConsistency` property for detailed documentation.
    public func setEnforceOTKConsistency(_ value: Bool) {
        self.enforceOTKConsistency = value
    }
    
    /// Sets the logging level for the ratchet state manager.
    ///
    /// - Parameter level: The desired log level. Available levels (from most to least verbose):
    ///   - `.trace`: Most verbose, includes all debug information
    ///   - `.debug`: Debug information including operations
    ///   - `.info`: Informational messages
    ///   - `.warning`: Warning messages
    ///   - `.error`: Only error messages
    public func setLogLevel(_ level: Level) async {
        logger.setLogLevel(level)
    }
    
    
    // MARK: - Session Initialization
    
    /// Shuts down the ratchet state core and persists all session states.
    ///
    /// This method:
    /// - Persists all session states to storage via the delegate
    /// - Clears in-memory session configurations
    /// - Marks the core as shut down
    ///
    /// - Important: This method must be called before the core is deinitialized.
    ///   If `shutdown()` is not called, the `deinit` will crash with a precondition failure.
    ///
    /// - Throws: An error if session state persistence fails through the delegate.
    public func shutdown() async throws {
        for (_, configuration) in sessionConfigurations {
            try await updateSessionIdentity(configuration: configuration, persist: true)
        }
        sessionConfigurations.removeAll()
        didShutdown = true
    }
    
    // MARK: - Private Helper Methods
    
    /// Container for cryptographic key material used in ratchet initialization.
    struct EncryptionKeys: Sendable {
        let remoteLongTermPublicKey: RemoteLongTermPublicKey
        let remoteOneTimePublicKey: RemoteOneTimePublicKey?
        let remoteMLKEMPublicKey: RemoteMLKEMPublicKey
        let localLongTermPrivateKey: LocalLongTermPrivateKey
        let localOneTimePrivateKey: LocalOneTimePrivateKey?
        let localMLKEMPrivateKey: LocalMLKEMPrivateKey
        
        var header: EncryptedHeader?
        
        init(remotePublicLongTermKey: RemoteLongTermPublicKey,
             remoteOneTimePublicKey: RemoteOneTimePublicKey?,
             remoteMLKEMPublicKey: RemoteMLKEMPublicKey,
             localLongTermPrivateKey: LocalLongTermPrivateKey,
             localOneTimePrivateKey: LocalOneTimePrivateKey?,
             localMLKEMPrivateKey: LocalMLKEMPrivateKey)
        {
            remoteLongTermPublicKey = remotePublicLongTermKey
            self.remoteOneTimePublicKey = remoteOneTimePublicKey
            self.remoteMLKEMPublicKey = remoteMLKEMPublicKey
            self.localLongTermPrivateKey = localLongTermPrivateKey
            self.localOneTimePrivateKey = localOneTimePrivateKey
            self.localMLKEMPrivateKey = localMLKEMPrivateKey
        }
        
        public init(
            remote: RemoteKeys,
            local: LocalKeys
        ) {
            self.init(
                remotePublicLongTermKey: remote.longTerm.rawRepresentation,
                remoteOneTimePublicKey: remote.oneTime,
                remoteMLKEMPublicKey: remote.mlKEM,
                localLongTermPrivateKey: local.longTerm.rawRepresentation,
                localOneTimePrivateKey: local.oneTime,
                localMLKEMPrivateKey: local.mlKEM)
        }
        
        public init(
            header: EncryptedHeader?,
            local: LocalKeys
        ) throws {
            if let header = header {
                try self.init(
                    remote: .init(
                        longTerm: .init(header.remoteLongTermPublicKey),
                        oneTime: header.remoteOneTimePublicKey,
                        mlKEM: header.remoteMLKEMPublicKey),
                    local: local)
                self.header = header
            } else {
                throw RatchetError.missingConfiguration
            }
        }
    }
    
    /// Represents the direction of message flow and associated keys.
    enum MessageType: Sendable {
        case sending(EncryptionKeys)
        case receiving(EncryptionKeys)
    }
    
    /// Gets the current session configuration for the specified session ID.
    ///
    /// - Parameter id: The UUID of the session.
    /// - Returns: The session configuration for the specified session.
    /// - Throws: `RatchetError.missingConfiguration` if the session is not found.
    func getCurrentConfiguration(id: UUID) throws -> SessionConfiguration {
        guard let configuration = sessionConfigurations[id] else {
            throw RatchetError.missingConfiguration
        }
        return configuration
    }
    
    /// Sets or updates the session identity configuration in the core's session store.
    ///
    /// This method atomically updates the session configuration, ensuring thread safety.
    ///
    /// - Parameter configuration: The session configuration to store or update.
    func setSessionIdentity(configuration: SessionConfiguration) {
        sessionConfigurations[configuration.sessionIdentity.id] = configuration
    }
    
    /// Checks if a message number has already been decrypted for the specified session.
    ///
    /// This method is used internally to prevent duplicate decryption of messages,
    /// which is important for security and correctness. The state is managed atomically
    /// within the core actor to avoid reentrancy issues.
    ///
    /// - Parameters:
    ///   - sessionId: The UUID of the session to check.
    ///   - messageNumber: The message number (0-based index) to check.
    /// - Returns: `true` if the message has already been decrypted, `false` otherwise.
    /// - Throws:
    ///   - `RatchetError.missingConfiguration`: If the session is not found.
    ///   - `RatchetError.stateUninitialized`: If the session state is not initialized.
    func checkAlreadyDecrypted(sessionId: UUID, messageNumber: Int) async throws -> Bool {
        let config = try getCurrentConfiguration(id: sessionId)
        guard let state = config.state else {
            throw RatchetError.stateUninitialized
        }
        return state.alreadyDecryptedMessageNumbers.contains(messageNumber)
    }
    
    /// Marks a message number as decrypted for the specified session.
    ///
    /// This method atomically updates the session state to record that a message
    /// has been successfully decrypted. This prevents duplicate decryption attempts
    /// and ensures state consistency across actor boundaries.
    ///
    /// - Parameters:
    ///   - sessionId: The UUID of the session to update.
    ///   - messageNumber: The message number (0-based index) to mark as decrypted.
    /// - Throws:
    ///   - `RatchetError.missingConfiguration`: If the session is not found.
    ///   - `RatchetError.stateUninitialized`: If the session state is not initialized.
    ///
    /// - Note: This method updates the state atomically within the core actor,
    ///   ensuring thread safety and preventing reentrancy issues.
    func markAsDecrypted(sessionId: UUID, messageNumber: Int) async throws {
        var config = try getCurrentConfiguration(id: sessionId)
        guard var state = config.state else {
            throw RatchetError.stateUninitialized
        }
        state = await state.updateAlreadyDecryptedMessageNumber(messageNumber)
        config.state = state
        sessionConfigurations[config.sessionIdentity.id] = config
    }
    
    /// Updates the session identity with a new ratchet state.
    func updateSessionIdentity(configuration: SessionConfiguration, persist: Bool = false) async throws {
        
        guard var props = await configuration.sessionIdentity.props(symmetricKey: configuration.sessionSymmetricKey) else {
            throw RatchetError.missingProps
        }
#if DEBUG
        if let oldState = props.state, let newState = configuration.state {
            await logRatchetStateDifferences(from: oldState, to: newState)
        }
#endif
        if let newState = configuration.state {
            props.state = newState
        }
        
        try await configuration.sessionIdentity.updateIdentityProps(
            symmetricKey: configuration.sessionSymmetricKey,
            props: props)
        
        if persist {
            try await delegate?.updateSessionIdentity(configuration.sessionIdentity)
        }
        
        sessionConfigurations[configuration.sessionIdentity.id] = configuration
        logger.log(level: .trace, message: "Ratchet Manager updated Session Identity state")
    }
    
    private func logRatchetStateDifferences(from old: RatchetState, to new: RatchetState) async {
        // Compare each field. Log only if changed.
        if old.sentMessagesCount != new.sentMessagesCount {
            logger.log(level: .trace, message: "sentMessagesCount changed: \(old.sentMessagesCount) → \(new.sentMessagesCount)")
        }
        if old.receivedMessagesCount != new.receivedMessagesCount {
            logger.log(level: .trace, message: "receivedMessagesCount changed: \(old.receivedMessagesCount) → \(new.receivedMessagesCount)")
        }
        if old.previousMessagesCount != new.previousMessagesCount {
            logger.log(level: .trace, message: "previousMessagesCount changed: \(old.previousMessagesCount) → \(new.previousMessagesCount)")
        }
        if old.sendingHandshakeFinished != new.sendingHandshakeFinished {
            logger.log(level: .trace, message: "sendingHandshakeFinished changed: \(old.sendingHandshakeFinished) → \(new.sendingHandshakeFinished)")
        }
        if old.receivingHandshakeFinished != new.receivingHandshakeFinished {
            logger.log(level: .trace, message: "receivingHandshakeFinished changed: \(old.receivingHandshakeFinished) → \(new.receivingHandshakeFinished)")
        }
        if old.localLongTermPrivateKey != new.localLongTermPrivateKey {
            logger.log(level: .trace, message: "localLongTermPrivateKey changed")
        }
        if old.localOneTimePrivateKey?.rawRepresentation != new.localOneTimePrivateKey?.rawRepresentation {
            logger.log(level: .trace, message: "localOneTimePrivateKey changed")
        }
        if old.localMLKEMPrivateKey.rawRepresentation != new.localMLKEMPrivateKey.rawRepresentation {
            logger.log(level: .trace, message: "localMLKEMPrivateKey changed")
        }
        if old.remoteLongTermPublicKey != new.remoteLongTermPublicKey {
            logger.log(level: .trace, message: "remoteLongTermPublicKey changed")
        }
        if old.remoteOneTimePublicKey?.rawRepresentation != new.remoteOneTimePublicKey?.rawRepresentation {
            logger.log(level: .trace, message: "remoteOneTimePublicKey changed")
        }
        if old.remoteMLKEMPublicKey.rawRepresentation != new.remoteMLKEMPublicKey.rawRepresentation {
            logger.log(level: .trace, message: "remoteMLKEMPublicKey changed")
        }
        if old.sendingKey != new.sendingKey {
            logger.log(level: .trace, message: "sendingKey changed")
        }
        if old.receivingKey != new.receivingKey {
            logger.log(level: .trace, message: "receivingKey changed")
        }
        if old.headerCiphertext != new.headerCiphertext {
            logger.log(level: .trace, message: "headerCiphertext changed")
        }
        if old.sendingHeaderKey != new.sendingHeaderKey {
            logger.log(level: .trace, message: "sendingHeaderKey changed")
        }
        if old.nextSendingHeaderKey != new.nextSendingHeaderKey {
            logger.log(level: .trace, message: "nextSendingHeaderKey changed")
        }
        if old.receivingHeaderKey != new.receivingHeaderKey {
            logger.log(level: .trace, message: "receivingHeaderKey changed")
        }
        if old.nextReceivingHeaderKey != new.nextReceivingHeaderKey {
            logger.log(level: .trace, message: "nextReceivingHeaderKey changed")
        }
        if old.skippedMessageKeys.count != new.skippedMessageKeys.count {
            logger.log(level: .trace, message: "skippedMessageKeys count changed: \(old.skippedMessageKeys.count) → \(new.skippedMessageKeys.count)")
        }
        if old.skippedHeaderMessages.count != new.skippedHeaderMessages.count {
            logger.log(level: .trace, message: "skippedHeaderMessages count changed: \(old.skippedHeaderMessages.count) → \(new.skippedHeaderMessages.count)")
        }
        if old.alreadyDecryptedMessageNumbers != new.alreadyDecryptedMessageNumbers {
            logger.log(level: .trace, message: "alreadyDecryptedMessageNumbers changed")
        }
        if old.lastSkippedIndex != new.lastSkippedIndex {
            logger.log(level: .trace, message: "lastSkippedIndex changed: \(old.lastSkippedIndex) → \(new.lastSkippedIndex)")
        }
        if old.headerIndex != new.headerIndex {
            logger.log(level: .trace, message: "headerIndex changed: \(old.headerIndex) → \(new.headerIndex)")
        }
        if old.lastDecryptedMessageNumber != new.lastDecryptedMessageNumber {
            logger.log(level: .trace, message: "lastDecryptedMessageNumber changed: \(old.lastDecryptedMessageNumber) → \(new.lastDecryptedMessageNumber)")
        }
    }
    
    func setState(for messageType: MessageType, configuration: SessionConfiguration) async throws -> RatchetState {
        switch messageType {
        case let .receiving(keys):
            guard let header = keys.header else {
                throw RatchetError.missingConfiguration
            }
            return RatchetState(
                remoteLongTermPublicKey: header.remoteLongTermPublicKey,
                remoteOneTimePublicKey: header.remoteOneTimePublicKey,
                remoteMLKEMPublicKey: header.remoteMLKEMPublicKey,
                localLongTermPrivateKey: keys.localLongTermPrivateKey,
                localOneTimePrivateKey: keys.localOneTimePrivateKey,
                localMLKEMPrivateKey: keys.localMLKEMPrivateKey)
        case let .sending(keys):
            let (sendingKey, cipher) = try await deriveNextMessageKey(
                localLongTermPrivateKey: keys.localLongTermPrivateKey,
                remoteLongTermPublicKey: keys.remoteLongTermPublicKey,
                localOneTimePrivateKey: keys.localOneTimePrivateKey,
                remoteOneTimePublicKey: keys.remoteOneTimePublicKey,
                remoteMLKEMPublicKey: keys.remoteMLKEMPublicKey,
                configuration: configuration)
            return RatchetState(
                remoteLongTermPublicKey: keys.remoteLongTermPublicKey,
                remoteOneTimePublicKey: keys.remoteOneTimePublicKey,
                remoteMLKEMPublicKey: keys.remoteMLKEMPublicKey,
                localLongTermPrivateKey: keys.localLongTermPrivateKey,
                localOneTimePrivateKey: keys.localOneTimePrivateKey,
                localMLKEMPrivateKey: keys.localMLKEMPrivateKey,
                rootKey: cipher.symmetricKey,
                messageCiphertext: cipher.ciphertext,
                sendingKey: sendingKey)
        }
    }
    
    /// Performs a symmetric-key ratchet step to derive the next message key.
    func symmetricKeyRatchet(from symmetricKey: SymmetricKey) async throws -> SymmetricKey {
        let chainKey = HMAC<SHA256>.authenticationCode(for: defaultRatchetConfiguration.messageKeyData, using: symmetricKey)
        return SymmetricKey(data: chainKey)
    }
    
    /// Derives a new chain key from a base symmetric key and ratchet configuration.
    func deriveChainKey(
        from symmetricKey: SymmetricKey,
        configuration: RatchetConfiguration,
    ) async throws -> SymmetricKey {
        let chainKey = HMAC<SHA256>.authenticationCode(for: configuration.chainKeyData, using: symmetricKey)
        return SymmetricKey(data: chainKey)
    }
    
    /// Derives a shared secret from Curve25519 key agreement.
    private func deriveSharedSecret(
        localPrivateKey: LocalPrivateKey,
        remotePublicKey: RemotePublicKey,
    ) async throws -> SharedSecret {
        let localPrivateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: localPrivateKey)
        let remotePublicKeyData = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: remotePublicKey)
        return try localPrivateKey.sharedSecretFromKeyAgreement(with: remotePublicKeyData)
    }
    
    /// Derives the PQ-X3DH final key from received ciphertext and Curve25519 keys (receiver side).
    func derivePQXDHFinalKeyReceiver(
        remoteLongTermPublicKey: RemoteLongTermPublicKey,
        remoteOneTimePublicKey: RemoteOneTimePublicKey?,
        localLongTermPrivateKey: LocalLongTermPrivateKey,
        localOneTimePrivateKey: LocalOneTimePrivateKey?,
        localMLKEMPrivateKey: LocalMLKEMPrivateKey,
        receivedCiphertext: Data,
    ) async throws -> SymmetricKey {
        
        // Derive shared secret for long-term keys
        let K_B = try await deriveSharedSecret(localPrivateKey: localLongTermPrivateKey, remotePublicKey: remoteLongTermPublicKey)
        let K_B_data = K_B.bytes
        
        // Derive shared secret for one-time keys if both are present
        var K_B_ot_data = Data()
        if let localOTKey = localOneTimePrivateKey, let remoteOTKey = remoteOneTimePublicKey {
            let K_B_ot = try await deriveSharedSecret(localPrivateKey: localOTKey.rawRepresentation, remotePublicKey: remoteOTKey.rawRepresentation)
            K_B_ot_data = K_B_ot.bytes
        }
        
        let localMLKEMPK = try localMLKEMPrivateKey.rawRepresentation.decodeMLKem1024()
        let decapsulatedBytes = try localMLKEMPK.decapsulate(receivedCiphertext).bytes
        // Use local private one-time public key as salt if available, else fallback to long-term public key
        let salt: Data
        if let localOTKey = localOneTimePrivateKey {
            let curveKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: localOTKey.rawRepresentation)
            let mlKEMKey = try localMLKEMPrivateKey.rawRepresentation.decodeMLKem1024()
            salt = curveKey.publicKey.rawRepresentation + mlKEMKey.publicKey.rawRepresentation
        } else {
            let curveKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: localLongTermPrivateKey)
            let mlKEMKey = try localMLKEMPrivateKey.rawRepresentation.decodeMLKem1024()
            salt = curveKey.publicKey.rawRepresentation + mlKEMKey.publicKey.rawRepresentation
        }
        
        // Concatenate secrets
        let concatenatedSecrets = K_B_data + K_B_ot_data + decapsulatedBytes
        
        // Derive final symmetric key using HKDF with SHA512
        return HKDF<SHA512>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: concatenatedSecrets),
            salt: salt,
            outputByteCount: 32)
    }
    
    /// A container for encapsulated MLKEM ciphertext and resulting symmetric key.
    struct PQXDHCipher: Sendable {
        let ciphertext: Data
        let symmetricKey: SymmetricKey
    }
    
    /// Derives a PQ-X3DH hybrid key (sender side), combining Curve25519 and Kyber-1024 key exchange.
    ///
    /// - Returns: A `PQXDHCipher` containing MLKEM ciphertext and final symmetric key.
    /// - Throws: Errors during key agreement or encapsulation.
    func derivePQXDHFinalKey(
        localLongTermPrivateKey: LocalLongTermPrivateKey,
        localOneTimePrivateKey: LocalOneTimePrivateKey?,
        remoteLongTermPublicKey: RemoteLongTermPublicKey,
        remoteOneTimePublicKey: RemoteOneTimePublicKey?,
        remoteMLKEMPublicKey: RemoteMLKEMPublicKey,
    ) async throws -> PQXDHCipher {
        
        let K_A = try await deriveSharedSecret(localPrivateKey: localLongTermPrivateKey, remotePublicKey: remoteLongTermPublicKey)
        
        var K_A_ot_data = Data()
        if let localOTKey = localOneTimePrivateKey, let remoteOTKey = remoteOneTimePublicKey {
            let K_A_ot = try await deriveSharedSecret(localPrivateKey: localOTKey.rawRepresentation, remotePublicKey: remoteOTKey.rawRepresentation)
            K_A_ot_data = K_A_ot.bytes
        }
        
        let K_A_data = K_A.bytes
        
        let remoteMLKEMPK = try MLKEM1024.PublicKey(rawRepresentation: remoteMLKEMPublicKey.rawRepresentation)
        let result = try remoteMLKEMPK.encapsulate()
        let ciphertext = result.encapsulated
        let sharedSecretBytes = result.sharedSecret.bytes
        
        let concatenatedSecrets = K_A_data + K_A_ot_data + sharedSecretBytes
        
        let salt: Data = if let remoteOTKey = remoteOneTimePublicKey {
            remoteOTKey.rawRepresentation + remoteMLKEMPublicKey.rawRepresentation
        } else {
            // Use the remote long-term public key as a fallback salt (stable, non-empty)
            remoteLongTermPublicKey + remoteMLKEMPublicKey.rawRepresentation
        }
        let symmetricKey = HKDF<SHA512>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: concatenatedSecrets),
            salt: salt,
            outputByteCount: 32)
        return PQXDHCipher(ciphertext: ciphertext, symmetricKey: symmetricKey)
    }
    
    private func deriveNextMessageKey(localLongTermPrivateKey: LocalLongTermPrivateKey,
                                      remoteLongTermPublicKey: RemoteLongTermPublicKey,
                                      localOneTimePrivateKey: LocalOneTimePrivateKey?,
                                      remoteOneTimePublicKey: RemoteOneTimePublicKey?,
                                      remoteMLKEMPublicKey: RemoteMLKEMPublicKey,
                                      configuration: SessionConfiguration
    ) async throws -> (SymmetricKey, PQXDHCipher) {

        let cipher = try await derivePQXDHFinalKey(
            localLongTermPrivateKey: localLongTermPrivateKey,
            localOneTimePrivateKey: localOneTimePrivateKey,
            remoteLongTermPublicKey: remoteLongTermPublicKey,
            remoteOneTimePublicKey: remoteOneTimePublicKey,
            remoteMLKEMPublicKey: remoteMLKEMPublicKey)
        
        let newChainKey = try await deriveChainKey(
            from: cipher.symmetricKey,
            configuration: defaultRatchetConfiguration)
        
        var configuration = configuration
        if var state = configuration.state {
            state = await state.updateRootKey(cipher.symmetricKey)
            state = await state.updateCiphertext(cipher.ciphertext)
            configuration.state = state
            try await updateSessionIdentity(configuration: configuration)
        }
        return (newChainKey, cipher)
    }
    
}
