//
//  RatchetKeyStateManager.swift
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

public actor RatchetKeyStateManager<Hash: HashFunction & Sendable> {
    
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
    
    private let core: RatchetStateCore<Hash>
    
    public init(
        executor: any SerialExecutor,
        logger: NeedleTailLogger = NeedleTailLogger(),
        ratchetConfiguration: RatchetConfiguration? = nil
    ) {
        self.executor = executor
        self.logger = logger
        self.logger.setLogLevel(.trace)
        core = RatchetStateCore(
            executor: executor,
            logger: logger,
            ratchetConfiguration: ratchetConfiguration)
    }
    
    deinit {
        precondition(didShutdown, "⛔️ RatchetKeyStateManager was deinitialized without calling shutdown(). ")
    }
    
    /// Sets the delegate for session identity management.
    public func setDelegate(_ delegate: SessionIdentityDelegate) async {
        await core.setDelegate(delegate)
    }
    
    /// Enable or disable strict one-time-prekey (OTK) consistency enforcement.
    public func setEnforceOTKConsistency(_ value: Bool) async {
        await core.setEnforceOTKConsistency(value)
    }
    
    /// Sets the logging level for the ratchet state manager.
    public func setLogLevel(_ level: Level) async {
        logger.setLogLevel(level)
        await core.setLogLevel(level)
    }
    
    // MARK: - Session Initialization
    
    /// Initializes a sending session with the provided keys and session identity.
    public func senderInitialization(
        sessionIdentity: SessionIdentity,
        sessionSymmetricKey: SymmetricKey,
        remoteKeys: RemoteKeys,
        localKeys: LocalKeys,
    ) async throws {
        let keys = RatchetStateCore<Hash>.EncryptionKeys(remote: remoteKeys, local: localKeys)
        try await loadConfigurations(
            sessionIdentity: sessionIdentity,
            sessionSymmetricKey: sessionSymmetricKey,
            messageType: .sending(keys))
    }
    
    /// Initializes a receiving session for external key derivation workflows.
    public func recipientInitialization(
        sessionIdentity: SessionIdentity,
        sessionSymmetricKey: SymmetricKey,
        localKeys: LocalKeys,
        remoteKeys: RemoteKeys,
        ciphertext: Data
    ) async throws {
        let keys = RatchetStateCore<Hash>.EncryptionKeys(remote: remoteKeys, local: localKeys)
        try await loadConfigurations(
            sessionIdentity: sessionIdentity,
            sessionSymmetricKey: sessionSymmetricKey,
            messageType: .receiving(keys))
    }
    
    /// Shuts down the ratchet state manager and persists all session states.
    public func shutdown() async throws {
        try await core.shutdown()
        didShutdown = true
    }
    
    /// Load or create session configuration and ratchet state as needed.
    func loadConfigurations(
        sessionIdentity: SessionIdentity,
        sessionSymmetricKey: SymmetricKey,
        messageType: RatchetStateCore<Hash>.MessageType,
    ) async throws {
        if var configuration = await core.sessionConfigurations[sessionIdentity.id] {
            // 1. Check if we have a currently loaded session
            logger.log(level: .trace, message: "Found initialized session, reusing ratchet state")
            guard var currentProps = await configuration
                .sessionIdentity
                .props(symmetricKey: sessionSymmetricKey) else {
                throw RatchetError.missingProps
            }
            
            // If we have a session and we call this method again we need to check if it is a new type
            switch messageType {
            case let .sending(keys):
                guard let state = configuration.state else {
                    throw RatchetError.stateUninitialized
                }
                
                // Check if sending handshake is finished
                if state.sendingHandshakeFinished == false || state.messageCiphertext == nil {
                    // Do initial sending setup and update the state with the ciphertext and sending key
                    var chainKey: SymmetricKey
                    var updatedState = state
                    
                    if let sendingKey = state.sendingKey {
                        // Sending key already exists, use it
                        chainKey = sendingKey
                        currentProps.state = updatedState
                    } else {
                        // Generate PQXDH ciphertext for sending
                        let pqxdhCipher = try await core.derivePQXDHFinalKey(
                            localLongTermPrivateKey: keys.localLongTermPrivateKey,
                            localOneTimePrivateKey: keys.localOneTimePrivateKey,
                            remoteLongTermPublicKey: keys.remoteLongTermPublicKey,
                            remoteOneTimePublicKey: keys.remoteOneTimePublicKey,
                            remoteMLKEMPublicKey: keys.remoteMLKEMPublicKey
                        )
                        
                        // Update root key if not set
                        if updatedState.rootKey == nil {
                            updatedState = await updatedState.updateRootKey(pqxdhCipher.symmetricKey)
                        }
                        
                        // Update ciphertext
                        updatedState = await updatedState.updateCiphertext(pqxdhCipher.ciphertext)
                        
                        // Derive initial chain key from root key
                        if let rootKey = updatedState.rootKey {
                            chainKey = try await core.deriveChainKey(
                                from: rootKey,
                                configuration: core.defaultRatchetConfiguration
                            )
                        } else {
                            chainKey = try await core.deriveChainKey(
                                from: pqxdhCipher.symmetricKey,
                                configuration: core.defaultRatchetConfiguration
                            )
                        }
                        
                        // Update state with sending key
                        updatedState = await updatedState.updateSendingKey(chainKey)
                        currentProps.state = updatedState
                    }
                } else {
                    // Sending handshake already finished, use existing state
                    currentProps.state = state
                }
                
            case .receiving(let keys):
                // For receiving, state should already be initialized via recipientInitialization
                // Just ensure we have the state
                if let state = currentProps.state {
                    currentProps.state = state
                } else {
                    // If no state exists, create a basic receiving state
                    let ratchetState = RatchetState(
                        remoteLongTermPublicKey: keys.remoteLongTermPublicKey,
                        remoteOneTimePublicKey: keys.remoteOneTimePublicKey,
                        remoteMLKEMPublicKey: keys.remoteMLKEMPublicKey,
                        localLongTermPrivateKey: keys.localLongTermPrivateKey,
                        localOneTimePrivateKey: keys.localOneTimePrivateKey,
                        localMLKEMPrivateKey: keys.localMLKEMPrivateKey
                    )
                    currentProps.state = ratchetState
                }
            }
            
            configuration.state = currentProps.state
            try await sessionIdentity.updateIdentityProps(symmetricKey: sessionSymmetricKey, props: currentProps)
            
            configuration.sessionIdentity = sessionIdentity
            configuration.sessionSymmetricKey = sessionSymmetricKey
            
            try await core.updateSessionIdentity(configuration: configuration, persist: true)
            // Ensure configuration is set in memory for subsequent operations
            await core.setSessionIdentity(configuration: configuration)
        } else {
            logger.log(level: .trace, message: "Session not initialized yet, creating state for ratchet")
            var configuration = RatchetStateCore<Hash>.SessionConfiguration(
                sessionIdentity: sessionIdentity,
                sessionSymmetricKey: sessionSymmetricKey)
            
            guard var props = await sessionIdentity.props(symmetricKey: sessionSymmetricKey) else {
                throw RatchetError.missingProps
            }
            
            if var state = props.state {
                // If this session identity is not loaded into memory we may have rotated key before loaded;
                // therefore we need to update session identity. If not we assure we are using the keys
                // received from the consumer when they feed the session identity.
                switch messageType {
                case let .sending(keys):
                    // Check if sending handshake needs to be completed
                    if state.sendingHandshakeFinished == false || state.messageCiphertext == nil {
                        // Generate PQXDH ciphertext for sending
                        let pqxdhCipher = try await core.derivePQXDHFinalKey(
                            localLongTermPrivateKey: keys.localLongTermPrivateKey,
                            localOneTimePrivateKey: keys.localOneTimePrivateKey,
                            remoteLongTermPublicKey: keys.remoteLongTermPublicKey,
                            remoteOneTimePublicKey: keys.remoteOneTimePublicKey,
                            remoteMLKEMPublicKey: keys.remoteMLKEMPublicKey
                        )
                        
                        // Update root key if not set
                        if state.rootKey == nil {
                            state = await state.updateRootKey(pqxdhCipher.symmetricKey)
                        }
                        
                        // Update ciphertext
                        state = await state.updateCiphertext(pqxdhCipher.ciphertext)
                        
                        // Derive initial chain key from root key
                        let initialChainKey: SymmetricKey
                        if let rootKey = state.rootKey {
                            initialChainKey = try await core.deriveChainKey(
                                from: rootKey,
                                configuration: core.defaultRatchetConfiguration
                            )
                        } else {
                            initialChainKey = try await core.deriveChainKey(
                                from: pqxdhCipher.symmetricKey,
                                configuration: core.defaultRatchetConfiguration
                            )
                        }
                        
                        // Update state with sending key
                        state = await state.updateSendingKey(initialChainKey)
                    }
                    
                case .receiving(let keys):
                    // For receiving, state should already be set up via recipientInitialization
                    // Just ensure keys are updated if needed
                    if state.remoteLongTermPublicKey != keys.remoteLongTermPublicKey {
                        state = await state.updateRemoteLongTermPublicKey(keys.remoteLongTermPublicKey)
                    }
                    if state.remoteOneTimePublicKey != keys.remoteOneTimePublicKey {
                        state = await state.updateRemoteOneTimePublicKey(keys.remoteOneTimePublicKey)
                    }
                    if state.remoteMLKEMPublicKey != keys.remoteMLKEMPublicKey {
                        state = await state.updateRemoteMLKEMPublicKey(keys.remoteMLKEMPublicKey)
                    }
                }
                configuration.state = state
            } else {
                // Initialize new state based on message type
                // First, set the configuration in memory so core.setState can access it
                await core.setSessionIdentity(configuration: configuration)
                
                let state: RatchetState
                switch messageType {
                case .sending:
                    // For sending, use core.setState which generates ciphertext
                    state = try await core.setState(for: messageType, configuration: configuration)
                case let .receiving(keys):
                    // For receiving in external key derivation workflow, create state without header
                    // The ciphertext is provided separately via recipientInitialization
                    state = RatchetState(
                        remoteLongTermPublicKey: keys.remoteLongTermPublicKey,
                        remoteOneTimePublicKey: keys.remoteOneTimePublicKey,
                        remoteMLKEMPublicKey: keys.remoteMLKEMPublicKey,
                        localLongTermPrivateKey: keys.localLongTermPrivateKey,
                        localOneTimePrivateKey: keys.localOneTimePrivateKey,
                        localMLKEMPrivateKey: keys.localMLKEMPrivateKey
                    )
                }
                props.state = state
                configuration.sessionIdentity = sessionIdentity
                configuration.state = state
                try await core.updateSessionIdentity(configuration: configuration)
            }
            
            try await sessionIdentity.updateIdentityProps(symmetricKey: sessionSymmetricKey, props: props)
            try await core.updateSessionIdentity(configuration: configuration, persist: true)
            // Ensure configuration is set in memory for subsequent operations
            await core.setSessionIdentity(configuration: configuration)
        }
    }
    
    /// Derives the next message key for sending without performing full message encryption.
    ///
    /// This method is designed for advanced use cases where you want to handle encryption externally
    /// while the SDK manages ratchet key derivation. It derives the next message key, advances the
    /// sending chain key, and updates the session state.
    ///
    /// ## Use Cases
    /// - **External Encryption**: When you need to use a custom encryption scheme but want the SDK
    ///   to manage Double Ratchet key derivation
    /// - **Key Pre-computation**: When you want to derive keys in advance for batch processing
    /// - **Custom Message Format**: When your message format differs from the standard `RatchetMessage`
    ///
    /// ## Side Effects
    /// This method mutates the session state:
    /// - Advances the sending chain key
    /// - Increments the sent message count
    /// - Marks handshake as finished if it was the first message
    /// - Persists state through the delegate
    ///
    /// ## Example
    /// ```swift
    /// // Derive message key for external encryption
    /// let (messageKey, messageNumber) = try await manager.deriveMessageKey(sessionId: sessionId)
    ///
    /// // Perform custom encryption
    /// let encryptedData = try customEncrypt(plaintext, key: messageKey)
    ///
    /// // Send encrypted data with your own protocol
    /// // messageNumber is the index of this message (0-based)
    /// ```
    ///
    /// - Parameter sessionId: The UUID of the session to derive the key for.
    /// - Returns: A tuple containing the derived symmetric key for encrypting the next message and its message number.
    /// - Throws:
    ///   - `RatchetError.missingConfiguration`: If the session is not found.
    ///   - `RatchetError.stateUninitialized`: If the session state is not initialized.
    ///   - `RatchetError.sendingKeyIsNil`: If the sending key is missing.
    ///   - `RatchetError.missingOneTimeKey`: If OTK consistency is enforced and the key is missing.
    ///
    /// - Important: This method advances the ratchet state. Each call derives a new key and
    ///   increments the message counter. Do not call this method multiple times for the same message.
    ///
    /// - Warning: **This method should only be used when NOT encrypting/decrypting messages via
    ///   `ratchetEncrypt`/`ratchetDecrypt`.** These methods (`deriveMessageKey`, `deriveReceivedMessageKey`,
    ///   `getSentMessageNumber`, `getReceivedMessageNumber`, `setCipherText`, `getCipherText`) are
    ///   designed for external key derivation workflows in `RatchetKeyStateManager`.
    ///   Do not mix these methods with the standard encryption/decryption API, as this may cause state
    ///   inconsistencies and security issues.
    ///
    /// - SeeAlso: `deriveReceivedMessageKey(sessionId:cipherText:)` for the receiving side equivalent.
    public func deriveMessageKey(sessionId: UUID) async throws -> (SymmetricKey, Int) {
        
        var configuration = try await core.getCurrentConfiguration(id: sessionId)
        
        guard var state = configuration.state else {
            throw RatchetError.stateUninitialized
        }
        
        if !state.sendingHandshakeFinished {
            if await core.enforceOTKConsistency {
                let wantsOTK = (state.remoteOneTimePublicKey != nil)
                if wantsOTK && state.localOneTimePrivateKey == nil {
                    throw RatchetError.missingOneTimeKey
                }
            }
        }
        
        configuration.state = state
        
        guard let sendingKey = state.sendingKey else {
            throw RatchetError.sendingKeyIsNil
        }
        
        // Step 7: Encrypt the payload using AEAD with the current sending key.
        let messageKey = try await core.symmetricKeyRatchet(from: sendingKey)
        
        if !state.sendingHandshakeFinished {
            state = await state.updateSendingHandshakeFinished(true)
            logger.log(level: .trace, message: "Initial sending handshake succeeded")
        }
        
        let newChainKey = try await core.deriveChainKey(
            from: sendingKey,
            configuration: core.defaultRatchetConfiguration)
        
        // Capture message number before incrementing (0-based index)
        let messageNumber = state.sentMessagesCount
        
        state = await state.updateSendingKey(newChainKey)
        state = await state.incrementSentMessagesCount()
        
        configuration.state = state
        try await core.updateSessionIdentity(configuration: configuration, persist: true)
        
        return (messageKey, messageNumber)
    }
    
    /// Derives the next message key for receiving without performing full message decryption.
    ///
    /// This method is designed for advanced use cases where you want to handle decryption externally
    /// while the SDK manages ratchet key derivation. It derives the next message key, advances the
    /// receiving chain key, and updates the session state.
    ///
    /// ## Use Cases
    /// - **External Decryption**: When you need to use a custom decryption scheme but want the SDK
    ///   to manage Double Ratchet key derivation
    /// - **Key Pre-computation**: When you want to derive keys in advance for batch processing
    /// - **Custom Message Format**: When your message format differs from the standard `RatchetMessage`
    ///
    /// ## Side Effects
    /// This method mutates the session state:
    /// - Advances the receiving chain key
    /// - Increments the received message count
    /// - Updates root key if this is the first message after handshake
    /// - Persists state through the delegate
    ///
    /// ## Example
    /// ```swift
    /// // Derive message key for external decryption
    /// let (messageKey, messageNumber) = try await manager.deriveReceivedMessageKey(
    ///     sessionId: sessionId,
    ///     cipherText: ciphertext
    /// )
    ///
    /// // Perform custom decryption
    /// let plaintext = try customDecrypt(encryptedData, key: messageKey)
    /// // messageNumber is the index of this message (0-based)
    /// ```
    ///
    /// - Parameters:
    ///   - sessionId: The UUID of the session to derive the key for.
    ///   - cipherText: The MLKEM ciphertext. Used during handshake to derive root key if needed.
    ///     After handshake, this parameter is not used but required for signature consistency.
    /// - Returns: A tuple containing the derived symmetric key for decrypting the next message and its message number.
    /// - Throws:
    ///   - `RatchetError.missingConfiguration`: If the session is not found.
    ///   - `RatchetError.stateUninitialized`: If the session state is not initialized.
    ///   - `RatchetError.receivingKeyIsNil`: If the receiving key is missing.
    ///   - `RatchetError.rootKeyIsNil`: If the root key is missing when needed.
    ///
    /// - Important: This method advances the ratchet state. Each call derives a new key. Do not
    ///   call this method multiple times for the same message.
    ///
    /// - Warning: **This method should only be used when NOT encrypting/decrypting messages via
    ///   `ratchetEncrypt`/`ratchetDecrypt`.** These methods (`deriveMessageKey`, `deriveReceivedMessageKey`,
    ///   `getSentMessageNumber`, `getReceivedMessageNumber`, `setCipherText`, `getCipherText`) are
    ///   designed for external key derivation workflows in `RatchetKeyStateManager`.
    ///   Do not mix these methods with the standard encryption/decryption API, as this may cause state
    ///   inconsistencies and security issues.
    ///
    /// - SeeAlso: `deriveMessageKey(sessionId:)` for the sending side equivalent.
    public func deriveReceivedMessageKey(sessionId: UUID, cipherText: Data) async throws -> (SymmetricKey, Int) {
        
        var configuration = try await core.getCurrentConfiguration(id: sessionId)
        
        guard var state = configuration.state else {
            throw RatchetError.stateUninitialized
        }
        
        // We then handle decryption logic.. at this point the key order must be in resolved
        // MESSAGE DECRYPTION PHASE
        if !state.receivingHandshakeFinished {
            var chainKey: SymmetricKey
            if state.rootKey == nil {
                
                // First message after handshake:
                // Derive root and chain keys from PQXDH final key receiver function.
                let finalReceivingKey = try await core.derivePQXDHFinalKeyReceiver(
                    remoteLongTermPublicKey: state.remoteLongTermPublicKey,
                    remoteOneTimePublicKey: state.remoteOneTimePublicKey,
                    localLongTermPrivateKey: state.localLongTermPrivateKey,
                    localOneTimePrivateKey: state.localOneTimePrivateKey,
                    localMLKEMPrivateKey: state.localMLKEMPrivateKey,
                    receivedCiphertext: cipherText)
                
                // Derive chain key from the new root key.
                chainKey = try await core.deriveChainKey(from: finalReceivingKey, configuration: core.defaultRatchetConfiguration)
                let nextChainKey = try await core.deriveChainKey(from: chainKey, configuration: core.defaultRatchetConfiguration)
                // Update root and receiving chain key in state for ratchet progression.
                state = await state.updateRootKey(finalReceivingKey)
                state = await state.updateReceivingKey(nextChainKey)
            } else {
                if let receivingKey = state.receivingKey {
                    chainKey = receivingKey
                } else {
                    guard let rootKey = state.rootKey else {
                        throw RatchetError.rootKeyIsNil
                    }
                    // if we have a root key but not a receiving key create a receiving key from the root key
                    chainKey = try await core.deriveChainKey(
                        from: rootKey,
                        configuration: core.defaultRatchetConfiguration,
                    )
                }
                
                let nextChainKey = try await core.deriveChainKey(from: chainKey, configuration: core.defaultRatchetConfiguration)
                state = await state.updateReceivingKey(nextChainKey)
            }
            
            // Derive message key and update state
            let messageKey = try await core.symmetricKeyRatchet(from: chainKey)
            
            if !state.receivingHandshakeFinished {
                state = await state.updateReceivingHandshakeFinished(true)
                logger.log(level: .trace, message: "Initial receiving handshake succeeded")
            }
            
            // Capture message number before incrementing (0-based index)
            let messageNumber = state.receivedMessagesCount
            
            state = await state.incrementReceivedMessagesCount()
            
            // Update State
            configuration.state = state
            try await core.updateSessionIdentity(configuration: configuration, persist: true)
            
            return (messageKey, messageNumber)
            
        } else {
            
            guard let receivingKey = state.receivingKey else {
                throw RatchetError.receivingKeyIsNil
            }
            
            // Step 7: Derive the message key using AEAD with the current receiving key.
            let messageKey = try await core.symmetricKeyRatchet(from: receivingKey)
            
            // Capture message number before incrementing (0-based index)
            let messageNumber = state.receivedMessagesCount
            
            let newChainKey = try await core.deriveChainKey(
                from: receivingKey,
                configuration: core.defaultRatchetConfiguration)
            
            state = await state.updateReceivingKey(newChainKey)
            state = await state.incrementReceivedMessagesCount()
            
            configuration.state = state
            try await core.updateSessionIdentity(configuration: configuration, persist: true)
            
            return (messageKey, messageNumber)
            
        }
    }
    
    /// Gets the MLKEM ciphertext stored in the session state.
    ///
    /// The ciphertext is the post-quantum key exchange ciphertext from the PQXDH handshake.
    /// It is used during the initial handshake phase to derive the root key and establish
    /// the secure communication channel.
    ///
    /// ## Use Cases
    /// - **State Inspection**: Retrieve the stored ciphertext for debugging or logging
    /// - **External Key Derivation**: Access the ciphertext when using external key derivation workflows
    /// - **State Recovery**: Verify the ciphertext during session restoration
    ///
    /// ## Example
    /// ```swift
    /// // Get the stored ciphertext for a session
    /// let ciphertext = try manager.getCipherText(sessionId: sessionId)
    /// print("Ciphertext length: \(ciphertext.count) bytes")
    /// ```
    ///
    /// - Parameter sessionId: The UUID of the session.
    /// - Returns: The MLKEM ciphertext data.
    /// - Throws:
    ///   - `RatchetError.missingConfiguration`: If the session is not found.
    ///   - `RatchetError.stateUninitialized`: If the session state is not initialized.
    ///   - `RatchetError.missingCipherText`: If the ciphertext has not been set in the session state.
    ///
    /// - Warning: **This method should only be used when NOT encrypting/decrypting messages via
    ///   `ratchetEncrypt`/`ratchetDecrypt`.** These methods (`deriveMessageKey`, `deriveReceivedMessageKey`,
    ///   `getSentMessageNumber`, `getReceivedMessageNumber`, `setCipherText`, `getCipherText`) are
    ///   designed for external key derivation workflows in `RatchetKeyStateManager`.
    ///   Do not mix these methods with the standard encryption/decryption API, as this may cause state
    ///   inconsistencies and security issues.
    public func getCipherText(sessionId: UUID) async throws -> Data {
        
        let configuration = try await core.getCurrentConfiguration(id: sessionId)
        
        guard let state = configuration.state else {
            throw RatchetError.stateUninitialized
        }
        guard let cipherText = state.messageCiphertext else {
            throw RatchetError.missingCipherText
        }
        return cipherText
    }
    
    /// Sets the MLKEM ciphertext in the session state.
    ///
    /// The ciphertext is the post-quantum key exchange ciphertext from the PQXDH handshake.
    /// Setting this value updates the session state and persists it through the delegate.
    ///
    /// ## Use Cases
    /// - **External Handshake**: Set the ciphertext when performing the handshake externally
    /// - **State Restoration**: Restore the ciphertext when recovering a session state
    /// - **Custom Workflows**: Manually set the ciphertext for advanced use cases
    ///
    /// ## Side Effects
    /// This method mutates the session state:
    /// - Updates the message ciphertext in the session state
    /// - Persists state through the delegate
    ///
    /// ## Example
    /// ```swift
    /// // Set the ciphertext for a session (e.g., from external handshake)
    /// try await manager.setCipherText(
    ///     sessionId: sessionId,
    ///     cipherText: mlkemCiphertext
    /// )
    /// ```
    ///
    /// - Parameters:
    ///   - sessionId: The UUID of the session.
    ///   - cipherText: The MLKEM ciphertext data to store in the session state.
    /// - Throws:
    ///   - `RatchetError.missingConfiguration`: If the session is not found.
    ///   - `RatchetError.stateUninitialized`: If the session state is not initialized.
    ///
    /// - Important: This method updates and persists the session state. The ciphertext should
    ///   be the MLKEM ciphertext from the PQXDH key exchange handshake.
    ///
    /// - Warning: **This method should only be used when NOT encrypting/decrypting messages via
    ///   `ratchetEncrypt`/`ratchetDecrypt`.** These methods (`deriveMessageKey`, `deriveReceivedMessageKey`,
    ///   `getSentMessageNumber`, `getReceivedMessageNumber`, `setCipherText`, `getCipherText`) are
    ///   designed for external key derivation workflows in `RatchetKeyStateManager`.
    ///   Do not mix these methods with the standard encryption/decryption API, as this may cause state
    ///   inconsistencies and security issues.
    public func setCipherText(sessionId: UUID, cipherText: Data) async throws {
        
        var configuration = try await core.getCurrentConfiguration(id: sessionId)
        
        guard var state = configuration.state else {
            throw RatchetError.stateUninitialized
        }
        
        state = await state.updateCiphertext(cipherText)
        configuration.state = state
        try await core.updateSessionIdentity(configuration: configuration, persist: true)
    }
    
    /// Gets the current sent message number (0-based index) for the specified session.
    ///
    /// - Parameter sessionId: The UUID of the session.
    /// - Returns: The current sent message number (0-based index).
    /// - Throws:
    ///   - `RatchetError.missingConfiguration`: If the session is not found.
    ///   - `RatchetError.stateUninitialized`: If the session state is not initialized.
    ///
    /// - Warning: **This method should only be used when NOT encrypting/decrypting messages via
    ///   `ratchetEncrypt`/`ratchetDecrypt`.** These methods (`deriveMessageKey`, `deriveReceivedMessageKey`,
    ///   `getSentMessageNumber`, `getReceivedMessageNumber`, `setCipherText`, `getCipherText`) are
    ///   designed for external key derivation workflows in `RatchetKeyStateManager`.
    ///   Do not mix these methods with the standard encryption/decryption API, as this may cause state
    ///   inconsistencies and security issues.
    public func getSentMessageNumber(sessionId: UUID) async throws -> Int {
        let configuration = try await core.getCurrentConfiguration(id: sessionId)
        
        guard let state = configuration.state else {
            throw RatchetError.stateUninitialized
        }
        
        return state.sentMessagesCount
    }
    
    /// Gets the current received message number (0-based index) for the specified session.
    ///
    /// - Parameter sessionId: The UUID of the session.
    /// - Returns: The current received message number (0-based index).
    /// - Throws:
    ///   - `RatchetError.missingConfiguration`: If the session is not found.
    ///   - `RatchetError.stateUninitialized`: If the session state is not initialized.
    ///
    /// - Warning: **This method should only be used when NOT encrypting/decrypting messages via
    ///   `ratchetEncrypt`/`ratchetDecrypt`.** These methods (`deriveMessageKey`, `deriveReceivedMessageKey`,
    ///   `getSentMessageNumber`, `getReceivedMessageNumber`, `setCipherText`, `getCipherText`) are
    ///   designed for external key derivation workflows in `RatchetKeyStateManager`.
    ///   Do not mix these methods with the standard encryption/decryption API, as this may cause state
    ///   inconsistencies and security issues.
    public func getReceivedMessageNumber(sessionId: UUID) async throws -> Int {
        let configuration = try await core.getCurrentConfiguration(id: sessionId)
        
        guard let state = configuration.state else {
            throw RatchetError.stateUninitialized
        }
        
        return state.receivedMessagesCount
    }
}
