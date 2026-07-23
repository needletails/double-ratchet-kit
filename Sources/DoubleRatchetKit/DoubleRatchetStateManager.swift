//
//  DoubleRatchetStateManager.swift
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

/*
 # Double Ratchet API Overview
 
 This module implements the **Double Ratchet Algorithm**, which provides *asynchronous forward secrecy* and *post-compromise security* for secure messaging, per the public Double Ratchet specification:
 
 📄 Specification: https://signal.org/docs/specifications/doubleratchet/doubleratchet.pdf
 
 The Double Ratchet combines a **Diffie-Hellman (DH) ratchet** and **symmetric-key ratchets** to derive message keys that change with every message. It ensures that compromise of current or past keys does not reveal other session messages.
 
 ## Core Features
 
 1. **Header Encryption (HE) Variant**
 This implementation includes *header encryption*, which encrypts message headers (e.g., message counters, key IDs) under the current sending header key (`HKs`). This protects metadata against passive traffic analysis. See the `encryptHeader` and `decryptHeader` methods for details.
 
 2. **Skipped Message Key Management**
 To support out-of-order message receipt, skipped message keys are temporarily stored. To mitigate denial-of-service (DoS) and compromise risks:
 - A cap is placed on the number of stored skipped keys per session (e.g., 100).
 - Keys are purged after timeouts or event-based thresholds (e.g., number of received messages).
 
 3. **Deferred DH Ratchet Key Generation**
 As an optimization, the generation of new DH ratchet keys can be deferred until a message is actually sent. This slightly increases security by reducing the window in which private keys exist.
 
 4. **Post-Compromise Recovery**
 Even if a party is compromised (e.g., key leak or device breach), the Double Ratchet ensures that new messages are still secure once the ratchet advances. However, active attacks can persist unless new identity keys and devices are re-established.
 
 5. **Post-Quantum X3DH (PQXDH) Integration**
 This Double Ratchet is designed to work with **PQXDH**, a post-quantum secure version of X3DH for initial key agreement:
 - `SK` from PQXDH is used as the initial root key.
 - `AD` (associated data) from PQXDH is passed to message encryption/decryption.
 - Bob's signed prekey (SPKB) becomes the initial DH ratchet public key.
 - Alice's first Double Ratchet message includes the PQXDH initial ciphertext.
 
 🔒 PQXDH Specification: https://signal.org/docs/specifications/pqxdh/
 
 ## Key Components
 
 - `DoubleRatchetStateManager`: Core ratchet state machine. Handles key rotation, message counters, and skipped key pruning.
 - `encryptHeader`: Serializes and encrypts the message header under the current header key (HKs).
 - `decryptHeader`: Decrypts the header using current, next, or skipped header keys. May trigger a DH ratchet step.
 
 ## Operational & Security Considerations
 
 - Bounded header-gap scanning: `decryptHeader` tries skipped header keys, then the current header key, and then advances the header key iteratively up to `maxSkippedMessageKeys`. This supports large out-of-order gaps while keeping per-message work bounded.
 - Error surface: Internal crypto failures surface as `CryptoKitError` or specific `RatchetError` values (e.g., `missingConfiguration`, `receivingHeaderKeyIsNil`, `maxSkippedHeadersExceeded`). Callers should avoid exposing detailed crypto errors to untrusted clients.
 - Logging: Do not log key material or ciphertext in production. Any prints in this file are intended for debugging and must be disabled in production builds.
 
 ## References
 
 - Double Ratchet Specification: https://signal.org/docs/specifications/doubleratchet/
 - PQXDH Specification: https://signal.org/docs/specifications/pqxdh/
 - X3DH (original): https://signal.org/docs/specifications/x3dh/
 */

/* INITIAL MESSAGE (Handshake Phase)
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

import Foundation
import BinaryCodable
import NeedleTailCrypto
import NeedleTailLogger

/// An actor that manages the cryptographic state for secure messaging using the Double Ratchet algorithm.
///
/// ## Overview
/// Provides a NeedleTails Double Ratchet with header encryption and PQXDH-style
/// integration for asynchronous forward secrecy and post‑compromise security.
/// Combines a Diffie‑Hellman ratchet with symmetric‑key ratchets so keys change
/// per message. Influenced by public specifications; not wire-compatible with
/// third-party messaging clients.
///
/// - Double Ratchet reference: https://signal.org/docs/specifications/doubleratchet/
/// - PQXDH reference: https://signal.org/docs/specifications/pqxdh/
/// - X3DH reference: https://signal.org/docs/specifications/x3dh/
///
/// ## Core Features
/// - Header Encryption (HE): Encrypts headers under the sending header key (`HKs`).
/// - Skipped Keys: Bounded storage and lookup for skipped message/header keys to support out‑of‑order delivery.
/// - Deferred DH: Generates DH ratchet keys only when needed.
/// - Post‑Compromise Recovery: Security resumes after ratchet advancement.
/// - PQXDH Integration: Hybrid classical + post‑quantum handshake.
///
/// ## Operational & Security Considerations
/// - Bounded header‑gap scanning: `decryptHeader` tries skipped header keys, then current header
///   key, then iteratively advances up to `maxSkippedMessageKeys`.
/// - Error surface: Internal errors surface as `CryptoKitError` or `RatchetError`
///   (e.g., `missingConfiguration`, `receivingHeaderKeyIsNil`, `maxSkippedHeadersExceeded`).
/// - Logging: Avoid logging key material or ciphertext in production builds.
///
/// - Note: Keep `RatchetState` in sync and persisted via `updateSessionIdentity`.
public actor DoubleRatchetStateManager<Hash: HashFunction & Sendable> {
    
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
    
    /// Internal cryptographic utility object.
    private let crypto = NeedleTailCrypto()
    private var logger: NeedleTailLogger
    /// Tracks whether `shutdown()` has been called.
    private nonisolated(unsafe) var didShutdown = false
    
    private let core: RatchetStateCore<Hash>
    
    /// The delegate for session identity management.
    ///
    /// The delegate handles persistence of session identities and one-time key management.
    /// Set this property using `setDelegate(_:)` method.
    ///
    /// - SeeAlso: `SessionIdentityDelegate` protocol
    /// - SeeAlso: `setDelegate(_:)` method
    public weak var delegate: SessionIdentityDelegate?
    
    /// Sets the delegate for session identity management.
    ///
    /// The delegate is responsible for:
    /// - Persisting session identities to storage via `updateSessionIdentity(_:)`
    /// - Fetching one-time private keys by ID via `fetchOneTimePrivateKey(_:)`
    /// - Managing one-time key rotation via `updateOneTimeKey(remove:)`
    ///
    /// - Parameter delegate: An object conforming to `SessionIdentityDelegate`.
    ///   Pass `nil` to remove the current delegate.
    ///
    /// - Important: The delegate should be set before calling initialization methods
    ///   if you want session state to be persisted automatically. Without a delegate,
    ///   session state will only exist in memory and will be lost when the manager is deinitialized.
    ///
    /// ## Example
    /// ```swift
    /// let manager = DoubleRatchetStateManager<SHA256>(executor: executor, logger: logger)
    /// manager.setDelegate(MySessionDelegate())
    ///
    /// // Now session state will be persisted automatically
    /// try await manager.senderInitialization(...)
    /// ```
    ///
    /// - SeeAlso: `SessionIdentityDelegate` protocol for implementation details.
    public func setDelegate(_ delegate: SessionIdentityDelegate) async {
        self.delegate = delegate
        await core.setDelegate(delegate)
    }
    
    /// Enable or disable strict one-time-prekey (OTK) consistency enforcement.
    ///
    /// - Parameter value: `true` to enable strict validation, `false` to disable.
    ///
    /// - SeeAlso: `enforceOTKConsistency` for detailed documentation.
    public func setEnforceOTKConsistency(_ value: Bool) async {
        await core.setEnforceOTKConsistency(value)
    }
    
    // MARK: - Initialization
    
    /// Initializes the ratchet state manager.
    ///
    /// Creates a new instance of the ratchet state manager with the specified executor,
    /// logger, and optional custom configuration.
    ///
    /// - Parameters:
    ///   - executor: A `SerialExecutor` used to coordinate concurrent operations within the actor.
    ///     This executor serializes all actor-isolated operations to ensure thread safety.
    ///   - logger: The logger instance for debugging and monitoring. Defaults to a new `NeedleTailLogger`.
    ///     The initial log level is set to `.trace` for maximum verbosity.
    ///   - ratchetConfiguration: Optional custom configuration for the Double Ratchet protocol.
    ///     If `nil`, uses the default configuration with:
    ///     - `maxSkippedMessageKeys: 100`
    ///     - Standard key derivation data (`messageKeyData`, `chainKeyData`, `rootKeyData`)
    ///     - Default associated data: "DoubleRatchetKit"
    ///
    /// ## Default Configuration
    /// The default configuration is suitable for most use cases and provides:
    /// - Support for up to 100 skipped messages (out-of-order delivery)
    /// - Standard key derivation parameters
    /// - Appropriate associated data for message authentication
    ///
    /// ## Custom Configuration
    /// Use a custom `ratchetConfiguration` only if you need to:
    /// - Modify protocol parameters for compatibility with other implementations
    /// - Adjust security parameters (e.g., reduce `maxSkippedMessageKeys` for memory constraints)
    /// - Change key derivation data for specific security requirements
    ///
    /// - Note: Changing the configuration may affect compatibility with other Double Ratchet
    ///   implementations. Use the default configuration unless you have specific requirements.
    ///
    /// ## Example
    /// ```swift
    /// // Default configuration
    /// let manager = DoubleRatchetStateManager<SHA256>(
    ///     executor: executor,
    ///     logger: logger
    /// )
    ///
    /// // Custom configuration
    /// let customConfig = RatchetConfiguration(
    ///     messageKeyData: Data([0x00]),
    ///     chainKeyData: Data([0x01]),
    ///     rootKeyData: Data([0x02, 0x03]),
    ///     associatedData: "MyApp".data(using: .ascii)!,
    ///     maxSkippedMessageKeys: 100
    /// )
    /// let manager = DoubleRatchetStateManager<SHA256>(
    ///     executor: executor,
    ///     logger: logger,
    ///     ratchetConfiguration: customConfig
    /// )
    /// ```
    public init(
        executor: any SerialExecutor,
        logger: NeedleTailLogger = NeedleTailLogger(),
        ratchetConfiguration: RatchetConfiguration? = nil
    ) {
        self.executor = executor
        self.logger = logger
        core = RatchetStateCore<Hash>(
            executor: executor,
            logger: logger,
            ratchetConfiguration: ratchetConfiguration)
    }
    
    deinit {
        precondition(didShutdown, "⛔️ DoubleRatchetStateManager was deinitialized without calling shutdown(). ")
    }
    
    /// Sets the logging level for the ratchet state manager.
    ///
    /// Adjusts the verbosity of logging output from the ratchet state manager.
    /// The default log level is `.trace` for maximum verbosity during development.
    ///
    /// - Parameter level: The desired log level. Available levels (from most to least verbose):
    ///   - `.trace`: Most verbose, includes all debug information, key derivations, and state transitions
    ///   - `.debug`: Debug information including initialization, encryption/decryption operations
    ///   - `.info`: Informational messages about session management and key operations
    ///   - `.warning`: Warning messages about potential issues (e.g., missing keys, state inconsistencies)
    ///   - `.error`: Only error messages for failures and exceptions
    ///
    /// ## Performance Considerations
    /// - **Development**: Use `.trace` or `.debug` for detailed debugging
    /// - **Production**: Use `.info` or `.warning` to reduce logging overhead
    /// - **Minimal Logging**: Use `.error` for production environments with strict performance requirements
    ///
    /// ## Example
    /// ```swift
    /// // Development: maximum verbosity
    /// await manager.setLogLevel(.trace)
    ///
    /// // Production: minimal logging
    /// await manager.setLogLevel(.warning)
    ///
    /// // Errors only
    /// await manager.setLogLevel(.error)
    /// ```
    ///
    /// - Note: The log level affects all logging operations within the ratchet state manager.
    ///   Changing the log level does not affect logs from other components.
    public func setLogLevel(_ level: Level) async {
        logger.setLogLevel(level)
    }
    
    /// Shuts down the ratchet state manager and persists all session states.
    ///
    /// ## Lifecycle
    /// This method must be called before the manager is deinitialized. It:
    /// - Persists all session states to storage via the delegate
    /// - Clears in-memory session configurations
    /// - Marks the manager as shut down
    ///
    /// ## When to Call
    /// - Before the manager goes out of scope
    /// - Before application termination
    /// - When switching to a new manager instance
    /// - In `defer` blocks to ensure cleanup even if errors occur
    ///
    /// ## Important
    /// - The manager cannot be used after `shutdown()` is called
    /// - If `shutdown()` is not called, the `deinit` will crash with a precondition failure
    /// - This method is safe to call multiple times (idempotent after first call)
    ///
    /// ## Example
    /// ```swift
    /// let manager = DoubleRatchetStateManager<SHA256>(executor: executor, logger: logger)
    /// defer {
    ///     try? await manager.shutdown()
    /// }
    /// // ... use manager
    /// ```
    ///
    /// - Throws: An error if session state persistence fails through the delegate.
    public func shutdown() async throws {
        try await core.shutdown()
        didShutdown = true
    }

    /// Evicts the in-memory session configuration for the specified session, if present.
    ///
    /// ## When to Call
    /// Call this after rolling back a persisted `SessionIdentity` following a failed
    /// encrypt/decrypt attempt. `loadConfigurations` persists working mutations during an
    /// attempt, so after the caller restores the persisted row to its pre-attempt data the
    /// cached in-memory configuration still holds the failed attempt's state (for example a
    /// stale local one-time key or a partially advanced ratchet). Evicting it forces the next
    /// operation on this session to rebuild deterministically from the restored row — for a
    /// state-less identity that means a clean PQXDH bootstrap from the incoming header.
    ///
    /// Without eviction, a rolled-back session can be permanently poisoned: the cached
    /// configuration is reused on every retry, key changes on the local side are not
    /// re-derived, and decryption fails indefinitely.
    ///
    /// - Parameter id: The UUID of the session whose cached configuration should be discarded.
    public func evictSessionConfiguration(_ id: UUID) async {
        await core.removeConfiguration(id: id)
        logger.log(level: .debug, message: "Evicted in-memory session configuration for \(id)")
    }
    
    
    /// Load or create session configuration and ratchet state as needed.
    /// - Parameters:
    ///   - sessionIdentity: Identity of the communicating peer.
    ///   - sessionSymmetricKey: Symmetric key for deriving state secrets.
    ///   - messageType: Indicates if the context is for sending or receiving.
    private func loadConfigurations(
        sessionIdentity: SessionIdentity,
        sessionSymmetricKey: SymmetricKey,
        messageType: RatchetStateCore<Hash>.MessageType,
    ) async throws {
        
        func checkSendingKeyChanges(state: RatchetState, keys: RatchetStateCore<Hash>.EncryptionKeys) -> Bool {
            if state.localLongTermPrivateKey != keys.localLongTermPrivateKey {
                logger.log(level: .trace, message: "Sending long term key has changed")
                return true
            }
            
            if state.localOneTimePrivateKey != keys.localOneTimePrivateKey {
                logger.log(level: .trace, message: "Sending one time key has changed")
                return true
            }
            
            if state.localMLKEMPrivateKey != keys.localMLKEMPrivateKey {
                logger.log(level: .trace, message: "Sending mlKEM key has changed")
                return true
            }
            return false
        }
        
        func checkReceivingKeyChanges(state: RatchetState, header: EncryptedHeader) -> Bool {
            hasReceivingKeyChanges(state: state, header: header)
        }
        
        // Detects when the caller-supplied local private keys differ from the ones bound to
        // the cached state (e.g. the local party rotated keys while the session was persisted).
        func checkLocalKeyChanges(state: RatchetState, keys: RatchetStateCore<Hash>.EncryptionKeys) -> Bool {
            if state.localLongTermPrivateKey != keys.localLongTermPrivateKey {
                logger.log(level: .trace, message: "Local long term key has changed")
                return true
            }
            if state.localOneTimePrivateKey?.id != keys.localOneTimePrivateKey?.id {
                logger.log(level: .trace, message: "Local one time key has changed")
                return true
            }
            if state.localMLKEMPrivateKey.id != keys.localMLKEMPrivateKey.id {
                logger.log(level: .trace, message: "Local mlKEM key has changed")
                return true
            }
            return false
        }
        
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
                var changesDetected = false
                defer {
                    changesDetected = false
                }
                
                changesDetected = checkSendingKeyChanges(state: state, keys: keys)
                
                if changesDetected {
                    currentProps.setLongTermPublicKey(keys.remoteLongTermPublicKey)
                    if let key = keys.remoteOneTimePublicKey {
                        currentProps.setOneTimePublicKey(key)
                    }
                    currentProps.setMLKEMPublicKey(keys.remoteMLKEMPublicKey)
                    currentProps.state = await currentProps.state?.updateRemoteLongTermPublicKey(keys.remoteLongTermPublicKey)
                    currentProps.state = await currentProps.state?.updateRemoteOneTimePublicKey(keys.remoteOneTimePublicKey)
                    currentProps.state = await currentProps.state?.updateRemoteMLKEMPublicKey(keys.remoteMLKEMPublicKey)
                    currentProps.longTermPublicKey = keys.remoteLongTermPublicKey
                    currentProps.oneTimePublicKey = keys.remoteOneTimePublicKey
                    currentProps.mlKEMPublicKey = keys.remoteMLKEMPublicKey
                    
                    configuration.state = currentProps.state
                    
                    currentProps.state = try await diffieHellmanRatchet(
                        localKeys: LocalKeys(
                            longTerm: .init(keys.localLongTermPrivateKey),
                            oneTime: keys.localOneTimePrivateKey,
                            mlKEM: keys.localMLKEMPrivateKey),
                        configuration: configuration)
                    
                } else if let state = currentProps.state, state.sendingHandshakeFinished == false {
                    // Do intial sending setup and update the state with the ciphertext and sending key
                    
                    var chainKey: SymmetricKey
                    
                    if let sendingKey = state.sendingKey {
                        chainKey = sendingKey
                    } else {
                        guard let rootKey = state.rootKey else {
                            throw RatchetError.rootKeyIsNil
                        }
                        // if we have a root key but not a sending key create a sending key from the root key
                        chainKey = try await core.deriveChainKey(
                            from: rootKey,
                            configuration: core.defaultRatchetConfiguration,
                        )
                    }
                    currentProps.state = await state.updateSendingKey(chainKey)
                }
            case .receiving(let keys):
                guard let header = keys.header else {
                    throw RatchetError.missingConfiguration
                }
                if let state = currentProps.state {
                    // Adopt caller-supplied local keys when either side's keys changed;
                    // a rotated local key that is never adopted poisons every future decrypt.
                    let remoteChanged = checkReceivingKeyChanges(state: state, header: header)
                    let localChanged = checkLocalKeyChanges(state: state, keys: keys)
                    
                    if remoteChanged || localChanged {
                        currentProps.state = await currentProps.state?.updateLocalLongTermPrivateKey(keys.localLongTermPrivateKey)
                        currentProps.state = await currentProps.state?.updateLocalOneTimePrivateKey(keys.localOneTimePrivateKey)
                        currentProps.state = await currentProps.state?.updateLocalMLKEMPrivateKey(keys.localMLKEMPrivateKey)
                    }
                } else {
                    // Cached configuration exists but its state is nil (e.g. a prior attempt
                    // failed before initialization completed). Rebuild from the incoming header
                    // exactly like the cache-miss path instead of leaving the session unusable.
                    let state = try await core.setState(for: messageType, configuration: configuration)
                    currentProps.state = state
                }
            }
            
            configuration.state = currentProps.state
            try await sessionIdentity.updateIdentityProps(symmetricKey: sessionSymmetricKey, props: currentProps)
            
            configuration.sessionIdentity = sessionIdentity
            configuration.sessionSymmetricKey = sessionSymmetricKey
            
            // In-memory registration only: initialization must not persist mid-attempt.
            // Durable commits happen at the success points of ratchetEncrypt/ratchetDecrypt.
            try await core.updateSessionIdentity(configuration: configuration)
        } else {
            logger.log(level: .trace, message: "Session not initialized yet, creating state for ratchet")
            var configuration = RatchetStateCore<Hash>.SessionConfiguration(
                sessionIdentity: sessionIdentity,
                sessionSymmetricKey: sessionSymmetricKey)
            
            guard var props = await sessionIdentity.props(symmetricKey: sessionSymmetricKey) else {
                throw RatchetError.missingProps
            }
            if var state = props.state {
                var changesDetected = false
                defer {
                    changesDetected = false
                }
                
                // If this session identity is not loaded into memory we may have rotated key before loaded; therefore we need to update session identity. If not we assure we are using the keys received from the consumer when they feed the session identity.
                switch messageType {
                case let .sending(keys):
                    
                    changesDetected = checkSendingKeyChanges(state: state, keys: keys)
                    
                    if changesDetected {
                        props.setLongTermPublicKey(keys.remoteLongTermPublicKey)
                        if let key = keys.remoteOneTimePublicKey {
                            props.setOneTimePublicKey(key)
                        }
                        
                        props.setMLKEMPublicKey(keys.remoteMLKEMPublicKey)
                        
                        state = await state.updateRemoteLongTermPublicKey(keys.remoteLongTermPublicKey)
                        state = await state.updateRemoteOneTimePublicKey(keys.remoteOneTimePublicKey)
                        state = await state.updateRemoteMLKEMPublicKey(keys.remoteMLKEMPublicKey)
                        
                        configuration.state = state
                        state = try await diffieHellmanRatchet(
                            localKeys: LocalKeys(
                                longTerm: .init(keys.localLongTermPrivateKey),
                                oneTime: keys.localOneTimePrivateKey,
                                mlKEM: keys.localMLKEMPrivateKey),
                            configuration: configuration)
                    } else if state.sendingHandshakeFinished == false, state.sendingKey == nil {
                        // Responder sending bootstrap on cache miss: a persisted responder state
                        // (created by the receiving path) has a root key but no sending chain yet.
                        // Mirror the in-memory branch so the first reply doesn't fail with sendingKeyIsNil.
                        guard let rootKey = state.rootKey else {
                            throw RatchetError.rootKeyIsNil
                        }
                        let chainKey = try await core.deriveChainKey(
                            from: rootKey,
                            configuration: core.defaultRatchetConfiguration,
                        )
                        state = await state.updateSendingKey(chainKey)
                    }
                case .receiving(let keys):
                    guard let header = keys.header else {
                        throw RatchetError.missingConfiguration
                    }
                    let remoteChanged = checkReceivingKeyChanges(state: state, header: header)
                    let localChanged = checkLocalKeyChanges(state: state, keys: keys)
                    changesDetected = remoteChanged || localChanged
                    
                    if changesDetected {
                        
                        state = await state.updateLocalLongTermPrivateKey(keys.localLongTermPrivateKey)
                        state = await state.updateLocalOneTimePrivateKey(keys.localOneTimePrivateKey)
                        state = await state.updateLocalMLKEMPrivateKey(keys.localMLKEMPrivateKey)
                    }
                }
                configuration.state = state
            } else {
                let state = try await core.setState(for: messageType, configuration: configuration)
                props.state = state
                configuration.sessionIdentity = sessionIdentity
                configuration.state = state
                try await core.updateSessionIdentity(configuration: configuration)
            }
            
            try await sessionIdentity.updateIdentityProps(symmetricKey: sessionSymmetricKey, props: props)
            // In-memory registration only: initialization must not persist mid-attempt.
            // Durable commits happen at the success points of ratchetEncrypt/ratchetDecrypt.
            try await core.updateSessionIdentity(configuration: configuration)
            await core.setSessionIdentity(configuration: configuration)
        }
    }
    
    private func hasReceivingKeyChanges(state: RatchetState, header: EncryptedHeader) -> Bool {
        if state.remoteLongTermPublicKey != header.remoteLongTermPublicKey {
            logger.log(level: .trace, message: "Receiving long term key has changed")
            return true
        }
        
        if state.remoteOneTimePublicKey != header.remoteOneTimePublicKey {
            logger.log(level: .trace, message: "Receiving one time key has changed")
            return true
        }
        
        if state.remoteMLKEMPublicKey != header.remoteMLKEMPublicKey {
            logger.log(level: .trace, message: "Receiving mlKEM key has changed")
            return true
        }
        return false
    }
    
    // MARK: - Public Interface
    
    /// Initializes a new sending session using the provided cryptographic identities and keys.
    ///
    /// This method prepares the local device for sending encrypted messages in a new session.
    /// It loads and validates all necessary cryptographic keys, binds them to the session identity,
    /// and prepares the ratchet state for outbound communication.
    ///
    /// ## Initialization Semantics
    /// - **First call**: Initializes a new session with the provided keys.
    /// - **Subsequent calls**: If called again for the same session:
    ///   - Updates state if keys have changed (triggers a Diffie-Hellman ratchet step)
    ///   - Supports key rotation scenarios where keys may change while session is persisted
    ///   - Completes handshake setup if it was previously incomplete
    ///
    /// ## Key Rotation
    /// If keys change while a session is persisted but not loaded in memory, calling this method
    /// again with new keys will detect the change and perform a DH ratchet step to establish new
    /// shared secrets with the updated keys.
    ///
    /// - Parameters:
    ///   - sessionIdentity: A unique identity used to bind the session cryptographically (e.g. user or device identity).
    ///   - sessionSymmetricKey: A symmetric key used to encrypt metadata or protect session state.
    ///   - remoteKeys: The recipient's public keys, including long-term, one-time, and MLKEM keys.
    ///   - localKeys: The sender's private keys, including long-term, one-time, and MLKEM keys.
    /// - Throws: An error if the session cannot be initialized (e.g. invalid keys, storage issues).
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
    
    /// Initializes a receiving session using the initial incoming message and cryptographic identities.
    ///
    /// This method processes the first received message in a new session, establishing shared secrets
    /// and preparing the ratchet state for continued secure communication.
    ///
    /// ## Initialization Semantics
    /// - **First call**: Initializes a new session with the provided header and keys.
    /// - **Subsequent calls**: If called again for the same session:
    ///   - Updates state if keys have changed (triggers a Diffie-Hellman ratchet step)
    ///   - Handles out-of-order message headers by updating state accordingly
    ///   - Supports key rotation scenarios where keys may change while session is persisted
    ///
    /// ## Out-of-Order Message Handling
    /// This method can be called multiple times with different headers for the same session to handle
    /// out-of-order message delivery. Each header may contain different keys, and the method will
    /// detect changes and update the ratchet state accordingly.
    ///
    /// - Parameters:
    ///   - sessionIdentity: A unique identity used to bind the session cryptographically (e.g. user or device identity).
    ///   - sessionSymmetricKey: A symmetric key used to decrypt or authenticate session metadata.
    ///   - header: The `EncryptedHeader` received from the sender. This header contains the sender's
    ///     public keys and encrypted metadata needed to establish the session.
    ///   - localKeys: The recipient's private keys, including long-term, one-time, and MLKEM keys.
    /// - Throws: An error if the message cannot be decrypted or the session cannot be initialized.
    ///
    /// - Note: For handling out-of-order messages, you may call this method multiple times with different
    ///   headers. The method will detect key changes and update the ratchet state as needed.
    public func recipientInitialization(
        sessionIdentity: SessionIdentity,
        sessionSymmetricKey: SymmetricKey,
        header: EncryptedHeader,
        localKeys: LocalKeys
    ) async throws {
        try await loadConfigurations(
            sessionIdentity: sessionIdentity,
            sessionSymmetricKey: sessionSymmetricKey,
            messageType: .receiving(.init(header: header, local: localKeys)))
    }

    /// Represents a Diffie-Hellman key pair used for Curve25519.
    private struct DiffieHellmanKeyPair: Sendable {
        let privateKey: Curve25519.KeyAgreement.PrivateKey
        let publicKey: Curve25519.KeyAgreement.PublicKey
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
        configuration: RatchetConfiguration,
    ) async throws -> SymmetricKey {
        try await crypto.deriveHKDFSymmetricKey(
            hash: Hash.self,
            from: sharedSecret,
            with: symmetricKey,
            sharedInfo: configuration.rootKeyData)
    }
    
    /// Encrypts a plaintext message using the post-quantum hybrid Double Ratchet protocol.
    ///
    /// This method generates a `RatchetMessage` by performing a hybrid (PQXDH) key derivation using both
    /// classical (Curve25519) and post-quantum (MLKEM1024) primitives, establishing ephemeral symmetric keys
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
    ///   After message encryption, clients should remove any consumed one‑time keys via delegate or
    ///   persistence hooks to preserve forward secrecy and prevent key reuse.
    ///
    /// - Warning:
    ///   The method is sensitive to nonce construction, key reuse, and state consistency. Failure to meet
    ///   these constraints may compromise confidentiality or forward secrecy.
    ///
    /// - SeeAlso:
    ///   `derivePQXDHFinalKey`, `encryptHeader`, `updateSessionIdentity`, `RatchetMessage`
    public func ratchetEncrypt(plainText: Data, sessionId: UUID) async throws -> RatchetMessage {
        logger.log(level: .trace, message: "Ratchet encrypt started")
        
        var configuration = try await core.getCurrentConfiguration(id: sessionId)
        
        guard var state = configuration.state else {
            throw RatchetError.stateUninitialized
        }
        
        // Per-turn hybrid sending ratchet step: due whenever the peer's ratchet key differs
        // from the one our current sending chain is keyed against (they took a turn, or — for
        // the responder's first reply — we have their bootstrap ratchet key but have never
        // stepped). The initiator's first send is excluded automatically: it has no remote
        // ratchet key yet, so it stays on the PQXDH bootstrap lane. Bursts in one direction
        // leave the keys equal and reuse the chain — no step per message.
        if state.remoteRatchetPublicKey != nil,
           state.remoteRatchetPublicKey != state.sendingChainRemoteRatchetKey,
           state.remoteRatchetKEMPublicKey != nil,
           state.rootKey != nil {
            state = try await performSendingRatchetStep(on: state)
        }
        
        // Step 2: Construct ratchet header metadata (per-turn ratchet fields ride inside the
        // encrypted header body, preserving metadata protection).
        var localRatchetPublicKey: Data?
        if let ratchetPrivate = state.localRatchetPrivateKey {
            localRatchetPublicKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: ratchetPrivate)
                .publicKey.rawRepresentation
        }
        var localRatchetKEMPublicKey: Data?
        if let ratchetKEMPrivate = state.localRatchetKEMPrivateKey {
            localRatchetKEMPublicKey = try ratchetKEMPrivate.decodeMLKem1024().publicKey.rawRepresentation
        }
        let messageHeader = MessageHeader(
            previousChainLength: state.previousMessagesCount,
            messageNumber: state.sentMessagesCount,
            ratchetPublicKey: localRatchetPublicKey,
            ratchetKEMPublicKey: localRatchetKEMPublicKey,
            ratchetKEMCiphertext: state.localRatchetKEMCiphertext)
        
        if !state.sendingHandshakeFinished {
            // Optional enforcement: if the peer advertised an OTK in state but we don't have
            // our local matching piece, fail fast when enforcement is enabled.
            if await core.enforceOTKConsistency {
                let wantsOTK = (state.remoteOneTimePublicKey != nil)
                if wantsOTK && state.localOneTimePrivateKey == nil {
                    throw RatchetError.missingOneTimeKey
                }
            }
            // Step 3: Derive symmetric header encryption key using hybrid PQXDH.
            let headerCipher = try await core.derivePQXDHFinalKey(
                localLongTermPrivateKey: state.localLongTermPrivateKey,
                localOneTimePrivateKey: state.localOneTimePrivateKey,
                remoteLongTermPublicKey: state.remoteLongTermPublicKey,
                remoteOneTimePublicKey: state.remoteOneTimePublicKey,
                remoteMLKEMPublicKey: state.remoteMLKEMPublicKey)
            state = await state.updateHeaderCiphertext(headerCipher.ciphertext)
            state = await state.updateSendingHeaderKey(headerCipher.symmetricKey)
            
        } else {
            // Header-key chains are symmetric HE chains independent of the per-turn DH ratchet;
            // they advance once per message regardless of ratchet steps. The receiver's bounded
            // header-chain scan already handles cross-turn gaps.
            guard let sendingHeaderKey = state.sendingHeaderKey else {
                throw RatchetError.sendingKeyIsNil
            }
            
            let newSendingHeaderKey = try await core.deriveChainKey(
                from: sendingHeaderKey,
                configuration: core.defaultRatchetConfiguration)
            
            state = await state.updateSendingHeaderKey(newSendingHeaderKey)
        }
        
        // Step 5: Reconstruct local public keys to embed into the header.
        let localLongTermPublicKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: state.localLongTermPrivateKey)
            .publicKey.rawRepresentation
        var remoteOneTimePublicKey: RemoteOneTimePublicKey?
        if let localOneTimePrivateKey = state.localOneTimePrivateKey {
            let localOneTimePublicKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: localOneTimePrivateKey.rawRepresentation).publicKey.rawRepresentation
            remoteOneTimePublicKey = try RemoteOneTimePublicKey(id: localOneTimePrivateKey.id, localOneTimePublicKey)
        }
        let localMLKEMPublicKey = try state.localMLKEMPrivateKey.rawRepresentation.decodeMLKem1024()
            .publicKey.rawRepresentation
        let remoteMLKEMPublicKey = try RemoteMLKEMPublicKey(id: state.localMLKEMPrivateKey.id, localMLKEMPublicKey)
        
        configuration.state = state
        
        // Step 6: Encrypt the message header using AEAD.
        let encryptedHeader = try await encryptHeader(
            messageHeader,
            remoteLongTermPublicKey: localLongTermPublicKey,
            remoteOneTimePublicKey: remoteOneTimePublicKey,
            remoteMLKEMPublicKey: remoteMLKEMPublicKey,
            oneTimeKeyId: state.remoteOneTimePublicKey?.id,
            mlKEMOneTimeKeyId: state.remoteMLKEMPublicKey.id,
            configuration: configuration)
        
        guard let sendingKey = state.sendingKey else {
            throw RatchetError.sendingKeyIsNil
        }
        
        // Step 7: Encrypt the payload using AEAD with the current sending key.
        let messageKey = try await core.symmetricKeyRatchet(from: sendingKey)
        
        let payloadAAD = try await payloadAssociatedData(for: encryptedHeader)
        let encryptedData = try encryptPayload(
            plainText,
            using: messageKey,
            associatedData: payloadAAD)
        
        if !state.sendingHandshakeFinished {
            state = await state.updateSendingHandshakeFinished(true)
            logger.log(level: .trace, message: "Initial sending handshake succeeded")
        }
        
        let newChainKey = try await core.deriveChainKey(
            from: sendingKey,
            configuration: core.defaultRatchetConfiguration)
        
        state = await state.updateSendingKey(newChainKey)
        state = await state.incrementSentMessagesCount()
        
        configuration.state = state
        try await core.updateSessionIdentity(configuration: configuration, persist: true)
        
        defer {
            logger.log(level: .trace, message: "Encryption Succeeded")
        }
        
        return RatchetMessage(
            header: encryptedHeader,
            encryptedData: encryptedData)
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
    public func ratchetDecrypt(_ message: RatchetMessage, sessionId: UUID) async throws -> Data {
        logger.log(level: .trace, message: "Ratchet decrypt started")
        
        var configuration = try await core.getCurrentConfiguration(id: sessionId)
        
        guard var state = configuration.state else {
            throw RatchetError.stateUninitialized
        }
        
        // OTK consistency preflight: If header signals an OTK, ensure we have the matching local
        // private key available (hydrate via delegate if possible). If header omits OTK, proceed
        // without contributing any local OTK (no failure when enforcement is off).
        if let otkId = message.header.oneTimeKeyId {
            if state.localOneTimePrivateKey == nil {
                if let fetched = try await delegate?.fetchOneTimePrivateKey(otkId) {
                    state = await state.updateLocalOneTimePrivateKey(fetched)
                    configuration.state = state
                } else if await core.enforceOTKConsistency {
                    throw RatchetError.missingOneTimeKey
                }
            }
        }
        
        if hasReceivingKeyChanges(state: state, header: message.header) {
            configuration.state = state
            state = try await diffieHellmanRatchet(
                header: message.header,
                configuration: configuration,
                persist: false)
            configuration.state = state
        }
        
        // HEADER DECRYPTION PHASE
        if !state.receivingHandshakeFinished {
            
            // If handshake not finished, derive header receiving key using PQXDH final key receiver.
            // This combines multiple DH operations to produce the symmetric key for header encryption.
            let finalHeaderReceivingKey = try await core.derivePQXDHFinalKeyReceiver(
                remoteLongTermPublicKey: state.remoteLongTermPublicKey,
                remoteOneTimePublicKey: state.remoteOneTimePublicKey,
                localLongTermPrivateKey: state.localLongTermPrivateKey,
                localOneTimePrivateKey: state.localOneTimePrivateKey,
                localMLKEMPrivateKey: state.localMLKEMPrivateKey,
                receivedCiphertext: message.header.headerCiphertext)
            
            // Update state with new receiving header key and persist changes.
            state = await state.updateReceivingHeaderKey(finalHeaderReceivingKey)
            configuration.state = state
        } else {
            // If handshake completed, ratchet receiving header key forward to derive next header key.
            if state.headerIndex == 0 {
                guard let receivingHeaderKey = state.receivingHeaderKey else {
                    throw RatchetError.receivingHeaderKeyIsNil
                }
                let newReceivingHeaderKey = try await core.deriveChainKey(from: receivingHeaderKey, configuration: core.defaultRatchetConfiguration)
                state = await state.updateReceivingHeaderKey(newReceivingHeaderKey)
                configuration.state = state
            }
        }
        
        // Decrypt the header now that the appropriate key is available.
        let (header, headerState) = try await decryptHeaderWithWorkingState(
            encryptedHeader: message.header,
            configuration: configuration,
            persistAdvancedState: false)
        state = headerState
        
        // Ensure header was successfully decrypted before continuing.
        guard let decrypted = header.decrypted else {
            throw RatchetError.headerDecryptFailed
        }
        
        // After handshake, advance next receiving header key by ratcheting it forward.
        let nextReceivingHeaderKey = state.nextReceivingHeaderKey ?? state.receivingHeaderKey
        guard let nextReceivingHeaderKey else {
            throw RatchetError.receivingHeaderKeyIsNil
        }
        let newReceivingHeaderKey = try await core.deriveChainKey(from: nextReceivingHeaderKey, configuration: core.defaultRatchetConfiguration)
        state = await state.updateReceivingNextHeaderKey(newReceivingHeaderKey)
        
        // Skipped-key lookup. The chain tag (sender's per-turn ratchet key) disambiguates
        // equal message indices across ratchet turns; legacy stashes and legacy frames both
        // carry nil tags and keep matching each other during the drain.
        if let key = state.skippedMessageKeys.first(where: {
            $0.messageIndex == decrypted.messageNumber &&
            $0.remoteLongTermPublicKey == header.remoteLongTermPublicKey &&
            $0.remoteMLKEMPublicKey == header.remoteMLKEMPublicKey.rawRepresentation &&
            $0.chainRatchetPublicKey == decrypted.ratchetPublicKey
        }) {
            logger.log(level: .trace, message: "Trying skipped message key index \(key.messageIndex)")
            if let oneTimeKey = key.remoteOneTimePublicKey, oneTimeKey != header.remoteOneTimePublicKey?.rawRepresentation {
                throw RatchetError.expiredKey
            }
            let plaintext = try await processFoundMessage(
                ratchetMessage: message,
                usingMessageKey: key.messageKey,
                messageNumber: decrypted.messageNumber)
            state = await state.removeSkippedMessage(key)
            state = await markAlreadyDecrypted(
                decrypted.messageNumber,
                in: state,
                configuration: core.defaultRatchetConfiguration)

            configuration.state = state
            try await core.updateSessionIdentity(configuration: configuration, persist: true)
            return plaintext
        }
        
        // Per-turn hybrid receiving ratchet step: the decrypted header advertises a ratchet
        // key different from the chain we are on, plus a KEM ciphertext we can decapsulate.
        // This works on a fresh initiator too (receiving the responder's first ratcheted
        // reply while `receivingHandshakeFinished` is still false): the bootstrap root from
        // the sender initialization seeds KDF_RK. All mutations stay on the working copy —
        // a mismatched step fails decryption below and is never committed.
        var performedReceivingStep = false
        if let headerRatchetKey = decrypted.ratchetPublicKey,
           headerRatchetKey != state.remoteRatchetPublicKey,
           let headerKEMCiphertext = decrypted.ratchetKEMCiphertext,
           let localRatchetPrivateKey = state.localRatchetPrivateKey,
           let localRatchetKEMPrivateKey = state.localRatchetKEMPrivateKey,
           state.rootKey != nil {
            state = try await performReceivingRatchetStep(
                on: state,
                header: decrypted,
                headerRatchetKey: headerRatchetKey,
                headerKEMCiphertext: headerKEMCiphertext,
                localRatchetPrivateKey: localRatchetPrivateKey,
                localRatchetKEMPrivateKey: localRatchetKEMPrivateKey)
            performedReceivingStep = true
        }
        
        // Gap-fill and prepare MK for current message using a working copy, commit after decrypt
        var preparedMessageKey: SymmetricKey? = nil
        if state.receivingHandshakeFinished {
            (state, preparedMessageKey) = try await deriveMessageKey(
                header: header,
                configuration: core.defaultRatchetConfiguration,
                state: state)
        }
        
        // We then handle decryption logic.. at this point the key order must be in resolved
        // MESSAGE DECRYPTION PHASE
        if !state.receivingHandshakeFinished {
            var chainKey: SymmetricKey
            if state.rootKey == nil {
                if decrypted.messageNumber != 0 {
                    throw RatchetError.initialMessageNotReceived
                }
                // First message after handshake:
                // Derive root and chain keys from PQXDH final key receiver function.
                let finalReceivingKey = try await core.derivePQXDHFinalKeyReceiver(
                    remoteLongTermPublicKey: state.remoteLongTermPublicKey,
                    remoteOneTimePublicKey: state.remoteOneTimePublicKey,
                    localLongTermPrivateKey: state.localLongTermPrivateKey,
                    localOneTimePrivateKey: state.localOneTimePrivateKey,
                    localMLKEMPrivateKey: state.localMLKEMPrivateKey,
                    receivedCiphertext: message.header.messageCiphertext)
                
                if state.messageCiphertext == nil {
                    state = await state.updateCiphertext(message.header.messageCiphertext)
                }
                
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
            
            let messageKey = try await core.symmetricKeyRatchet(from: chainKey)
            let plaintext = try await processFoundMessage(
                ratchetMessage: message,
                usingMessageKey: messageKey,
                messageNumber: decrypted.messageNumber,
            )

            // If an OTK was used for this initial message and enforcement is enabled,
            // consume it via delegate and clear it from state only after auth succeeds.
            if await core.enforceOTKConsistency, let otkId = message.header.oneTimeKeyId {
                await delegate?.updateOneTimeKey(remove: otkId)
                state = await state.updateLocalOneTimePrivateKey(nil)
            }

            // Adopt the initiator's per-turn ratchet publics from the bootstrap header:
            // our first reply performs the first full sending ratchet step against them.
            if let headerRatchetKey = decrypted.ratchetPublicKey {
                state = await state.updateRemoteRatchetPublicKey(headerRatchetKey)
            }
            if let headerRatchetKEMKey = decrypted.ratchetKEMPublicKey {
                state = await state.updateRemoteRatchetKEMPublicKey(headerRatchetKEMKey)
            }

            state = await state.incrementReceivedMessagesCount()
            state = await state.updateReceivingHandshakeFinished(true)

            configuration.state = state
            try await core.updateSessionIdentity(configuration: configuration, persist: true)
            logger.log(level: .trace, message: "Initial receiving handshake succeeded")
            return plaintext
        } else {
            // Subsequent messages after handshake, decrypt using prepared MK, then commit prepared state exactly once
            guard let messageKey = preparedMessageKey else { throw RatchetError.decryptionFailed }
            // Try decrypt without committing state
            let plaintext = try await processFoundMessage(
                ratchetMessage: message,
                usingMessageKey: messageKey,
                messageNumber: decrypted.messageNumber)
            // A receiving ratchet step that completed the initial handshake still owes the
            // one-time-key consumption the bootstrap branch would have performed.
            if performedReceivingStep, await core.enforceOTKConsistency, let otkId = message.header.oneTimeKeyId {
                await delegate?.updateOneTimeKey(remove: otkId)
                state = await state.updateLocalOneTimePrivateKey(nil)
            }
            // Commit prepared state and finalize message bookkeeping. We commit once per successfully
            // decrypted message to ensure counters/indices remain consistent with the derived keys.
            var commitState = state
            // Ensure we set lastDecrypted and counts based on message number n -> Ns = n+1
            commitState = await commitState.updateLastDecryptedMessageNumber(decrypted.messageNumber)
            commitState = await commitState.updateReceivedMessagesCount(decrypted.messageNumber + 1)
            commitState = await markAlreadyDecrypted(
                decrypted.messageNumber,
                in: commitState,
                configuration: core.defaultRatchetConfiguration)
            configuration.state = commitState
            try await core.updateSessionIdentity(configuration: configuration, persist: true)
            return plaintext
        }
    }

    private func markAlreadyDecrypted(
        _ messageNumber: Int,
        in state: RatchetState,
        configuration: RatchetConfiguration
    ) async -> RatchetState {
        var state = await state.updateAlreadyDecryptedMessageNumber(messageNumber)
        let oldestRetained = max(0, messageNumber - configuration.maxSkippedMessageKeys)
        let retained = state.alreadyDecryptedMessageNumbers.filter { $0 >= oldestRetained }
        state = await state.setAlreadyDecryptedMessageNumbers(Set(retained))
        return state
    }
    
    // Derive and stash skipped message keys and prepare the current message key; do not mutate live state
    private func deriveMessageKey(
        header: EncryptedHeader,
        configuration: RatchetConfiguration,
        state: RatchetState
    ) async throws -> (RatchetState, SymmetricKey) {
        var state: RatchetState = state
        guard let decrypted = header.decrypted else { throw RatchetError.headerDecryptFailed }
        let messageNumber = decrypted.messageNumber //n
        let receivedMessagesCount = state.receivedMessagesCount //Ns
        guard var receivingKey = state.receivingKey else { throw RatchetError.receivingKeyIsNil } //ck
        
        if receivedMessagesCount < messageNumber {
            let skippedCount = messageNumber - receivedMessagesCount
            if skippedCount > configuration.maxSkippedMessageKeys {
                throw RatchetError.maxSkippedHeadersExceeded
            }

            // Tag stashed keys with the chain they belong to (the sender's per-turn ratchet
            // key from this header) so equal indices across ratchet turns stay distinct.
            let chainTag = decrypted.ratchetPublicKey
            for i in receivedMessagesCount ..< messageNumber {
                let messageKey = try await core.symmetricKeyRatchet(from: receivingKey) //mk_i
                let nextReceivingKey = try await core.deriveChainKey(from: receivingKey, configuration: configuration) //nextCK
                let skipped = SkippedMessageKey(
                    remoteLongTermPublicKey: header.remoteLongTermPublicKey,
                    remoteOneTimePublicKey: header.remoteOneTimePublicKey?.rawRepresentation,
                    remoteMLKEMPublicKey: header.remoteMLKEMPublicKey.rawRepresentation,
                    messageIndex: i,
                    messageKey: messageKey,
                    chainRatchetPublicKey: chainTag)
                
                if !state.skippedMessageKeys.contains(where: { $0.messageIndex == i && $0.chainRatchetPublicKey == chainTag }) && !state.alreadyDecryptedMessageNumbers.contains(i) {
                    state = await state.updateSkippedMessage(skippedMessageKey: skipped)
                }
                state = await state.updateSkippedMessageIndex(i)
                receivingKey = nextReceivingKey
            }
        }
        
        // Prepare current MK_n and next CK
        let messageKey = try await core.symmetricKeyRatchet(from: receivingKey) //mk_n
        let nextReceivingChain = try await core.deriveChainKey(from: receivingKey, configuration: configuration) //ck_after_n
        state = await state.updateReceivingKey(nextReceivingChain)
        return (state, messageKey)
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
        messageNumber: Int,
        configuration: RatchetStateCore<Hash>.SessionConfiguration
    ) async throws -> Data {
        
        var configuration = configuration
        guard var state = configuration.state else {
            throw RatchetError.stateUninitialized
        }
        
        let messageKey = try await core.symmetricKeyRatchet(from: decodedMessage.chainKey)
        let payloadAAD = try await payloadAssociatedData(for: decodedMessage.ratchetMessage.header)
        
        if state.receivingHandshakeFinished == false {
            let decryptedMessage = try decryptPayload(
                decodedMessage.ratchetMessage.encryptedData,
                using: messageKey,
                associatedData: payloadAAD)
            
            // If an OTK was used for this initial message and enforcement is enabled,
            // consume it via delegate and clear it from state to prevent reuse.
            if await core.enforceOTKConsistency, let otkId = decodedMessage.ratchetMessage.header.oneTimeKeyId {
                await delegate?.updateOneTimeKey(remove: otkId)
                state = await state.updateLocalOneTimePrivateKey(nil)
            }
            
            // Increment count of received messages.
            state = await state.incrementReceivedMessagesCount()
            state = await state.updateReceivingHandshakeFinished(true)
            
            configuration.state = state
            try await core.updateSessionIdentity(configuration: configuration, persist: true)
            logger.log(level: .trace, message: "Initial receiving handshake succeeded")
            return decryptedMessage
        } else {
            let decryptedMessage = try decryptPayload(
                decodedMessage.ratchetMessage.encryptedData,
                using: messageKey,
                associatedData: payloadAAD)
            state = await state.incrementReceivedMessagesCount()
            state = await state.updateLastDecryptedMessageNumber(messageNumber)
            state = await markAlreadyDecrypted(
                messageNumber,
                in: state,
                configuration: core.defaultRatchetConfiguration)
            
            configuration.state = state
            try await core.updateSessionIdentity(configuration: configuration, persist: true)
            logger.log(level: .trace, message: "Decryption Succeeded")
            return decryptedMessage
        }
    }
    
    // Decrypt using a pre-derived message key. This function does NOT mutate state.
    private func processFoundMessage(
        ratchetMessage: RatchetMessage,
        usingMessageKey messageKey: SymmetricKey,
        messageNumber: Int
    ) async throws -> Data {
        let payloadAAD = try await payloadAssociatedData(for: ratchetMessage.header)
        return try decryptPayload(
            ratchetMessage.encryptedData,
            using: messageKey,
            associatedData: payloadAAD)
    }
    
    /// A container for a decrypted ratchet message and its corresponding symmetric key.
    private struct DecodedMessage: Sendable {
        let ratchetMessage: RatchetMessage
        let chainKey: SymmetricKey
    }
    
    /// Builds the AEAD associated data for payload encryption.
    private func payloadAssociatedData(for header: EncryptedHeader) async throws -> Data {
        let headerData = try BinaryEncoder().encode(header)
        return await core.defaultRatchetConfiguration.associatedData + headerData
    }

    private func encryptPayload(
        _ plaintext: Data,
        using messageKey: SymmetricKey,
        associatedData: Data
    ) throws -> Data {
        do {
            let sealedBox = try AES.GCM.seal(
                plaintext,
                using: messageKey,
                authenticating: associatedData)
            guard let combined = sealedBox.combined else {
                throw RatchetError.encryptionFailed
            }
            return combined
        } catch let error as RatchetError {
            throw error
        } catch {
            throw RatchetError.encryptionFailed
        }
    }

    private func decryptPayload(
        _ encryptedData: Data,
        using messageKey: SymmetricKey,
        associatedData: Data
    ) throws -> Data {
        let sealedBox = try AES.GCM.SealedBox(combined: encryptedData)
        return try AES.GCM.open(
            sealedBox,
            using: messageKey,
            authenticating: associatedData)
    }
    
    /// Performs the per-turn hybrid **receiving** ratchet step (spec `DHRatchet`, receiver half).
    ///
    /// Runs when a decrypted header advertises a ratchet public key different from the chain
    /// we are currently receiving on:
    /// 1. Spec `SkipMessageKeys(header.previousChainLength)`: derive and stash the remaining
    ///    keys of the *old* receiving chain (bounded by `maxSkippedMessageKeys`), tagged with
    ///    the old chain's ratchet key, so late old-chain frames still decrypt after the turn.
    /// 2. `dhOut = DH(localRatchetPrivateKey, headerRatchetKey)`;
    ///    `kemSS = decapsulate(headerKEMCiphertext)`.
    /// 3. `(rootKey, CKr) = KDF_RK(rootKey, dhOut || kemSS)` — identical inputs to the
    ///    sender's step, so CKr equals their CKs.
    /// 4. Adopts the peer's new ratchet publics (the next sending step encapsulates to the
    ///    new KEM key), resets the received counter for the new chain, and scopes
    ///    `alreadyDecryptedMessageNumbers` to it. Skipped caches are retained.
    ///
    /// Skipped-key stashes and all other mutations stay on the caller's working copy; nothing
    /// commits unless the message decrypts.
    private func performReceivingRatchetStep(
        on state: RatchetState,
        header: MessageHeader,
        headerRatchetKey: Data,
        headerKEMCiphertext: Data,
        localRatchetPrivateKey: Data,
        localRatchetKEMPrivateKey: Data
    ) async throws -> RatchetState {
        guard let rootKey = state.rootKey else {
            throw RatchetError.rootKeyIsNil
        }
        logger.log(level: .trace, message: "Performing per-turn hybrid receiving ratchet step")
        var state = state
        
        // 1. Retain the tail of the old receiving chain (spec SkipMessageKeys(header.pn)).
        if state.receivingHandshakeFinished,
           var oldReceivingKey = state.receivingKey,
           state.receivedMessagesCount < header.previousChainLength {
            let ratchetConfiguration = await core.defaultRatchetConfiguration
            let skippedCount = header.previousChainLength - state.receivedMessagesCount
            if skippedCount > ratchetConfiguration.maxSkippedMessageKeys {
                throw RatchetError.maxSkippedHeadersExceeded
            }
            let oldChainTag = state.remoteRatchetPublicKey
            for i in state.receivedMessagesCount ..< header.previousChainLength {
                let messageKey = try await core.symmetricKeyRatchet(from: oldReceivingKey)
                let nextReceivingKey = try await core.deriveChainKey(
                    from: oldReceivingKey,
                    configuration: ratchetConfiguration)
                if !state.skippedMessageKeys.contains(where: { $0.messageIndex == i && $0.chainRatchetPublicKey == oldChainTag })
                    && !state.alreadyDecryptedMessageNumbers.contains(i) {
                    state = await state.updateSkippedMessage(skippedMessageKey: SkippedMessageKey(
                        remoteLongTermPublicKey: state.remoteLongTermPublicKey,
                        remoteOneTimePublicKey: state.remoteOneTimePublicKey?.rawRepresentation,
                        remoteMLKEMPublicKey: state.remoteMLKEMPublicKey.rawRepresentation,
                        messageIndex: i,
                        messageKey: messageKey,
                        chainRatchetPublicKey: oldChainTag))
                }
                oldReceivingKey = nextReceivingKey
            }
        }
        
        // 2. Hybrid secrets: our current ratchet private (whose public the sender saw)
        //    against the sender's fresh ratchet public.
        let dhOutput = try await core.ratchetDH(
            localPrivate: localRatchetPrivateKey,
            remotePublic: headerRatchetKey)
        let kemSharedSecret = try localRatchetKEMPrivateKey.decodeMLKem1024()
            .decapsulate(headerKEMCiphertext).bytes
        
        // 3. Root KDF step -> new root + new receiving chain.
        let derived = await core.kdfRootKey(rootKey, input: dhOutput + kemSharedSecret)
        
        // 4. Switch to the new chain.
        state = await state.updateRootKey(derived.rootKey)
        state = await state.updateReceivingKey(derived.chainKey)
        state = await state.updateRemoteRatchetPublicKey(headerRatchetKey)
        if let headerKEMPublicKey = header.ratchetKEMPublicKey {
            state = await state.updateRemoteRatchetKEMPublicKey(headerKEMPublicKey)
        }
        state = await state.updateReceivedMessagesCount(0)
        state = await state.resetAlreadyDecryptedMessageNumber()
        // The message-key lane is now on the ratchet; the PQXDH bootstrap lane is subsumed.
        state = await state.updateReceivingHandshakeFinished(true)
        return state
    }
    
    /// Performs the per-turn hybrid **sending** ratchet step (spec `DHRatchet`, sender half,
    /// with deferred key generation).
    ///
    /// Runs on the first send after the peer took a turn:
    /// 1. Generates fresh local Curve25519 + ML-KEM-1024 ratchet key pairs.
    /// 2. `dhOut = DH(newLocalRatchet, remoteRatchetPublicKey)`;
    ///    `kemCt, kemSS = encapsulate(remoteRatchetKEMPublicKey)`.
    /// 3. `(rootKey, CKs) = KDF_RK(rootKey, dhOut || kemSS)`.
    /// 4. `previousMessagesCount = sentMessagesCount`, `sentMessagesCount = 0`.
    ///
    /// The new ratchet publics and `kemCt` ride in every encrypted header of the new chain
    /// (not just the boundary frame) so the receiver can complete the matching receiving step
    /// even if the first message of the chain is lost.
    private func performSendingRatchetStep(on state: RatchetState) async throws -> RatchetState {
        guard let remoteRatchetPublicKey = state.remoteRatchetPublicKey,
              let remoteRatchetKEMPublicKey = state.remoteRatchetKEMPublicKey,
              let rootKey = state.rootKey else {
            throw RatchetError.stateUninitialized
        }
        logger.log(level: .trace, message: "Performing per-turn hybrid sending ratchet step")
        
        // 1. Fresh per-turn key pairs.
        let newRatchetPrivateKey = crypto.generateCurve25519PrivateKey()
        let newRatchetKEMPrivateKey = try MLKEM1024.PrivateKey().encode()
        
        // 2. Hybrid secrets against the peer's latest advertised ratchet keys.
        let dhOutput = try await core.ratchetDH(
            localPrivate: newRatchetPrivateKey.rawRepresentation,
            remotePublic: remoteRatchetPublicKey)
        let remoteKEM = try MLKEM1024.PublicKey(rawRepresentation: remoteRatchetKEMPublicKey)
        let kemResult = try remoteKEM.encapsulate()
        
        // 3. Root KDF step -> new root + new sending chain.
        let derived = await core.kdfRootKey(rootKey, input: dhOutput + kemResult.sharedSecret.bytes)
        
        // 4. Commit the turn into the working state.
        var state = state
        state = await state.updateRootKey(derived.rootKey)
        state = await state.updateSendingKey(derived.chainKey)
        state = await state.updateLocalRatchetPrivateKey(newRatchetPrivateKey.rawRepresentation)
        state = await state.updateLocalRatchetKEMPrivateKey(newRatchetKEMPrivateKey)
        state = await state.updateLocalRatchetKEMCiphertext(kemResult.encapsulated)
        state = await state.updateSendingChainRemoteRatchetKey(remoteRatchetPublicKey)
        state = await state.updatePreviousMessagesCount(state.sentMessagesCount)
        state = await state.updateSentMessagesCount(0)
        return state
    }
    
    /// Executes an in-place PQXDH re-key (epoch step), triggered by identity/prekey changes.
    ///
    /// Rare when the session-management layer mints fresh sessions on rotation, but kept correct:
    /// - **Skipped caches are preserved** so late old-epoch frames still decrypt from stash.
    /// - A **bounded tail of the old receiving chain** is stashed before the switch (the
    ///   in-flight window of the peer's old sending chain has no `previousChainLength`
    ///   signal on an epoch step, so a bounded run replaces the spec's exact gap-fill).
    /// - **Root continuity**: the fresh PQXDH secret is mixed through `KDF_RK` with the old
    ///   root as salt — an epoch no longer stands alone.
    /// - **Direction separation**: two successive `KDF_RK` steps yield distinct chains. The
    ///   re-keying (sender-driven) party takes step 1 as its sending chain; the receiving
    ///   party mirrors it as its receiving chain.
    ///
    /// - Parameter header: The header containing the new remote public keys (receive-driven).
    /// - Parameter localKeys: The rotated local private keys (sender-driven).
    /// - Returns: An updated `RatchetState` after applying the re-key.
    /// - Throws: `RatchetError.stateUninitialized` if the ratchet state is unavailable.
    private func diffieHellmanRatchet(
        header: EncryptedHeader? = nil,
        localKeys: LocalKeys? = nil,
        configuration: RatchetStateCore<Hash>.SessionConfiguration,
        persist: Bool = true
    ) async throws -> RatchetState {
        // 1. Load current state
        var configuration = configuration
        guard var state = configuration.state else {
            throw RatchetError.stateUninitialized
        }
        logger.log(level: .trace, message: "Starting PQXDH re-key (epoch) step")
        
        // 2. Stash a bounded tail of the old receiving chain so the peer's in-flight
        //    old-epoch frames remain decryptable, then reset per-message counters.
        //    Skipped message/header caches are intentionally NOT cleared.
        state = await stashOldReceivingChainTail(on: state)
        state = await state
            .updatePreviousMessagesCount(state.sentMessagesCount)
            .updateSentMessagesCount(0)
            .updateReceivedMessagesCount(0)
            .resetAlreadyDecryptedMessageNumber()
            .updateSendingHandshakeFinished(false)
            .updateReceivingHandshakeFinished(false)
        
        let oldRootKey = state.rootKey
        
        if let header {
            // 3. Update remote public keys
            logger.log(level: .trace, message: "Updating remote public keys from header")
            state = await state.updateRemoteLongTermPublicKey(header.remoteLongTermPublicKey)
            state = await state.updateRemoteOneTimePublicKey(header.remoteOneTimePublicKey)
            state = await state.updateRemoteMLKEMPublicKey(header.remoteMLKEMPublicKey)
            
            let pqxdhSecret = try await core.derivePQXDHFinalKeyReceiver(
                remoteLongTermPublicKey: state.remoteLongTermPublicKey,
                remoteOneTimePublicKey: state.remoteOneTimePublicKey,
                localLongTermPrivateKey: state.localLongTermPrivateKey,
                localOneTimePrivateKey: state.localOneTimePrivateKey,
                localMLKEMPrivateKey: state.localMLKEMPrivateKey,
                receivedCiphertext: header.messageCiphertext)
            
            // Receive-driven: step 1 = our receiving chain (the re-keyer's sending chain),
            // step 2 = our sending chain. Mirrors the sender-driven branch below.
            let step1 = await core.kdfRootKey(oldRootKey, input: pqxdhSecret.bytes)
            let step2 = await core.kdfRootKey(step1.rootKey, input: pqxdhSecret.bytes)
            state = await state.updateRootKey(step2.rootKey)
            state = await state.updateCiphertext(header.messageCiphertext)
            state = await state.updateReceivingKey(step1.chainKey)
            state = await state.updateSendingKey(step2.chainKey)
            
            logger.log(level: .trace, message: "Epoch re-key applied (receive-driven)")
            
        } else if let localKeys {
            // 3. Adopt the rotated local private keys
            logger.log(level: .trace, message: "Updating local private keys")
            state = await state.updateLocalLongTermPrivateKey(localKeys.longTerm.rawRepresentation)
            state = await state.updateLocalOneTimePrivateKey(localKeys.oneTime)
            state = await state.updateLocalMLKEMPrivateKey(localKeys.mlKEM)
            
            let cipher = try await core.derivePQXDHFinalKey(
                localLongTermPrivateKey: state.localLongTermPrivateKey,
                localOneTimePrivateKey: state.localOneTimePrivateKey,
                remoteLongTermPublicKey: state.remoteLongTermPublicKey,
                remoteOneTimePublicKey: state.remoteOneTimePublicKey,
                remoteMLKEMPublicKey: state.remoteMLKEMPublicKey)
            
            // Sender-driven: step 1 = our sending chain, step 2 = our receiving chain.
            let step1 = await core.kdfRootKey(oldRootKey, input: cipher.symmetricKey.bytes)
            let step2 = await core.kdfRootKey(step1.rootKey, input: cipher.symmetricKey.bytes)
            state = await state.updateRootKey(step2.rootKey)
            state = await state.updateCiphertext(cipher.ciphertext)
            state = await state.updateSendingKey(step1.chainKey)
            state = await state.updateReceivingKey(step2.chainKey)
            
            logger.log(level: .trace, message: "Epoch re-key applied (sender-driven)")
        }
        logger.log(level: .trace, message: "Ratchet state successfully updated and returned")
        configuration.state = state
        if persist {
            try await core.updateSessionIdentity(configuration: configuration)
        }
        return state
    }
    
    /// Stashes a bounded run of the old receiving chain's message keys before an epoch
    /// re-key switches chains. Epoch steps carry no `previousChainLength` for the old chain,
    /// so a fixed window (capped by remaining skipped-key capacity) covers the realistic
    /// in-flight frames. Keys are tagged with the old chain's ratchet key.
    private func stashOldReceivingChainTail(on state: RatchetState) async -> RatchetState {
        let epochTailWindow = 32
        guard state.receivingHandshakeFinished,
              var receivingKey = state.receivingKey else {
            return state
        }
        var state = state
        let capacity = await max(0, core.defaultRatchetConfiguration.maxSkippedMessageKeys - state.skippedMessageKeys.count)
        let tailLength = min(epochTailWindow, capacity)
        guard tailLength > 0 else { return state }
        let oldChainTag = state.remoteRatchetPublicKey
        for i in state.receivedMessagesCount ..< (state.receivedMessagesCount + tailLength) {
            guard let messageKey = try? await core.symmetricKeyRatchet(from: receivingKey),
                  let nextReceivingKey = try? await core.deriveChainKey(
                    from: receivingKey,
                    configuration: core.defaultRatchetConfiguration) else {
                break
            }
            if !state.skippedMessageKeys.contains(where: { $0.messageIndex == i && $0.chainRatchetPublicKey == oldChainTag })
                && !state.alreadyDecryptedMessageNumbers.contains(i) {
                state = await state.updateSkippedMessage(skippedMessageKey: SkippedMessageKey(
                    remoteLongTermPublicKey: state.remoteLongTermPublicKey,
                    remoteOneTimePublicKey: state.remoteOneTimePublicKey?.rawRepresentation,
                    remoteMLKEMPublicKey: state.remoteMLKEMPublicKey.rawRepresentation,
                    messageIndex: i,
                    messageKey: messageKey,
                    chainRatchetPublicKey: oldChainTag))
            }
            receivingKey = nextReceivingKey
        }
        return state
    }
}

extension DoubleRatchetStateManager {
    /// Encrypts a message header using the current sending header key (`HKs`).
    ///
    /// This function encrypts the `MessageHeader` under the sender's current header key.
    /// The header key is established during the initial handshake and then ratcheted
    /// (symmetrically) per message thereafter; on DH ratchet steps a new header key is
    /// derived from the PQXDH result.
    ///
    /// - Parameters:
    ///   - header: The clear (unencrypted) message header to be encrypted.
    ///   - remotePublicLongTermKey: The recipient's Curve public key.
    ///   - remoteOneTimePublicKey: The recipient's ephemeral Curve public key.
    ///   - remoteMLKEMPublicKey: The recipient's MLKEM public key.
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
        remoteLongTermPublicKey: RemoteLongTermPublicKey,
        remoteOneTimePublicKey: RemoteOneTimePublicKey?,
        remoteMLKEMPublicKey: RemoteMLKEMPublicKey,
        oneTimeKeyId: UUID?,
        mlKEMOneTimeKeyId: UUID,
        configuration: RatchetStateCore<Hash>.SessionConfiguration
    ) async throws -> EncryptedHeader {
        
        guard let state = configuration.state else {
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
        
        // 1. Serialize the message header using BinaryEncoder.
        let headerPlain = try BinaryEncoder().encode(header)
        
        // 2. Construct a 96-bit nonce using the message counter.
        let counter = state.sentMessagesCount
        let nonceSize = 12
        var ctrBytes = withUnsafeBytes(of: UInt64(counter).bigEndian) { Data($0) }
        ctrBytes.append(contentsOf: [UInt8](repeating: 0, count: nonceSize - ctrBytes.count))
        
        let nonce = try AES.GCM.Nonce(data: ctrBytes)
        let messageKey = try await core.symmetricKeyRatchet(from: sendingHeaderKey)
        
        // 3. Encrypt the serialized header.
        guard let encrypted = try crypto.encrypt(
            data: headerPlain,
            symmetricKey: messageKey,
            nonce: nonce) else {
            throw RatchetError.headerEncryptionFailed
        }
        
        return EncryptedHeader(
            remoteLongTermPublicKey: remoteLongTermPublicKey,
            remoteOneTimePublicKey: remoteOneTimePublicKey,
            remoteMLKEMPublicKey: remoteMLKEMPublicKey,
            headerCiphertext: headerCiphertext,
            messageCiphertext: messageCiphertext,
            oneTimeKeyId: oneTimeKeyId,
            mlKEMOneTimeKeyId: mlKEMOneTimeKeyId,
            encrypted: encrypted)
    }
}

extension DoubleRatchetStateManager {
    
    /// Decrypts an encrypted header using skipped and current/advanced header keys.
    ///
    /// The method attempts header decryption in the following bounded order per call:
    /// 1. All stashed header keys in `skippedHeaderMessages` (to handle out-of-order delivery)
    /// 2. The current `receivingHeaderKey`
    /// 3. Iteratively stashes the current header key and advances to the next header key,
    ///    up to `maxSkippedMessageKeys`
    ///
    /// - Parameters:
    ///   - encryptedHeader: The received `EncryptedHeader` to decrypt.
    ///   - configuration: The session configuration containing ratchet state.
    /// - Returns: The same `EncryptedHeader` with its `decrypted` header populated on success.
    /// - Throws:
    ///   - `RatchetError.stateUninitialized` if session state is unavailable.
    ///   - `RatchetError.receivingHeaderKeyIsNil` if the current header key is missing.
    ///   - `RatchetError.maxSkippedHeadersExceeded` if the bounded advancement limit is reached.
    ///   - `CryptoError.decryptionFailed` if decryption fails with a tried key.
    ///
    /// - Important: Do not surface low-level crypto errors to untrusted clients; map to application-safe errors.
    func decryptHeader(
        encryptedHeader: EncryptedHeader,
        configuration: RatchetStateCore<Hash>.SessionConfiguration
    ) async throws -> EncryptedHeader {
        let (header, _) = try await decryptHeaderWithWorkingState(
            encryptedHeader: encryptedHeader,
            configuration: configuration,
            persistAdvancedState: true)
        return header
    }

    private func decryptHeaderWithWorkingState(
        encryptedHeader: EncryptedHeader,
        configuration: RatchetStateCore<Hash>.SessionConfiguration,
        persistAdvancedState: Bool
    ) async throws -> (EncryptedHeader, RatchetState) {
        var configuration = configuration
        // Note: `0...max` (not `0..<max`) is intentional — a gap of exactly `maxSkippedMessageKeys`
        // requires `max` advance iterations plus one final attempt with the advanced key. The cap
        // itself is enforced by the skippedHeaderMessages count guard below.
        for _ in await 0...core.defaultRatchetConfiguration.maxSkippedMessageKeys {
            guard let state = configuration.state else {
                throw RatchetError.stateUninitialized
            }
            // Try any stashed header keys first
            for skipped in state.skippedHeaderMessages {
                if let header = try? await attemptHeaderDecryption(encryptedHeader: encryptedHeader, chainKey: skipped.chainKey) {
                    // Evict the consumed skipped header key from the working state. Each header
                    // chain key decrypts exactly one message's header, so once matched it can
                    // never be needed again. The eviction only persists when the caller commits
                    // this working state after a successful payload decrypt.
                    let stateAfterUse = await state.removeSkippedHeaderMessage(skipped)
                    return (header, stateAfterUse)
                }
            }
            // Try current receiving header key
            guard let chainKey = state.receivingHeaderKey else {
                throw RatchetError.receivingHeaderKeyIsNil
            }
            if let header = try? await attemptHeaderDecryption(encryptedHeader: encryptedHeader, chainKey: chainKey) {
                return (header, state)
            }
            // If still failing, advance header chain until we either decrypt or hit the cap
            if await state.skippedHeaderMessages.count >= core.defaultRatchetConfiguration.maxSkippedMessageKeys {
                throw RatchetError.maxSkippedHeadersExceeded
            }
            var stateToAdvance = state
            stateToAdvance = await stateToAdvance.incrementSkippedHeaderIndex()
            guard let currentHeaderKey = stateToAdvance.receivingHeaderKey else {
                throw RatchetError.receivingHeaderKeyIsNil
            }
            let skippedHeader = SkippedHeaderMessage(chainKey: currentHeaderKey, index: stateToAdvance.headerIndex)
            stateToAdvance = await stateToAdvance.updateSkippedHeaderMessage(skippedHeader)
            let nextChainKey = try await core.deriveChainKey(from: currentHeaderKey, configuration: core.defaultRatchetConfiguration)
            stateToAdvance = await stateToAdvance.updateReceivingHeaderKey(nextChainKey)
            configuration.state = stateToAdvance
            if persistAdvancedState {
                try await core.updateSessionIdentity(configuration: configuration, persist: true)
            }
        }
        throw RatchetError.maxSkippedHeadersExceeded
    }
    
    
    private func attemptHeaderDecryption(
        encryptedHeader: EncryptedHeader,
        chainKey: SymmetricKey
    ) async throws -> EncryptedHeader {
        var encryptedHeader = encryptedHeader
        let messageKey = try await core.symmetricKeyRatchet(from: chainKey)
        
        guard let decryptedData = try crypto.decrypt(data: encryptedHeader.encrypted, symmetricKey: messageKey) else {
            throw CryptoError.decryptionFailed
        }
        let header = try BinaryDecoder().decode(MessageHeader.self, from: decryptedData)
        encryptedHeader.setDecrypted(header)
        return encryptedHeader
    }
    
}
