//
//  DoubleRatchet.swift
//  double-ratchet-kit
//
//  Created by Cole M on 6/16/25.
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

import BSON
import Foundation
import NeedleTailCrypto
import NeedleTailLogger

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
 - Bob's signed prekey (SPKB) becomes the initial DH ratchet public key.
 - Alice's first Double Ratchet message includes the PQXDH initial ciphertext.
 
 🔒 PQXDH Specification: https://signal.org/docs/specifications/pqxdh/
 
 ## Key Components
 
 - `RatchetStateManager`: Core ratchet state machine. Handles key rotation, message counters, and skipped key pruning.
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

/// An actor that manages the cryptographic state for secure messaging using the Double Ratchet algorithm.
///
/// ## Overview
/// Provides Double Ratchet with header encryption and PQXDH integration for
/// asynchronous forward secrecy and post‑compromise security. Combines a Diffie‑Hellman
/// ratchet with symmetric‑key ratchets so keys change per message.
///
/// - Specification: https://signal.org/docs/specifications/doubleratchet/
/// - PQXDH: https://signal.org/docs/specifications/pqxdh/
/// - X3DH: https://signal.org/docs/specifications/x3dh/
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
public actor RatchetStateManager<Hash: HashFunction & Sendable> {
    
    /// Default configuration for the Double Ratchet protocol.
    private var defaultRatchetConfiguration = RatchetConfiguration(
        messageKeyData: Data([0x00]), // Data for message key derivation.
        chainKeyData: Data([0x01]), // Data for chain key derivation.
        rootKeyData: Data([0x02, 0x03]), // Data for root key derivation.
        associatedData: "DoubleRatchetKit".data(using: .ascii)!, // Associated data for messages.
        maxSkippedMessageKeys: 1500)
    
    // MARK: - Private Properties
    
    /// The executor responsible for serialized task execution within the actor.
    private let executor: any SerialExecutor
    
    /// Returns the executor used for non-isolated tasks.
    public nonisolated var unownedExecutor: UnownedSerialExecutor {
        executor.asUnownedSerialExecutor()
    }
    
    /// Internal cryptographic utility object.
    private let crypto = NeedleTailCrypto()
    private var logger: NeedleTailLogger
    /// Tracks whether `shutdown()` has been called.
    private nonisolated(unsafe) var didShutdown = false
    /// Holds all known session configurations keyed by session identity.
    public private(set) var sessionConfigurations: [UUID: SessionConfiguration] = [:]
    
    public weak var delegate: SessionIdentityDelegate?
    public func setDelegate(_ delegate: SessionIdentityDelegate) {
        self.delegate = delegate
    }
    
    /// When enabled, enforce that one-time prekeys (OTK) are used exactly as indicated by the
    /// incoming header during the initial handshake. If the header signals an OTK but the
    /// corresponding local private OTK cannot be loaded, the decrypt will fail fast with
    /// `RatchetError.missingOneTimeKey`. When the header omits an OTK, decryption proceeds
    /// without using any local OTK.
    public var enforceOTKConsistency: Bool = false

    /// Enable or disable strict one-time-prekey (OTK) consistency enforcement.
    public func setEnforceOTKConsistency(_ value: Bool) {
        self.enforceOTKConsistency = value
    }
    
    // Working with the set locally for performance.
    private var alreadyDecryptedMessageNumbers = Set<Int>()
    
    // MARK: - Initialization
    
    /// Initializes the ratchet state manager.
    /// - Parameters:
    ///  - executor: A `SerialExecutor` used to coordinate concurrent operations within the actor.
    ///  - logger: The Logger
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
        precondition(didShutdown, "⛔️ RatchetStateManager was deinitialized without calling shutdown(). ")
    }
    
    public func setLogLevel(_ level: Level) async {
        logger.setLogLevel(.trace)
    }
    
    /// This must be called when the manager is done being used
    public func shutdown() async throws {
        for var (_, configuration) in sessionConfigurations {
            if var state = configuration.state {
                state = await state.setAlreadyDecryptedMessageNumbers(alreadyDecryptedMessageNumbers)
                configuration.state = state
                try await updateSessionIdentity(configuration: configuration, persist: true)
            }
        }
        sessionConfigurations.removeAll()
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
            header: EncryptedHeader,
            local: LocalKeys
        ) throws {
            try self.init(
                remote: .init(
                    longTerm: .init(header.remoteLongTermPublicKey),
                    oneTime: header.remoteOneTimePublicKey,
                    mlKEM: header.remoteMLKEMPublicKey),
                local: local)
            self.header = header
        }
    }
    
    /// Represents session identity and associated symmetric key for key derivation.
    public struct SessionConfiguration: Sendable {
        var sessionIdentity: SessionIdentity
        var sessionSymmetricKey: SymmetricKey
        var state: RatchetState?
    }
    
    /// Load or create session configuration and ratchet state as needed.
    /// - Parameters:
    ///   - sessionIdentity: Identity of the communicating peer.
    ///   - sessionSymmetricKey: Symmetric key for deriving state secrets.
    ///   - messageType: Indicates if the context is for sending or receiving.
    private func loadConfigurations(
        sessionIdentity: SessionIdentity,
        sessionSymmetricKey: SymmetricKey,
        messageType: MessageType,
    ) async throws {
        
        func checkSendingKeyChanges(state: RatchetState, keys: EncryptionKeys) -> Bool {
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
            
            if state.remoteLongTermPublicKey != header.remoteLongTermPublicKey {
                logger.log(level: .trace, message: "Receiveing long term key has changed")
                return true
            }
            
            if state.remoteOneTimePublicKey != header.remoteOneTimePublicKey {
                logger.log(level: .trace, message: "Receiveing one time key has changed")
                return true
            }
            
            if state.remoteMLKEMPublicKey != header.remoteMLKEMPublicKey {
                logger.log(level: .trace, message: "Receiveing mlKEM key has changed")
                return true
            }
            return false
        }
        
        if var configuration = sessionConfigurations[sessionIdentity.id] {
        // 1. Check if we have a currently loaded session
//        if let index = sessionConfigurations.firstIndex(where: {
//            $0.sessionIdentity.id == sessionIdentity.id
//        }) {
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
                        localKeys: .init(
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
                        chainKey = try await deriveChainKey(
                            from: rootKey,
                            configuration: defaultRatchetConfiguration,
                        )
                    }
                    currentProps.state = await state.updateSendingKey(chainKey)
                }
            case .receiving(let keys):
                var changesDetected = false
                defer {
                    changesDetected = false
                }
                guard let header = keys.header else {
                    fatalError("Receiving end must have a header")
                }
                if let state = currentProps.state {
                    changesDetected = checkReceivingKeyChanges(state: state, header: header)
                }
                
                if changesDetected {
                    
                    currentProps.state = await currentProps.state?.updateRemoteLongTermPublicKey(keys.remoteLongTermPublicKey)
                    currentProps.state = await currentProps.state?.updateRemoteOneTimePublicKey(keys.remoteOneTimePublicKey)
                    currentProps.state = await currentProps.state?.updateRemoteMLKEMPublicKey(keys.remoteMLKEMPublicKey)
                    currentProps.longTermPublicKey = keys.remoteLongTermPublicKey
                    currentProps.oneTimePublicKey = keys.remoteOneTimePublicKey
                    currentProps.mlKEMPublicKey = keys.remoteMLKEMPublicKey
                    
                    configuration.state = currentProps.state
                    do {
                        
                        currentProps.state = try await diffieHellmanRatchet(
                            header: header,
                            configuration: configuration)
                        
                    } catch {
                        configuration.state = nil
                        changesDetected = false
                    }
                }
            }
            
            configuration.state = currentProps.state
            try await sessionIdentity.updateIdentityProps(symmetricKey: sessionSymmetricKey, props: currentProps)
            
            configuration.sessionIdentity = sessionIdentity
            configuration.sessionSymmetricKey = sessionSymmetricKey

            try await updateSessionIdentity(configuration: configuration, persist: true)
        } else {
            logger.log(level: .trace, message: "Session not initialized yet, creating state for ratchet")
            var configuration = SessionConfiguration(
                sessionIdentity: sessionIdentity,
                sessionSymmetricKey: sessionSymmetricKey)
            
            guard var props = await sessionIdentity.props(symmetricKey: sessionSymmetricKey) else {
                throw RatchetError.missingProps
            }
            if var state = props.state {
                alreadyDecryptedMessageNumbers = state.alreadyDecryptedMessageNumbers
                
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
                        do {
                            state = try await diffieHellmanRatchet(
                                localKeys: .init(
                                    longTerm: .init(keys.localLongTermPrivateKey),
                                    oneTime: keys.localOneTimePrivateKey,
                                    mlKEM: keys.localMLKEMPrivateKey),
                                configuration: configuration)
                        } catch {
                            configuration.state = nil
                            changesDetected = false
                        }
                    }
                case .receiving(let keys):
                    guard let header = keys.header else {
                        fatalError("Receiving end must have a header")
                    }
                    changesDetected = checkReceivingKeyChanges(state: state, header: header)
                    
                    if changesDetected {
                        
                        state = await state.updateLocalLongTermPrivateKey(keys.localLongTermPrivateKey)
                        state = await state.updateLocalOneTimePrivateKey(keys.localOneTimePrivateKey)
                        state = await state.updateLocalMLKEMPrivateKey(keys.localMLKEMPrivateKey)
                        
                        configuration.state = state
                        do {
                            state = try await diffieHellmanRatchet(header: header, configuration: configuration)
                        } catch {
                            configuration.state = nil
                            changesDetected = false
                        }
                    }
                }
                configuration.state = state
            } else {
                let state = try await setState(for: messageType, configuration: configuration)
                props.state = state
                configuration.sessionIdentity = sessionIdentity
                configuration.state = state
                try await updateSessionIdentity(configuration: configuration)
            }
            
            try await sessionIdentity.updateIdentityProps(symmetricKey: sessionSymmetricKey, props: props)
            try await updateSessionIdentity(configuration: configuration, persist: true)
            sessionConfigurations[configuration.sessionIdentity.id] = configuration
        }
    }
    
    private func getCurrentConfiguration(id: UUID) throws -> SessionConfiguration {
        guard let configuration = sessionConfigurations[id] else {
            throw RatchetError.missingConfiguration
        }
        return configuration
    }
    
    /// Updates the session identity with a new ratchet state.
    private func updateSessionIdentity(configuration: SessionConfiguration, persist: Bool = false) async throws {
        
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
    
    /// Sets a  ratchet state based on message direction and keying material.
    private func setState(for messageType: MessageType, configuration: SessionConfiguration) async throws -> RatchetState {
        switch messageType {
        case let .receiving(keys):
            guard let header = keys.header else {
                fatalError("Receiving end must have a header")
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
                remotePublicLongTermKey: keys.remoteLongTermPublicKey,
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
    ///   - remoteKeys: The recipient's public keys, including long-term, one-time, and MLKEM keys.
    ///   - localKeys: The sender's private keys, including long-term, one-time, and MLKEM keys.
    /// - Throws: An error if the session cannot be initialized (e.g. invalid keys, storage issues).
    public func senderInitialization(
        sessionIdentity: SessionIdentity,
        sessionSymmetricKey: SymmetricKey,
        remoteKeys: RemoteKeys,
        localKeys: LocalKeys,
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
    ///   - header: The `EncryptedHeader` received
    /// - Throws: An error if the message cannot be decrypted or the session cannot be initialized.
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
        
        var configuration = try getCurrentConfiguration(id: sessionId)
        
        guard var state = configuration.state else {
            throw RatchetError.stateUninitialized
        }
        
        // Step 2: Construct ratchet header metadata.
        let messageHeader = MessageHeader(
            previousChainLength: state.previousMessagesCount,
            messageNumber: state.sentMessagesCount)
        
        if !state.sendingHandshakeFinished {
            // Optional enforcement: if the peer advertised an OTK in state but we don't have
            // our local matching piece, fail fast when enforcement is enabled.
            if enforceOTKConsistency {
                let wantsOTK = (state.remoteOneTimePublicKey != nil)
                if wantsOTK && state.localOneTimePrivateKey == nil {
                    throw RatchetError.missingOneTimeKey
                }
            }
            // Step 3: Derive symmetric header encryption key using hybrid PQXDH.
            let headerCipher = try await derivePQXDHFinalKey(
                localLongTermPrivateKey: state.localLongTermPrivateKey,
                localOneTimePrivateKey: state.localOneTimePrivateKey,
                remoteLongTermPublicKey: state.remoteLongTermPublicKey,
                remoteOneTimePublicKey: state.remoteOneTimePublicKey,
                remoteMLKEMPublicKey: state.remoteMLKEMPublicKey)
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
        let localLongTermPublicKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: state.localLongTermPrivateKey)
            .publicKey.rawRepresentation
        var remoteOneTimePublicKey: RemoteOneTimePublicKey?
        if let localOneTimePrivateKey = state.localOneTimePrivateKey {
            let localOneTimePublicKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: localOneTimePrivateKey.rawRepresentation).publicKey.rawRepresentation
            remoteOneTimePublicKey = try RemoteOneTimePublicKey(id: localOneTimePrivateKey.id, localOneTimePublicKey)
        }
        let localMLKEMPublicKey = state.localMLKEMPrivateKey.rawRepresentation.decodeMLKem1024()
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
        let messageKey = try await symmetricKeyRatchet(from: sendingKey)
        
        guard let encryptedData = try crypto.encrypt(
            data: plainText,
            symmetricKey: messageKey) else {
            throw RatchetError.encryptionFailed
        }
        
        if !state.sendingHandshakeFinished {
            state = await state.updateSendingHandshakeFinished(true)
            logger.log(level: .trace, message: "Initial sending handshake succeeded")
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
        configuration.state = state
        try await updateSessionIdentity(configuration: configuration, persist: true)
        
        defer {
            logger.log(level: .trace, message: "Encryption Succeeded")
        }
        
        return RatchetMessage(
            header: encryptedHeader,
            encryptedData: encryptedData)
    }
    
    /// Runs PQXDH, then HKDF chain-key, then HMAC ratchet to get the next message key.
    private func deriveNextMessageKey(localLongTermPrivateKey: LocalLongTermPrivateKey,
                                      remotePublicLongTermKey: RemoteLongTermPublicKey,
                                      localOneTimePrivateKey: LocalOneTimePrivateKey?,
                                      remoteOneTimePublicKey: RemoteOneTimePublicKey?,
                                      remoteMLKEMPublicKey: RemoteMLKEMPublicKey,
                                      configuration: SessionConfiguration
    ) async throws -> (SymmetricKey, PQXDHCipher) {
        let cipher = try await derivePQXDHFinalKey(
            localLongTermPrivateKey: localLongTermPrivateKey,
            localOneTimePrivateKey: localOneTimePrivateKey,
            remoteLongTermPublicKey: remotePublicLongTermKey,
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
        logger.log(level: .info, message: "Ratchet decrypt started \(sessionId)")
        
        var configuration = try getCurrentConfiguration(id: sessionId)
        
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
                    try await updateSessionIdentity(configuration: configuration)
                } else if enforceOTKConsistency {
                    throw RatchetError.missingOneTimeKey
                }
            }
        }
        
        // HEADER DECRYPTION PHASE
        if !state.receivingHandshakeFinished {
            
            // If handshake not finished, derive header receiving key using PQXDH final key receiver.
            // This combines multiple DH operations to produce the symmetric key for header encryption.
            let finalHeaderReceivingKey = try await derivePQXDHFinalKeyReceiver(
                remoteLongTermPublicKey: state.remoteLongTermPublicKey,
                remoteOneTimePublicKey: state.remoteOneTimePublicKey,
                localLongTermPrivateKey: state.localLongTermPrivateKey,
                localOneTimePrivateKey: state.localOneTimePrivateKey,
                localMLKEMPrivateKey: state.localMLKEMPrivateKey,
                receivedCiphertext: message.header.headerCiphertext)
            
            // Update state with new receiving header key and persist changes.
            state = await state.updateReceivingHeaderKey(finalHeaderReceivingKey)
            configuration.state = state
            try await updateSessionIdentity(configuration: configuration)
        } else {
            // If handshake completed, ratchet receiving header key forward to derive next header key.
            if state.headerIndex == 0 {
                guard let receivingHeaderKey = state.receivingHeaderKey else {
                    throw RatchetError.receivingHeaderKeyIsNil
                }
                let newReceivingHeaderKey = try await deriveChainKey(from: receivingHeaderKey, configuration: defaultRatchetConfiguration)
                state = await state.updateReceivingHeaderKey(newReceivingHeaderKey)
                configuration.state = state
                try await updateSessionIdentity(configuration: configuration)
            }
        }
        
        // Decrypt the header now that the appropriate key is available.
        let header = try await decryptHeader(
            encryptedHeader: message.header,
            configuration: configuration)
        
        configuration = try getCurrentConfiguration(id: sessionId)
        guard let newState = configuration.state else {
            throw RatchetError.stateUninitialized
        }
        state = newState
        
        // Ensure header was successfully decrypted before continuing.
        guard let decrypted = header.decrypted else {
            throw RatchetError.headerDecryptFailed
        }
        
        // No key change detected:
        if !state.receivingHandshakeFinished {
            // During handshake, derive and store next receiving header key for upcoming messages.
            let newNextReceivingHeaderKey = try await derivePQXDHFinalKey(
                localLongTermPrivateKey: state.localLongTermPrivateKey,
                localOneTimePrivateKey: state.localOneTimePrivateKey,
                remoteLongTermPublicKey: state.remoteLongTermPublicKey,
                remoteOneTimePublicKey: state.remoteOneTimePublicKey,
                remoteMLKEMPublicKey: state.remoteMLKEMPublicKey)
            
            state = await state.updateReceivingNextHeaderKey(newNextReceivingHeaderKey.symmetricKey)
        } else {
            // After handshake, advance next receiving header key by ratcheting it forward.
            guard let nextReceivingHeaderKey = state.nextReceivingHeaderKey else {
                throw RatchetError.receivingHeaderKeyIsNil
            }
            let newReceivingHeaderKey = try await deriveChainKey(from: nextReceivingHeaderKey, configuration: defaultRatchetConfiguration)
            state = await state.updateReceivingNextHeaderKey(newReceivingHeaderKey)
        }
        
        // Before this is header decryption and keys change logic(Keys are not changing in this scenario)
        if let key = state.skippedMessageKeys.first(where: {
            $0.messageIndex == decrypted.messageNumber &&
            $0.remoteLongTermPublicKey == header.remoteLongTermPublicKey &&
            $0.remoteMLKEMPublicKey == header.remoteMLKEMPublicKey.rawRepresentation
        }) {
            logger.log(level: .trace, message: "Trying skipped message key index \(key.messageIndex)")
            if let oneTimeKey = key.remoteOneTimePublicKey, oneTimeKey != header.remoteOneTimePublicKey?.rawRepresentation {
                throw RatchetError.expiredKey
            }
            state = await state.removeSkippedMessages(at: key.messageIndex)
            state = await state.updateAlreadyDecryptedMessageNumber(decrypted.messageNumber)
            alreadyDecryptedMessageNumbers.insert(decrypted.messageNumber)
            
            configuration.state = state
            try await updateSessionIdentity(configuration: configuration)
            // Decrypt using stored message key
            return try await processFoundMessage(
                ratchetMessage: message,
                usingMessageKey: key.messageKey,
                messageNumber: decrypted.messageNumber)
        }
        // Gap-fill and prepare MK for current message using a working copy, commit after decrypt
        var preparedMessageKey: SymmetricKey? = nil
        if state.receivingHandshakeFinished {
            (state, preparedMessageKey) = try await deriveMessageKey(
                header: header,
                configuration: defaultRatchetConfiguration,
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
                let finalReceivingKey = try await derivePQXDHFinalKeyReceiver(
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
                chainKey = try await deriveChainKey(from: finalReceivingKey, configuration: defaultRatchetConfiguration)
                let nextChainKey = try await deriveChainKey(from: chainKey, configuration: defaultRatchetConfiguration)
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
                    chainKey = try await deriveChainKey(
                        from: rootKey,
                        configuration: defaultRatchetConfiguration,
                    )
                }
                
                let nextChainKey = try await deriveChainKey(from: chainKey, configuration: defaultRatchetConfiguration)
                state = await state.updateReceivingKey(nextChainKey)
            }
            
            // Update State
            configuration.state = state
            try await updateSessionIdentity(configuration: configuration)
            
            // Process the decrypted message with derived message key.
            return try await processFoundMessage(
                decodedMessage: DecodedMessage(ratchetMessage: message, chainKey: chainKey),
                messageNumber: decrypted.messageNumber,
                configuration: configuration)
        } else {
            // Subsequent messages after handshake, decrypt using prepared MK, then commit prepared state exactly once
            guard let messageKey = preparedMessageKey else { throw RatchetError.decryptionFailed }
            // Try decrypt without committing state
            let plaintext = try await processFoundMessage(
                ratchetMessage: message,
                usingMessageKey: messageKey,
                messageNumber: decrypted.messageNumber)
            // Commit prepared state and finalize message bookkeeping. We commit once per successfully
            // decrypted message to ensure counters/indices remain consistent with the derived keys.
            var commitState = state
            // Ensure we set lastDecrypted and counts based on message number n -> Ns = n+1
            commitState = await commitState.updateLastDecryptedMessageNumber(decrypted.messageNumber)
            commitState = await commitState.updateReceivedMessagesCount(decrypted.messageNumber + 1)
            alreadyDecryptedMessageNumbers.insert(decrypted.messageNumber)
            configuration.state = commitState
            try await updateSessionIdentity(configuration: configuration, persist: true)
            return plaintext
        }
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
            for i in receivedMessagesCount ..< messageNumber {
                let messageKey = try await symmetricKeyRatchet(from: receivingKey) //mk_i
                let nextReceivingKey = try await deriveChainKey(from: receivingKey, configuration: configuration) //nextCK
                let skipped = SkippedMessageKey(
                    remoteLongTermPublicKey: header.remoteLongTermPublicKey,
                    remoteOneTimePublicKey: header.remoteOneTimePublicKey?.rawRepresentation,
                    remoteMLKEMPublicKey: header.remoteMLKEMPublicKey.rawRepresentation,
                    messageIndex: i,
                    messageKey: messageKey)
                
                if !state.skippedMessageKeys.contains(where: { $0.messageIndex == i }) && !alreadyDecryptedMessageNumbers.contains(i) {
                    state = await state.updateSkippedMessage(skippedMessageKey: skipped)
                }
                state = await state.updateSkippedMessageIndex(i)
                receivingKey = nextReceivingKey
            }
        }
        
        // Prepare current MK_n and next CK
        let messageKey = try await symmetricKeyRatchet(from: receivingKey) //mk_n
        let nextReceivingChain = try await deriveChainKey(from: receivingKey, configuration: configuration) //ck_after_n
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
        configuration: SessionConfiguration
    ) async throws -> Data {
        
        var configuration = configuration
        guard var state = configuration.state else {
            throw RatchetError.stateUninitialized
        }
        
        let nonce = try await concatenate(
            associatedData: defaultRatchetConfiguration.associatedData,
            header: decodedMessage.ratchetMessage.header)
        guard nonce.count == 32 else {
            throw RatchetError.invalidNonceLength
        }
        
        let messageKey = try await symmetricKeyRatchet(from: decodedMessage.chainKey)
        
        if state.receivingHandshakeFinished == false {
            guard let decryptedMessage = try crypto.decrypt(
                data: decodedMessage.ratchetMessage.encryptedData,
                symmetricKey: messageKey) else {
                throw RatchetError.decryptionFailed
            }
            
            // If an OTK was used for this initial message and enforcement is enabled,
            // consume it via delegate and clear it from state to prevent reuse.
            if enforceOTKConsistency, let otkId = decodedMessage.ratchetMessage.header.oneTimeKeyId {
                await delegate?.updateOneTimeKey(remove: otkId)
                state = await state.updateLocalOneTimePrivateKey(nil)
            }
            
            // Increment count of received messages.
            state = await state.incrementReceivedMessagesCount()
            state = await state.updateReceivingHandshakeFinished(true)
            
            configuration.state = state
            try await updateSessionIdentity(configuration: configuration, persist: true)
            logger.log(level: .trace, message: "Initial receiving handshake succeeded")
            return decryptedMessage
        } else {
            guard let decryptedMessage = try crypto.decrypt(
                data: decodedMessage.ratchetMessage.encryptedData,
                symmetricKey: messageKey) else {
                throw RatchetError.decryptionFailed
            }
            state = await state.incrementReceivedMessagesCount()
            state = await state.updateLastDecryptedMessageNumber(messageNumber)
            state = await state.updateAlreadyDecryptedMessageNumber(messageNumber)
            
            alreadyDecryptedMessageNumbers.insert(messageNumber)
            configuration.state = state
            try await updateSessionIdentity(configuration: configuration, persist: true)
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
        let nonce = try await concatenate(
            associatedData: defaultRatchetConfiguration.associatedData,
            header: ratchetMessage.header)
        guard nonce.count == 32 else {
            throw RatchetError.invalidNonceLength
        }
        
        guard let decryptedMessage = try crypto.decrypt(
            data: ratchetMessage.encryptedData,
            symmetricKey: messageKey) else {
            throw RatchetError.decryptionFailed
        }
        return decryptedMessage
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
        configuration: RatchetConfiguration,
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
        header: EncryptedHeader,
    ) async throws -> Data {
        let headerData = try BSONEncoder().encode(header).makeData()
        let info = headerData + associatedData
        let digest = SHA256.hash(data: info)
        return digest.withUnsafeBytes { buffer in
            Data(buffer: buffer.bindMemory(to: UInt8.self))
        }
    }
    
    /// Executes a full Diffie-Hellman ratchet step, updating keys and session state based on new keys.
    ///
    /// - Parameter header: The header containing the new remote public keys.
    /// - Returns: An updated `RatchetState` after applying the DH ratchet.
    /// - Throws: `RatchetError.stateUninitialized` if the ratchet state is unavailable.
    private func diffieHellmanRatchet(
        header: EncryptedHeader? = nil,
        localKeys: LocalKeys? = nil,
        configuration: SessionConfiguration
    ) async throws -> RatchetState {
        // 1. Load current state
        var configuration = configuration
        guard var state = configuration.state else {
            throw RatchetError.stateUninitialized
        }
        logger.log(level: .trace, message: "Starting Diffie-Hellman ratchet step")
        
        // 2. Reset per-message counters and skipped caches
        logger.log(level: .trace, message: "Resetting message counters and clearing skipped message cache")
        state = await state
            .updatePreviousMessagesCount(state.sentMessagesCount)
            .updateSentMessagesCount(0)
            .updateReceivedMessagesCount(0)
            .resetAlreadyDecryptedMessageNumber()
            .removeAllSkippedHeaderMessage()
            .removeAllSkippedMessages()
            .updateSendingHandshakeFinished(false)
            .updateReceivingHandshakeFinished(false)
        
        if let header {
            // 3. Update remote public keys
            logger.log(level: .trace, message: "Updating remote public long-term key")
            state = await state.updateRemoteLongTermPublicKey(header.remoteLongTermPublicKey)
            
            logger.log(level: .trace, message: "Updating remote one-time key")
            state = await state.updateRemoteOneTimePublicKey(header.remoteOneTimePublicKey)
            
            // If a new MLKEM public key arrives, update in state
            logger.log(level: .trace, message: "Updating remote MLKEM key")
            state = await state.updateRemoteMLKEMPublicKey(header.remoteMLKEMPublicKey)
            
            let finalReceivingKey = try await derivePQXDHFinalKeyReceiver(
                remoteLongTermPublicKey: state.remoteLongTermPublicKey,
                remoteOneTimePublicKey: state.remoteOneTimePublicKey,
                localLongTermPrivateKey: state.localLongTermPrivateKey,
                localOneTimePrivateKey: state.localOneTimePrivateKey,
                localMLKEMPrivateKey: state.localMLKEMPrivateKey,
                receivedCiphertext: header.messageCiphertext)
            
            logger.log(level: .trace, message: "Deriving new receiving and sending keys and updating root key")
            // Derive chain key from the new root key.
            let receivingChainKey = try await deriveChainKey(from: finalReceivingKey, configuration: defaultRatchetConfiguration)
            let receivingKey = try await deriveChainKey(from: receivingChainKey, configuration: defaultRatchetConfiguration)
            let sendingChainKey = try await deriveChainKey(from: finalReceivingKey, configuration: defaultRatchetConfiguration)
            let sendingKey = try await deriveChainKey(from: sendingChainKey, configuration: defaultRatchetConfiguration)
            // Update root and receiving chain key in state for ratchet progression.
            state = await state.updateRootKey(finalReceivingKey)
            state = await state.updateCiphertext(header.messageCiphertext)
            state = await state.updateReceivingKey(receivingKey)
            state = await state.updateSendingKey(sendingKey)
            
            logger.log(level: .trace, message: "Receiving key and root key updated")
            
        } else if let localKeys {
            // 3. Update remote public keys
            logger.log(level: .trace, message: "Updating local public long-term key")
            state = await state.updateLocalLongTermPrivateKey(localKeys.longTerm.rawRepresentation)
            
            // If a new one-time key arrives, update in state
            logger.log(level: .trace, message: "Updating local one-time key")
            state = await state.updateLocalOneTimePrivateKey(localKeys.oneTime)
            
            // If a new MLKEM public key arrives, update in state
            logger.log(level: .trace, message: "Updating local MLKEM key")
            state = await state.updateLocalMLKEMPrivateKey(localKeys.mlKEM)
            
            let cipher = try await derivePQXDHFinalKey(
                localLongTermPrivateKey: state.localLongTermPrivateKey,
                localOneTimePrivateKey: state.localOneTimePrivateKey,
                remoteLongTermPublicKey: state.remoteLongTermPublicKey,
                remoteOneTimePublicKey: state.remoteOneTimePublicKey,
                remoteMLKEMPublicKey: state.remoteMLKEMPublicKey)
            
            logger.log(level: .trace, message: "Deriving new receiving and sending keys and updating root key")
            // Derive chain key from the new root key.
            let receivingChainKey = try await deriveChainKey(from: cipher.symmetricKey, configuration: defaultRatchetConfiguration)
            let receivingKey = try await deriveChainKey(from: receivingChainKey, configuration: defaultRatchetConfiguration)
            let sendingChainKey = try await deriveChainKey(from: cipher.symmetricKey, configuration: defaultRatchetConfiguration)
            let sendingKey = try await deriveChainKey(from: sendingChainKey, configuration: defaultRatchetConfiguration)
            // Update root and receiving chain key in state for ratchet progression.
            state = await state.updateRootKey(cipher.symmetricKey)
            state = await state.updateCiphertext(cipher.ciphertext)
            state = await state.updateReceivingKey(receivingKey)
            state = await state.updateSendingKey(sendingKey)
            
        }
        logger.log(level: .trace, message: "Ratchet state successfully updated and returned")
        configuration.state = state
        try await updateSessionIdentity(configuration: configuration)
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
        remotePublicKey: RemotePublicKey,
    ) async throws -> SharedSecret {
        let localPrivateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: localPrivateKey)
        let remotePublicKeyData = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: remotePublicKey)
        return try localPrivateKey.sharedSecretFromKeyAgreement(with: remotePublicKeyData)
    }
    
    /// A container for encapsulated MLKEM ciphertext and resulting symmetric key.
    private struct PQXDHCipher: Sendable {
        let ciphertext: Data
        let symmetricKey: SymmetricKey
    }
    
    /// Derives a PQ-X3DH hybrid key (sender side), combining Curve25519 and Kyber-1024 key exchange.
    ///
    /// - Returns: A `PQXDHCipher` containing MLKEM ciphertext and final symmetric key.
    /// - Throws: Errors during key agreement or encapsulation.
    private func derivePQXDHFinalKey(
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
    
    /// Derives the PQ-X3DH final key from received ciphertext and Curve25519 keys (receiver side).
    ///
    /// - Throws: Errors during shared secret derivation or MLKEM decapsulation.
    private func derivePQXDHFinalKeyReceiver(
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
        
        let localMLKEMPK = localMLKEMPrivateKey.rawRepresentation.decodeMLKem1024()
        let decapsulatedBytes = try localMLKEMPK.decapsulate(receivedCiphertext).bytes
        // Use local private one-time public key as salt if available, else fallback to long-term public key
        let salt: Data
        if let localOTKey = localOneTimePrivateKey {
            let curveKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: localOTKey.rawRepresentation)
            let mlKEMKey = localMLKEMPrivateKey.rawRepresentation.decodeMLKem1024()
            salt = curveKey.publicKey.rawRepresentation + mlKEMKey.publicKey.rawRepresentation
        } else {
            let curveKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: localLongTermPrivateKey)
            let mlKEMKey = localMLKEMPrivateKey.rawRepresentation.decodeMLKem1024()
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
}

extension RatchetStateManager {
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
        configuration: SessionConfiguration
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
        
        // 1. Serialize the message header using BSON.
        let headerPlain = try BSONEncoder().encodeData(header)
        
        // 2. Construct a 96-bit nonce using the message counter.
        let counter = state.sentMessagesCount
        let nonceSize = 12
        var ctrBytes = withUnsafeBytes(of: UInt64(counter).bigEndian) { Data($0) }
        ctrBytes.append(contentsOf: [UInt8](repeating: 0, count: nonceSize - ctrBytes.count))
        
        let nonce = try AES.GCM.Nonce(data: ctrBytes)
        let messageKey = try await symmetricKeyRatchet(from: sendingHeaderKey)
        
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

extension RatchetStateManager {
    
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
        configuration: SessionConfiguration
    ) async throws -> EncryptedHeader {
        var configuration = configuration
        for _ in 0..<defaultRatchetConfiguration.maxSkippedMessageKeys {
            guard let state = configuration.state else {
                throw RatchetError.stateUninitialized
            }
            // Try any stashed header keys first
            for skipped in state.skippedHeaderMessages {
                if let header = try? await attemptHeaderDecryption(encryptedHeader: encryptedHeader, chainKey: skipped.chainKey) {
                    return header
                }
            }
            // Try current receiving header key
            guard let chainKey = state.receivingHeaderKey else {
                throw RatchetError.receivingHeaderKeyIsNil
            }
            if let header = try? await attemptHeaderDecryption(encryptedHeader: encryptedHeader, chainKey: chainKey) {
                return header
            }
            // If still failing, advance header chain until we either decrypt or hit the cap
            if state.skippedHeaderMessages.count >= defaultRatchetConfiguration.maxSkippedMessageKeys {
                throw RatchetError.maxSkippedHeadersExceeded
            }
            var stateToAdvance = state
            stateToAdvance = await stateToAdvance.incrementSkippedHeaderIndex()
            guard let currentHeaderKey = stateToAdvance.receivingHeaderKey else {
                throw RatchetError.receivingHeaderKeyIsNil
            }
            let skippedHeader = SkippedHeaderMessage(chainKey: currentHeaderKey, index: stateToAdvance.headerIndex)
            stateToAdvance = await stateToAdvance.updateSkippedHeaderMessage(skippedHeader)
            let nextChainKey = try await deriveChainKey(from: currentHeaderKey, configuration: defaultRatchetConfiguration)
            stateToAdvance = await stateToAdvance.updateReceivingHeaderKey(nextChainKey)
            configuration.state = stateToAdvance
            try await updateSessionIdentity(configuration: configuration, persist: true)
        }
        throw RatchetError.maxSkippedHeadersExceeded
    }

    
    private func attemptHeaderDecryption(
        encryptedHeader: EncryptedHeader,
        chainKey: SymmetricKey
    ) async throws -> EncryptedHeader {
        var encryptedHeader = encryptedHeader
        let messageKey = try await symmetricKeyRatchet(from: chainKey)
        
        guard let decryptedData = try crypto.decrypt(data: encryptedHeader.encrypted, symmetricKey: messageKey) else {
            throw CryptoError.decryptionFailed
        }
        let header = try BSONDecoder().decodeData(MessageHeader.self, from: decryptedData)
        encryptedHeader.setDecrypted(header)
        return encryptedHeader
    }
    
    /// Advances the receiving header key by one step and stashes the current header chain key.
    ///
    /// - Behavior:
    ///   - Increments the header index and stores the current `receivingHeaderKey` in `skippedHeaderMessages`.
    ///   - Derives the next header chain key and updates `receivingHeaderKey` to prepare for another attempt.
    ///   - Persists the updated state and immediately attempts header decryption with the stashed key.
    ///
    /// - Throws:
    ///   - `RatchetError.stateUninitialized` if state is missing.
    ///   - `RatchetError.maxSkippedHeadersExceeded` if the cap is reached.
    ///   - `RatchetError.receivingHeaderKeyIsNil` if the current header key is unavailable.
    private func generateSkippedHeaderMessage(
        encryptedHeader: EncryptedHeader,
        configuration: SessionConfiguration
    ) async throws -> EncryptedHeader {
        
        var configuration = configuration
        guard var state = configuration.state else {
            throw RatchetError.stateUninitialized
        }
        
        //If we maxed out throw the error
        if state.skippedHeaderMessages.count >= defaultRatchetConfiguration.maxSkippedMessageKeys {
            throw RatchetError.maxSkippedHeadersExceeded
        }
        
        state = await state.incrementSkippedHeaderIndex()
        guard let chainKey = state.receivingHeaderKey else {
            throw RatchetError.receivingHeaderKeyIsNil
        }
        let skippedHeader = SkippedHeaderMessage(
            chainKey: chainKey, //Stash the current chainkey that we skipped
            index: state.headerIndex)
        
        state = await state.updateSkippedHeaderMessage(skippedHeader) //Stashing
        
        // Produce the next chainKey that will decrypt the current message i.e 3 came but exepected 2, so ratchet
        let nextChainKey = try await deriveChainKey(from: chainKey, configuration: defaultRatchetConfiguration)
        
        state = await state.updateReceivingHeaderKey(nextChainKey) //The next time we call decrypt it will decrypt the current message... if not we ratchet again.
        
        configuration.state = state
        try await updateSessionIdentity(configuration: configuration, persist: true)
        return try await attemptHeaderDecryption(encryptedHeader: encryptedHeader, chainKey: chainKey)
    }
}

