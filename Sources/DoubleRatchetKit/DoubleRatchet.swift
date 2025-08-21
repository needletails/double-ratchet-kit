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
import Logging
import SwiftKyber
#if os(Android)
@preconcurrency import Crypto
#else
import Crypto
#endif

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
    private var logger: NeedleTailLogger
    /// Tracks whether `shutdown()` has been called.
    private nonisolated(unsafe) var didShutdown = false
    /// Holds all known session configurations keyed by session identity.
    public private(set) var sessionConfigurations = [SessionConfiguration]()

    /// The currently active session configuration.
    private var currentConfiguration: SessionConfiguration?
    private var state: RatchetState?
    public weak var delegate: SessionIdentityDelegate?
    public func setDelegate(_ delegate: SessionIdentityDelegate) {
        self.delegate = delegate
    }

    // Working with the set locally for performance.
    private var alreadyDecryptedMessageNumbers = Set<Int>()
    private var keysRotated = false

    // MARK: - Initialization

    /// Initializes the ratchet state manager.
    /// - Parameters:
    ///  - executor: A `SerialExecutor` used to coordinate concurrent operations within the actor.
    ///  - logger: The Logger
    public init(executor: any SerialExecutor, logger: NeedleTailLogger = NeedleTailLogger()) {
        self.executor = executor
        self.logger = logger
    }

    deinit {
        precondition(didShutdown, "⛔️ RatchetStateManager was deinitialized without calling shutdown(). ")
    }
    
    public func setLogLevel(_ level: Logging.Logger.Level) async {
        logger.setLogLevel(level)
    }

    /// This must be called when the manager is done being used
    public func shutdown() async throws {
        if var state {
            state = await state.setAlreadyDecryptedMessageNumbers(alreadyDecryptedMessageNumbers)
            try await updateSessionIdentity(state: state)
        }
        sessionConfigurations.removeAll()
        currentConfiguration = nil
        state = nil
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
        let remotePQKemPublicKey: RemotePQKemPublicKey
        let localLongTermPrivateKey: LocalLongTermPrivateKey
        let localOneTimePrivateKey: LocalOneTimePrivateKey?
        let localPQKemPrivateKey: LocalPQKemPrivateKey

        init(remotePublicLongTermKey: RemoteLongTermPublicKey,
             remoteOneTimePublicKey: RemoteOneTimePublicKey?,
             remotePQKemPublicKey: RemotePQKemPublicKey,
             localLongTermPrivateKey: LocalLongTermPrivateKey,
             localOneTimePrivateKey: LocalOneTimePrivateKey?,
             localPQKemPrivateKey: LocalPQKemPrivateKey)
        {
            remoteLongTermPublicKey = remotePublicLongTermKey
            self.remoteOneTimePublicKey = remoteOneTimePublicKey
            self.remotePQKemPublicKey = remotePQKemPublicKey
            self.localLongTermPrivateKey = localLongTermPrivateKey
            self.localOneTimePrivateKey = localOneTimePrivateKey
            self.localPQKemPrivateKey = localPQKemPrivateKey
        }

        public init(
            remote: RemoteKeys,
            local: LocalKeys
        ) {
            self.init(
                remotePublicLongTermKey: remote.longTerm.rawRepresentation,
                remoteOneTimePublicKey: remote.oneTime,
                remotePQKemPublicKey: remote.pqKem,
                localLongTermPrivateKey: local.longTerm.rawRepresentation,
                localOneTimePrivateKey: local.oneTime,
                localPQKemPrivateKey: local.pqKem)
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
        messageType: MessageType,
    ) async throws {
        // 1. Check if we have a currently loaded session
        if let index = sessionConfigurations.firstIndex(where: {
            $0.sessionIdentity.id == sessionIdentity.id
        }) {
            logger.log(level: .trace, message: "Found Session Identity, reusing ratchet state")
            guard var currentProps = await currentConfiguration?
                .sessionIdentity
                .props(symmetricKey: sessionSymmetricKey)
            else {
                throw RatchetError.missingProps
            }

            // If we have a session and we call this method again we need to check if it is a new type
            switch messageType {
            case let .sending(keys):
                let state = try await getRatchetState()
                var changesDetected = false
                defer {
                    changesDetected = false
                }

                func checkKeyChanges() {
                    if state.localLongTermPrivateKey != keys.localLongTermPrivateKey {
                        logger.log(level: .trace, message: "Sending long term key has changed")
                        changesDetected = true
                    }

                    if state.localOneTimePrivateKey != keys.localOneTimePrivateKey {
                        logger.log(level: .trace, message: "Sending one time key has changed")
                        changesDetected = true
                    }

                    if state.localPQKemPrivateKey != keys.localPQKemPrivateKey {
                        logger.log(level: .trace, message: "Sending pqKem key has changed")
                        changesDetected = true
                    }
                }
                checkKeyChanges()
                
                // Just update the keys
                currentProps.state = await currentProps.state?.updateRemoteLongTermPublicKey(keys.remoteLongTermPublicKey)
                currentProps.state = await currentProps.state?.updateRemoteOneTimePublicKey(keys.remoteOneTimePublicKey)
                currentProps.state = await currentProps.state?.updateRemotePQKemPublicKey(keys.remotePQKemPublicKey)
                currentProps.state = await currentProps.state?.updateLocalLongTermPrivateKey(keys.localLongTermPrivateKey)
                currentProps.state = await currentProps.state?.updateLocalOneTimePrivateKey(keys.localOneTimePrivateKey)
                currentProps.state = await currentProps.state?.updateLocalPQKemPrivateKey(keys.localPQKemPrivateKey)

                if changesDetected {
                     currentProps.setLongTermPublicKey(keys.remoteLongTermPublicKey)
                    if let key = keys.remoteOneTimePublicKey {
                        currentProps.setOneTimePublicKey(key)
                    }
                    
                    currentProps.setPQKemPublicKey(keys.remotePQKemPublicKey)
                    currentProps.state = try await diffieHellmanRatchet(
                        localKeys: .init(
                            longTerm: .init(keys.localLongTermPrivateKey),
                            oneTime: keys.localOneTimePrivateKey,
                            pqKem: keys.localPQKemPrivateKey))
                    
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
            case .receiving:
                break //We check if the receiving keys change in ratchet decrypt for key rotation logic
            }

            state = currentProps.state
            try await sessionIdentity.updateIdentityProps(symmetricKey: sessionSymmetricKey, props: currentProps)

            var config = sessionConfigurations[index]
            config.sessionIdentity = sessionIdentity
            config.sessionSymmetricKey = sessionSymmetricKey
            sessionConfigurations[index] = config
            currentConfiguration = config
            try await delegate?.updateSessionIdentity(sessionIdentity)
        } else {
            logger.log(level: .trace, message: "Session Identity not found, creating state for ratchet")
            let configuration = SessionConfiguration(
                sessionIdentity: sessionIdentity,
                sessionSymmetricKey: sessionSymmetricKey)
            currentConfiguration = configuration

            guard var props = await sessionIdentity.props(symmetricKey: sessionSymmetricKey) else {
                throw RatchetError.missingProps
            }
            if let state = props.state {
                alreadyDecryptedMessageNumbers = state.alreadyDecryptedMessageNumbers
                self.state = state
            } else {
                let state = try await setState(for: messageType)
                props.state = state
                try await sessionIdentity.updateIdentityProps(symmetricKey: sessionSymmetricKey, props: props)
                currentConfiguration?.sessionIdentity = sessionIdentity
                self.state = state
            }

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
            symmetricKey: currentConfiguration.sessionSymmetricKey) else {
            throw RatchetError.missingProps
        }
        return props
    }

    private func getRatchetState() async throws -> RatchetState {
        guard let state else {
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
        
        let oldState = props.state
#if DEBUG
        if let oldState = oldState {
            await logRatchetStateDifferences(from: oldState, to: state)
        }
#endif
        props.state = state

        try await currentConfiguration.sessionIdentity.updateIdentityProps(
            symmetricKey: currentConfiguration.sessionSymmetricKey,
            props: props)
        
        try await delegate?.updateSessionIdentity(currentConfiguration.sessionIdentity)
        if let index = sessionConfigurations.firstIndex(where: { $0.sessionIdentity.id == currentConfiguration.sessionIdentity.id }) {
            sessionConfigurations[index] = currentConfiguration
            self.currentConfiguration = currentConfiguration
        }
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
        if old.localPQKemPrivateKey.rawRepresentation != new.localPQKemPrivateKey.rawRepresentation {
            logger.log(level: .trace, message: "localPQKemPrivateKey changed")
        }
        if old.remoteLongTermPublicKey != new.remoteLongTermPublicKey {
            logger.log(level: .trace, message: "remoteLongTermPublicKey changed")
        }
        if old.remoteOneTimePublicKey?.rawRepresentation != new.remoteOneTimePublicKey?.rawRepresentation {
            logger.log(level: .trace, message: "remoteOneTimePublicKey changed")
        }
        if old.remotePQKemPublicKey.rawRepresentation != new.remotePQKemPublicKey.rawRepresentation {
            logger.log(level: .trace, message: "remotePQKemPublicKey changed")
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
    private func setState(for messageType: MessageType) async throws -> RatchetState {
        switch messageType {
        case let .receiving(recipientKeys):
            return RatchetState(
                remoteLongTermPublicKey: recipientKeys.remoteLongTermPublicKey,
                remoteOneTimePublicKey: recipientKeys.remoteOneTimePublicKey,
                remotePQKemPublicKey: recipientKeys.remotePQKemPublicKey,
                localLongTermPrivateKey: recipientKeys.localLongTermPrivateKey,
                localOneTimePrivateKey: recipientKeys.localOneTimePrivateKey,
                localPQKemPrivateKey: recipientKeys.localPQKemPrivateKey)
        case let .sending(senderKeys):
            let (sendingKey, cipher) = try await deriveNextMessageKey(
                localLongTermPrivateKey: senderKeys.localLongTermPrivateKey,
                remotePublicLongTermKey: senderKeys.remoteLongTermPublicKey,
                localOneTimePrivateKey: senderKeys.localOneTimePrivateKey,
                remoteOneTimePublicKey: senderKeys.remoteOneTimePublicKey,
                remotePQKemPublicKey: senderKeys.remotePQKemPublicKey)
            return RatchetState(
                remoteLongTermPublicKey: senderKeys.remoteLongTermPublicKey,
                remoteOneTimePublicKey: senderKeys.remoteOneTimePublicKey,
                remotePQKemPublicKey: senderKeys.remotePQKemPublicKey,
                localLongTermPrivateKey: senderKeys.localLongTermPrivateKey,
                localOneTimePrivateKey: senderKeys.localOneTimePrivateKey,
                localPQKemPrivateKey: senderKeys.localPQKemPrivateKey,
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
    ///   - remoteKeys: The recipient's public keys, including long-term, one-time, and PQKem keys.
    ///   - localKeys: The sender's private keys, including long-term, one-time, and PQKem keys.
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
    ///   - remoteKeys: The sender's public keys used to derive the shared secret.
    ///   - localKeys: The receiver's private keys required for decryption and ratchet initialization.
    /// - Throws: An error if the message cannot be decrypted or the session cannot be initialized.
    public func recipientInitialization(
        sessionIdentity: SessionIdentity,
        sessionSymmetricKey: SymmetricKey,
        remoteKeys: RemoteKeys,
        localKeys: LocalKeys,
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
        logger.log(level: .trace, message: "Ratchet encrypt started")

        var state = try await getRatchetState()

        // Step 2: Construct ratchet header metadata.
        let messageHeader = MessageHeader(
            previousChainLength: state.previousMessagesCount,
            messageNumber: state.sentMessagesCount)

        if !state.sendingHandshakeFinished {
            // Step 3: Derive symmetric header encryption key using hybrid PQXDH.
            let headerCipher = try await derivePQXDHFinalKey(
                localLongTermPrivateKey: state.localLongTermPrivateKey,
                remotePublicLongTermKey: state.remoteLongTermPublicKey,
                localOneTimePrivateKey: state.localOneTimePrivateKey,
                remoteOneTimePublicKey: state.remoteOneTimePublicKey,
                remotePQKemPublicKey: state.remotePQKemPublicKey)

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
        let localLongTermPublicKey = try Curve25519PrivateKey(rawRepresentation: state.localLongTermPrivateKey)
            .publicKey.rawRepresentation
        var remoteOneTimePublicKey: RemoteOneTimePublicKey?
        if let localOneTimePrivateKey = state.localOneTimePrivateKey {
            let localOneTimePublicKey = try Curve25519PrivateKey(rawRepresentation: localOneTimePrivateKey.rawRepresentation).publicKey.rawRepresentation
            remoteOneTimePublicKey = try RemoteOneTimePublicKey(id: localOneTimePrivateKey.id, localOneTimePublicKey)
        }
        let localPQKemPublicKey = state.localPQKemPrivateKey.rawRepresentation.decodeKyber1024()
            .publicKey.rawRepresentation
        let remotePQKemPublicKey = try RemotePQKemPublicKey(id: state.localPQKemPrivateKey.id, localPQKemPublicKey)
        self.state = state

        // Step 6: Encrypt the message header using AEAD.
        let encryptedHeader = try await encryptHeader(
            messageHeader,
            remoteLongTermPublicKey: localLongTermPublicKey,
            remoteOneTimePublicKey: remoteOneTimePublicKey,
            remotePQKemPublicKey: remotePQKemPublicKey,
            oneTimeKeyId: state.remoteOneTimePublicKey?.id,
            pqKemOneTimeKeyId: state.remotePQKemPublicKey.id)

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
        defer {
            logger.log(level: .trace, message: "Encryption Succeeded")
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
        self.state = state
        try await updateSessionIdentity(state: state)
        return RatchetMessage(
            header: encryptedHeader,
            encryptedData: encryptedData)
    }

    /// Runs PQXDH, then HKDF chain-key, then HMAC ratchet to get the next message key.
    private func deriveNextMessageKey(localLongTermPrivateKey: LocalLongTermPrivateKey,
                                      remotePublicLongTermKey: RemoteLongTermPublicKey,
                                      localOneTimePrivateKey: LocalOneTimePrivateKey?,
                                      remoteOneTimePublicKey: RemoteOneTimePublicKey?,
                                      remotePQKemPublicKey: RemotePQKemPublicKey) async throws -> (SymmetricKey, PQXDHCipher)
    {
        let cipher = try await derivePQXDHFinalKey(
            localLongTermPrivateKey: localLongTermPrivateKey,
            remotePublicLongTermKey: remotePublicLongTermKey,
            localOneTimePrivateKey: localOneTimePrivateKey,
            remoteOneTimePublicKey: remoteOneTimePublicKey,
            remotePQKemPublicKey: remotePQKemPublicKey)

        let newChainKey = try await deriveChainKey(
            from: cipher.symmetricKey,
            configuration: defaultRatchetConfiguration)

        if var state = try await sessionProps().state {
            state = await state.updateRootKey(cipher.symmetricKey)
            state = await state.updateCiphertext(cipher.ciphertext)
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
    public func ratchetDecrypt(_ message: RatchetMessage) async throws -> Data {
        logger.log(level: .trace, message: "Ratchet decrypt started")

        var state = try await getRatchetState()

        func checkKeyChanges() {
            var changesDetected = false

            if state.remoteLongTermPublicKey != message.header.remoteLongTermPublicKey {
                logger.log(level: .trace, message: "Receiving long term key has changed")
                changesDetected = true
            }

            if state.remoteOneTimePublicKey != message.header.remoteOneTimePublicKey {
                logger.log(level: .trace, message: "Receiving one time key has changed")
                changesDetected = true
            }

            if state.remotePQKemPublicKey != message.header.remotePQKemPublicKey {
                logger.log(level: .trace, message: "Receiving pqKem key has changed")
                changesDetected = true
            }

            keysRotated = changesDetected
        }
        checkKeyChanges()

        if keysRotated {
            // Perform Diffie-Hellman ratchet to update root key, chain keys, and ratchet state.
            state = try await diffieHellmanRatchet(header: message.header)
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
                localPQKemPrivateKey: state.localPQKemPrivateKey,
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
        state = try await getRatchetState()
        
        // Ensure header was successfully decrypted before continuing.
        guard let decrypted = header.decrypted else {
            throw RatchetError.headerDecryptFailed
        }

        if keysRotated {
            logger.log(level: .trace, message: "Keys Rotated")
            if let key = state.skippedMessageKeys.first(where: { $0.messageIndex == decrypted.messageNumber }) {
                logger.log(level: .trace, message: "Trying skipped message key index \(key.messageIndex)")
                state = await state.removeSkippedMessages(at: key.messageIndex)
                self.state = state
                try await updateSessionIdentity(state: state)

                // Decrypt using stored message key
                let plaintext = try await processFoundMessage(
                    ratchetMessage: message,
                    usingMessageKey: key.messageKey,
                    state: state,
                    messageNumber: decrypted.messageNumber
                )
                return plaintext
            }
            
            // Message gap-fill is handled later via deriveMessageKey for the current chain

            // On key change, advance receiving header key to next and perform DH ratchet step.
            guard let nextReceivingHeaderKey = state.nextReceivingHeaderKey else {
                throw RatchetError.missingNextHeaderKey
            }
            state = await state.updateReceivingNextHeaderKey(nextReceivingHeaderKey)
            self.state = state

            // After ratchet, derive next header key and update state.
            let newNextReceivingHeaderKey = try await derivePQXDHFinalKey(
                localLongTermPrivateKey: state.localLongTermPrivateKey,
                remotePublicLongTermKey: state.remoteLongTermPublicKey,
                localOneTimePrivateKey: state.localOneTimePrivateKey,
                remoteOneTimePublicKey: state.remoteOneTimePublicKey,
                remotePQKemPublicKey: state.remotePQKemPublicKey)

            state = await state.updateReceivingNextHeaderKey(newNextReceivingHeaderKey.symmetricKey)
            keysRotated = false
        } else {
            // No key change detected:
            if !state.receivingHandshakeFinished {
                // During handshake, derive and store next receiving header key for upcoming messages.
                let newNextReceivingHeaderKey = try await derivePQXDHFinalKey(
                    localLongTermPrivateKey: state.localLongTermPrivateKey,
                    remotePublicLongTermKey: state.remoteLongTermPublicKey,
                    localOneTimePrivateKey: state.localOneTimePrivateKey,
                    remoteOneTimePublicKey: state.remoteOneTimePublicKey,
                    remotePQKemPublicKey: state.remotePQKemPublicKey,
                )

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
        
        // Before this is header decryption and keys change logic(Keys are not changing in this scenario)
        if let key = state.skippedMessageKeys.first(where: {
            $0.messageIndex == decrypted.messageNumber &&
                $0.remoteLongTermPublicKey == header.remoteLongTermPublicKey &&
                $0.remotePQKemPublicKey == header.remotePQKemPublicKey.rawRepresentation
        }) {
            logger.log(level: .trace, message: "Trying skipped message key index \(key.messageIndex)")
            if let oneTimeKey = key.remoteOneTimePublicKey, oneTimeKey != header.remoteOneTimePublicKey?.rawRepresentation {
                throw RatchetError.expiredKey
            }
            state = await state.removeSkippedMessages(at: key.messageIndex)
            self.state = state
            try await updateSessionIdentity(state: state)
            // Decrypt using stored message key
            return try await processFoundMessage(
                ratchetMessage: message,
                usingMessageKey: key.messageKey,
                state: state,
                messageNumber: decrypted.messageNumber
            )
        }
        // Gap-fill and prepare MK for current message using a working copy, commit after decrypt
        var preparedState = state
        var preparedMessageKey: SymmetricKey? = nil
        if state.receivingHandshakeFinished {
            (preparedState, preparedMessageKey) = try await deriveMessageKey(
                header: header,
                configuration: defaultRatchetConfiguration,
                state: state
            )
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
                    localPQKemPrivateKey: state.localPQKemPrivateKey,
                    receivedCiphertext: message.header.messageCiphertext,
                )

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
                    // if we have a root key but not a receiving key create a receiving key from the root key
                    chainKey = try await deriveChainKey(
                        from: state.rootKey!,
                        configuration: defaultRatchetConfiguration,
                    )
                }

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
            // Subsequent messages after handshake, decrypt using prepared MK, then commit prepared state exactly once
            guard let messageKey = preparedMessageKey else { throw RatchetError.decryptionFailed }
            // Try decrypt without committing state
            let plaintext = try await processFoundMessage(
                ratchetMessage: message,
                usingMessageKey: messageKey,
                state: state,
                messageNumber: decrypted.messageNumber
            )
            // Commit prepared state and finalize message bookkeeping
            var commitState = preparedState
            // Ensure we set lastDecrypted and counts based on message number n -> Ns = n+1
            commitState = await commitState.updateLastDecryptedMessageNumber(decrypted.messageNumber)
            commitState = await commitState.updateReceivedMessagesCount(decrypted.messageNumber + 1)
            alreadyDecryptedMessageNumbers.insert(decrypted.messageNumber)
            self.state = commitState
            try await updateSessionIdentity(state: commitState)
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
                    remotePQKemPublicKey: header.remotePQKemPublicKey.rawRepresentation,
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

    // legacy generateSkippedMessageKeys removed; consolidated into deriveMessageKey

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
        messageNumber: Int,
    ) async throws -> Data {
        var state = state
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

            // Increment count of received messages.
            state = await state.incrementReceivedMessagesCount()
            state = await state.updateReceivingHandshakeFinished(true)
            self.state = state
            try await updateSessionIdentity(state: state)
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

            alreadyDecryptedMessageNumbers.insert(messageNumber)
            self.state = state
            try await updateSessionIdentity(state: state)
            logger.log(level: .trace, message: "Decryption Succeeded")
            return decryptedMessage
        }
    }

    // Decrypt using a pre-derived message key. This function does NOT mutate state.
    private func processFoundMessage(
        ratchetMessage: RatchetMessage,
        usingMessageKey messageKey: SymmetricKey,
        state: RatchetState,
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
    private func diffieHellmanRatchet(header: EncryptedHeader? = nil, localKeys: LocalKeys? = nil) async throws -> RatchetState {
        // 1. Load current state
        var state = try await getRatchetState()
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
            state = await state.updateRemoteLongTermPublicKey(header.remoteLongTermPublicKey)
            logger.log(level: .trace, message: "Updating remote public long-term key")
            // If a new one-time key arrives, update in state
            if state.remoteOneTimePublicKey != header.remoteOneTimePublicKey {
                logger.log(level: .trace, message: "Updating remote one-time key: \(String(describing: header.remoteOneTimePublicKey?.id))")
                state = await state.updateRemoteOneTimePublicKey(header.remoteOneTimePublicKey)
            }

            // If a new PQKem public key arrives, update in state
            if state.remotePQKemPublicKey != header.remotePQKemPublicKey {
                logger.log(level: .trace, message: "Updating remote PQKem key: \(header.remotePQKemPublicKey.id)")
                state = await state.updateRemotePQKemPublicKey(header.remotePQKemPublicKey)
            }

            let finalReceivingKey = try await derivePQXDHFinalKeyReceiver(
                remoteLongTermPublicKey: state.remoteLongTermPublicKey,
                remoteOneTimePublicKey: state.remoteOneTimePublicKey,
                localLongTermPrivateKey: state.localLongTermPrivateKey,
                localOneTimePrivateKey: state.localOneTimePrivateKey,
                localPQKemPrivateKey: state.localPQKemPrivateKey,
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
            state = await state.updateLocalLongTermPrivateKey(localKeys.longTerm.rawRepresentation)
            logger.log(level: .trace, message: "Updating local public long-term key")

            // If a new one-time key arrives, update in state
            if state.localOneTimePrivateKey != localKeys.oneTime {
                logger.log(level: .trace, message: "Updating local one-time key")
                state = await state.updateLocalOneTimePrivateKey(localKeys.oneTime)
            }

            // If a new PQKem public key arrives, update in state
            if state.localPQKemPrivateKey != localKeys.pqKem {
                logger.log(level: .trace, message: "Updating local PQKem key")
                state = await state.updateLocalPQKemPrivateKey(localKeys.pqKem)
            }
            
            let cipher = try await derivePQXDHFinalKey(
                localLongTermPrivateKey: state.localLongTermPrivateKey,
                remotePublicLongTermKey: state.remoteLongTermPublicKey,
                localOneTimePrivateKey: state.localOneTimePrivateKey,
                remoteOneTimePublicKey: state.remoteOneTimePublicKey,
                remotePQKemPublicKey: state.remotePQKemPublicKey)

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

    /// A container for encapsulated PQKem ciphertext and resulting symmetric key.
    private struct PQXDHCipher: Sendable {
        let ciphertext: Data
        let symmetricKey: SymmetricKey
    }

    /// Derives a PQ-X3DH hybrid key (sender side), combining Curve25519 and Kyber-1024 key exchange.
    ///
    /// - Returns: A `PQXDHCipher` containing PQKem ciphertext and final symmetric key.
    /// - Throws: Errors during key agreement or encapsulation.
    private func derivePQXDHFinalKey(
        localLongTermPrivateKey: LocalLongTermPrivateKey,
        remotePublicLongTermKey: RemoteLongTermPublicKey,
        localOneTimePrivateKey: LocalOneTimePrivateKey?,
        remoteOneTimePublicKey: RemoteOneTimePublicKey?,
        remotePQKemPublicKey: RemotePQKemPublicKey,
    ) async throws -> PQXDHCipher {
        let K_A = try await deriveSharedSecret(localPrivateKey: localLongTermPrivateKey, remotePublicKey: remotePublicLongTermKey)

        var K_A_ot_data = Data()
        if let localOTKey = localOneTimePrivateKey, let remoteOTKey = remoteOneTimePublicKey {
            let K_A_ot = try await deriveSharedSecret(localPrivateKey: localOTKey.rawRepresentation, remotePublicKey: remoteOTKey.rawRepresentation)
            K_A_ot_data = K_A_ot.bytes
        }

        let K_A_data = K_A.bytes

        let remotePQKemPK = Kyber1024.KeyAgreement.PublicKey(rawRepresentation: remotePQKemPublicKey.rawRepresentation)
        let (ciphertext, sharedSecret) = try remotePQKemPK.encapsulate()
        let concatenatedSecrets = K_A_data + K_A_ot_data + sharedSecret.bytes

        let salt: Data = if let remoteOTKey = remoteOneTimePublicKey {
            remoteOTKey.rawRepresentation + remotePQKemPublicKey.rawRepresentation
        } else {
            // Use the remote long-term public key as a fallback salt (stable, non-empty)
            remotePublicLongTermKey + remotePQKemPublicKey.rawRepresentation
        }
        let symmetricKey = HKDF<SHA512>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: concatenatedSecrets),
            salt: salt,
            outputByteCount: 32)

        return PQXDHCipher(ciphertext: ciphertext, symmetricKey: symmetricKey)
    }

    /// Derives the PQ-X3DH final key from received ciphertext and Curve25519 keys (receiver side).
    ///
    /// - Throws: Errors during shared secret derivation or PQKem decapsulation.
    private func derivePQXDHFinalKeyReceiver(
        remoteLongTermPublicKey: RemoteLongTermPublicKey,
        remoteOneTimePublicKey: RemoteOneTimePublicKey?,
        localLongTermPrivateKey: LocalLongTermPrivateKey,
        localOneTimePrivateKey: LocalOneTimePrivateKey?,
        localPQKemPrivateKey: LocalPQKemPrivateKey,
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

        // Derive PQKem shared secret from ciphertext
        let localPQKemPK = localPQKemPrivateKey.rawRepresentation.decodeKyber1024()
        let sharedSecret = try localPQKemPK.sharedSecret(from: receivedCiphertext)
        
        // Use local private one-time public key as salt if available, else fallback to long-term public key
        let salt: Data
        if let localOTKey = localOneTimePrivateKey {
            let curveKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: localOTKey.rawRepresentation)
            let pqKemKey = localPQKemPrivateKey.rawRepresentation.decodeKyber1024()
            salt = curveKey.publicKey.rawRepresentation + pqKemKey.publicKey.rawRepresentation
        } else {
            let curveKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: localLongTermPrivateKey)
            let pqKemKey = localPQKemPrivateKey.rawRepresentation.decodeKyber1024()
            salt = curveKey.publicKey.rawRepresentation + pqKemKey.publicKey.rawRepresentation
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
    ///   - remotePublicLongTermKey: The recipient's Curve public key.
    ///   - remoteOneTimePublicKey: The recipient's ephemeral Curve public key.
    ///   - remotePQKemPublicKey: The recipient's PQKem public key.
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
        remotePQKemPublicKey: RemotePQKemPublicKey,
        oneTimeKeyId: UUID?,
        pqKemOneTimeKeyId: UUID,
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
            remotePQKemPublicKey: remotePQKemPublicKey,
            headerCiphertext: headerCiphertext,
            messageCiphertext: messageCiphertext,
            oneTimeKeyId: oneTimeKeyId,
            pqKemOneTimeKeyId: pqKemOneTimeKeyId,
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
        for headerMessage in state.skippedHeaderMessages {
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
            if state.skippedHeaderMessages.count >= defaultRatchetConfiguration.maxSkippedMessageKeys {
                throw RatchetError.maxSkippedHeadersExceeded
            }

            for skipped in state.skippedHeaderMessages {
                if let (decrypted, newState) = try? await decryptHeaderMessage(
                    encryptedHeader: encryptedHeader,
                    chainKey: skipped.chainKey,
                    index: skipped.index,
                    state: state
                ) {
                    self.state = newState
                    return decrypted
                }
            }

            state = try await headerRatchet(chainKey: chainKey, state: state)
            self.state = state
            return try await decryptHeader(encryptedHeader)
        }
    }

    private func headerRatchet(chainKey: SymmetricKey, state _: RatchetState) async throws -> RatchetState {
        var state = try await getRatchetState()
        var chainKey = chainKey

        // If we fail ratchet
        if state.skippedHeaderMessages.count > 0 {
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
        index _: Int?,
        state: RatchetState,
    ) async throws -> (EncryptedHeader, RatchetState) {
        var encryptedHeader = encryptedHeader
        var state = state

        let messageKey = try await symmetricKeyRatchet(from: chainKey)
        guard let decryptedData = try crypto.decrypt(data: encryptedHeader.encrypted, symmetricKey: messageKey) else {
            throw CryptoError.decryptionFailed
        }

        let header = try BSONDecoder().decodeData(MessageHeader.self, from: decryptedData)

        encryptedHeader.setDecrypted(header)

        if state.skippedHeaderMessages.count > 0 {
            if let headerMessage = state.skippedHeaderMessages.first(where: { $0.chainKey == chainKey }) {
                state = await state.removeSkippedHeaderMessage(headerMessage)
            }
        }
        return (encryptedHeader, state)
    }
}

