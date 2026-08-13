//
//  RatchetStateCore+SessionLoad.swift
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
import Crypto
import NeedleTailCrypto

extension RatchetStateCore {

    func sessionStatus(sessionId: UUID) throws -> RatchetSessionStatus {
        let configuration = try getCurrentConfiguration(id: sessionId)
        guard let state = configuration.state else {
            throw RatchetError.stateUninitialized
        }
        return state.sessionStatus
    }

    /// Load or create session configuration and ratchet state as needed.
    ///
    /// Persistence is deferred: this method only registers in-memory state.
    /// Durable commits happen at the success points of encrypt/decrypt or key derivation.
    ///
    /// - Parameter epochOnSendingKeyChange: `true` for `MessageRatchet` (DH epoch when local
    ///   sending keys rotate). `false` for `KeyRatchet` (handshake completion only).
    func loadConfigurations(
        sessionIdentity: SessionIdentity,
        sessionSymmetricKey: SymmetricKey,
        messageType: MessageType,
        epochOnSendingKeyChange: Bool
    ) async throws {
        if var configuration = sessionConfigurations[sessionIdentity.id] {
            logger.log(level: .trace, message: "Found initialized session, reusing ratchet state")
            guard var currentProps = await configuration
                .sessionIdentity
                .props(symmetricKey: sessionSymmetricKey) else {
                throw RatchetError.missingProps
            }

            switch messageType {
            case let .sending(keys):
                guard let state = configuration.state else {
                    throw RatchetError.stateUninitialized
                }
                if epochOnSendingKeyChange, sendingKeysChanged(state: state, keys: keys) {
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
                } else if epochOnSendingKeyChange {
                    if let state = currentProps.state, state.sendingHandshakeFinished == false {
                        let chainKey: SymmetricKey
                        if let sendingKey = state.sendingKey {
                            chainKey = sendingKey
                        } else {
                            guard let rootKey = state.rootKey else {
                                throw RatchetError.rootKeyIsNil
                            }
                            chainKey = try await deriveChainKey(
                                from: rootKey,
                                configuration: defaultRatchetConfiguration)
                        }
                        currentProps.state = await state.updateSendingKey(chainKey)
                    }
                } else {
                    currentProps.state = try await completeKeyRatchetSendingHandshake(
                        state: state,
                        keys: keys,
                        fromCache: true)
                }

            case .receiving(let keys):
                if let header = keys.header {
                    if let state = currentProps.state {
                        let remoteChanged = hasReceivingKeyChanges(state: state, header: header)
                        let localChanged = localKeysChanged(state: state, keys: keys)
                        if remoteChanged || localChanged {
                            currentProps.state = await currentProps.state?.updateLocalLongTermPrivateKey(keys.localLongTermPrivateKey)
                            currentProps.state = await currentProps.state?.updateLocalOneTimePrivateKey(keys.localOneTimePrivateKey)
                            currentProps.state = await currentProps.state?.updateLocalMLKEMPrivateKey(keys.localMLKEMPrivateKey)
                        }
                    } else {
                        let state = try await setState(for: messageType, configuration: configuration)
                        currentProps.state = state
                    }
                } else if currentProps.state == nil {
                    currentProps.state = try await setState(for: messageType, configuration: configuration)
                }
            }

            configuration.state = currentProps.state
            try await sessionIdentity.update(currentProps, symmetricKey: sessionSymmetricKey)
            configuration.sessionIdentity = sessionIdentity
            configuration.sessionSymmetricKey = sessionSymmetricKey
            try await updateSessionIdentity(configuration: configuration)
        } else {
            logger.log(level: .trace, message: "Session not initialized yet, creating state for ratchet")
            var configuration = SessionConfiguration(
                sessionIdentity: sessionIdentity,
                sessionSymmetricKey: sessionSymmetricKey)

            guard var props = await sessionIdentity.props(symmetricKey: sessionSymmetricKey) else {
                throw RatchetError.missingProps
            }
            if var state = props.state {
                switch messageType {
                case let .sending(keys):
                    if epochOnSendingKeyChange, sendingKeysChanged(state: state, keys: keys) {
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
                    } else if epochOnSendingKeyChange,
                              state.sendingHandshakeFinished == false,
                              state.sendingKey == nil {
                        guard let rootKey = state.rootKey else {
                            throw RatchetError.rootKeyIsNil
                        }
                        let chainKey = try await deriveChainKey(
                            from: rootKey,
                            configuration: defaultRatchetConfiguration)
                        state = await state.updateSendingKey(chainKey)
                    } else if !epochOnSendingKeyChange {
                        state = try await completeKeyRatchetSendingHandshake(
                            state: state,
                            keys: keys,
                            fromCache: false)
                    }
                case .receiving(let keys):
                    if let header = keys.header {
                        let remoteChanged = hasReceivingKeyChanges(state: state, header: header)
                        let localChanged = localKeysChanged(state: state, keys: keys)
                        if remoteChanged || localChanged {
                            state = await state.updateLocalLongTermPrivateKey(keys.localLongTermPrivateKey)
                            state = await state.updateLocalOneTimePrivateKey(keys.localOneTimePrivateKey)
                            state = await state.updateLocalMLKEMPrivateKey(keys.localMLKEMPrivateKey)
                        }
                    } else {
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
                }
                configuration.state = state
            } else {
                setSessionIdentity(configuration: configuration)
                let state = try await setState(for: messageType, configuration: configuration)
                props.state = state
                configuration.sessionIdentity = sessionIdentity
                configuration.state = state
                try await updateSessionIdentity(configuration: configuration)
            }

            try await sessionIdentity.update(props, symmetricKey: sessionSymmetricKey)
            try await updateSessionIdentity(configuration: configuration)
            setSessionIdentity(configuration: configuration)
        }
    }

    func hasReceivingKeyChanges(state: RatchetState, header: EncryptedHeader) -> Bool {
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

    func diffieHellmanRatchet(
        header: EncryptedHeader? = nil,
        localKeys: LocalKeys? = nil,
        configuration: SessionConfiguration,
        persist: Bool = true
    ) async throws -> RatchetState {
        var configuration = configuration
        guard var state = configuration.state else {
            throw RatchetError.stateUninitialized
        }
        logger.log(level: .trace, message: "Starting PQXDH re-key (epoch) step")

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
            logger.log(level: .trace, message: "Updating remote public keys from header")
            state = await state.updateRemoteLongTermPublicKey(header.remoteLongTermPublicKey)
            state = await state.updateRemoteOneTimePublicKey(header.remoteOneTimePublicKey)
            state = await state.updateRemoteMLKEMPublicKey(header.remoteMLKEMPublicKey)

            let pqxdhSecret = try await derivePQXDHFinalKeyReceiver(
                remoteLongTermPublicKey: state.remoteLongTermPublicKey,
                remoteOneTimePublicKey: state.remoteOneTimePublicKey,
                localLongTermPrivateKey: state.localLongTermPrivateKey,
                localOneTimePrivateKey: state.localOneTimePrivateKey,
                localMLKEMPrivateKey: state.localMLKEMPrivateKey,
                receivedCiphertext: header.messageCiphertext)

            let step1 = kdfRootKey(oldRootKey, input: pqxdhSecret.bytes)
            let step2 = kdfRootKey(step1.rootKey, input: pqxdhSecret.bytes)
            state = await state.updateRootKey(step2.rootKey)
            state = await state.updateCiphertext(header.messageCiphertext)
            state = await state.updateReceivingKey(step1.chainKey)
            state = await state.updateSendingKey(step2.chainKey)
            logger.log(level: .trace, message: "Epoch re-key applied (receive-driven)")
        } else if let localKeys {
            logger.log(level: .trace, message: "Updating local private keys")
            state = await state.updateLocalLongTermPrivateKey(localKeys.longTerm.rawRepresentation)
            state = await state.updateLocalOneTimePrivateKey(localKeys.oneTime)
            state = await state.updateLocalMLKEMPrivateKey(localKeys.mlKEM)

            let cipher = try await derivePQXDHFinalKey(
                localLongTermPrivateKey: state.localLongTermPrivateKey,
                localOneTimePrivateKey: state.localOneTimePrivateKey,
                remoteLongTermPublicKey: state.remoteLongTermPublicKey,
                remoteOneTimePublicKey: state.remoteOneTimePublicKey,
                remoteMLKEMPublicKey: state.remoteMLKEMPublicKey)

            let step1 = kdfRootKey(oldRootKey, input: cipher.symmetricKey.bytes)
            let step2 = kdfRootKey(step1.rootKey, input: cipher.symmetricKey.bytes)
            state = await state.updateRootKey(step2.rootKey)
            state = await state.updateCiphertext(cipher.ciphertext)
            state = await state.updateSendingKey(step1.chainKey)
            state = await state.updateReceivingKey(step2.chainKey)
            logger.log(level: .trace, message: "Epoch re-key applied (sender-driven)")
        }
        logger.log(level: .trace, message: "Ratchet state successfully updated and returned")
        configuration.state = state
        if persist {
            try await updateSessionIdentity(configuration: configuration)
        }
        return state
    }

    private func sendingKeysChanged(state: RatchetState, keys: EncryptionKeys) -> Bool {
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

    private func localKeysChanged(state: RatchetState, keys: EncryptionKeys) -> Bool {
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

    private func completeKeyRatchetSendingHandshake(
        state: RatchetState,
        keys: EncryptionKeys,
        fromCache: Bool
    ) async throws -> RatchetState {
        guard state.sendingHandshakeFinished == false || state.messageCiphertext == nil else {
            return state
        }
        if fromCache {
            guard state.sendingKey == nil else {
                return state
            }
            var updatedState = state
            let chainKey: SymmetricKey
            if let rootKey = updatedState.rootKey {
                chainKey = try await deriveChainKey(
                    from: rootKey,
                    configuration: defaultRatchetConfiguration)
            } else {
                let pqxdhCipher = try await derivePQXDHFinalKey(
                    localLongTermPrivateKey: keys.localLongTermPrivateKey,
                    localOneTimePrivateKey: keys.localOneTimePrivateKey,
                    remoteLongTermPublicKey: keys.remoteLongTermPublicKey,
                    remoteOneTimePublicKey: keys.remoteOneTimePublicKey,
                    remoteMLKEMPublicKey: keys.remoteMLKEMPublicKey)
                updatedState = await updatedState.updateRootKey(pqxdhCipher.symmetricKey)
                updatedState = await updatedState.updateCiphertext(pqxdhCipher.ciphertext)
                chainKey = try await deriveChainKey(
                    from: pqxdhCipher.symmetricKey,
                    configuration: defaultRatchetConfiguration)
            }
            return await updatedState.updateSendingKey(chainKey)
        }

        let pqxdhCipher = try await derivePQXDHFinalKey(
            localLongTermPrivateKey: keys.localLongTermPrivateKey,
            localOneTimePrivateKey: keys.localOneTimePrivateKey,
            remoteLongTermPublicKey: keys.remoteLongTermPublicKey,
            remoteOneTimePublicKey: keys.remoteOneTimePublicKey,
            remoteMLKEMPublicKey: keys.remoteMLKEMPublicKey)
        var state = state
        if state.rootKey == nil {
            state = await state.updateRootKey(pqxdhCipher.symmetricKey)
        }
        state = await state.updateCiphertext(pqxdhCipher.ciphertext)
        guard let rootKey = state.rootKey else {
            throw RatchetError.rootKeyIsNil
        }
        let initialChainKey = try await deriveChainKey(
            from: rootKey,
            configuration: defaultRatchetConfiguration)
        return await state.updateSendingKey(initialChainKey)
    }

    private func stashOldReceivingChainTail(on state: RatchetState) async -> RatchetState {
        let epochTailWindow = 32
        guard state.receivingHandshakeFinished,
              var receivingKey = state.receivingKey else {
            return state
        }
        var state = state
        let capacity = max(0, defaultRatchetConfiguration.maxSkippedMessageKeys - state.skippedMessageKeys.count)
        let tailLength = min(epochTailWindow, capacity)
        guard tailLength > 0 else { return state }
        guard let oldChainTag = state.remoteRatchetPublicKey else { return state }
        for i in state.receivedMessagesCount ..< (state.receivedMessagesCount + tailLength) {
            guard let messageKey = try? await symmetricKeyRatchet(from: receivingKey),
                  let nextReceivingKey = try? await deriveChainKey(
                    from: receivingKey,
                    configuration: defaultRatchetConfiguration) else {
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
