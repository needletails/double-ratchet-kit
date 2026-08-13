//
//  WireFormatTests.swift
//  double-ratchet-kit
//
//  Created by Cole M on 4/15/25.
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
import Crypto
import Foundation
import NeedleTailCrypto
import NeedleTailLogger
import BinaryCodable
import Testing
@testable import DoubleRatchetKit

extension MessageRatchetTests {
    @Test
    func testPayloadDecryptFailsWhenAssociatedDataDiffers() async throws {
        let aliceConfiguration = testableRatchetConfiguration
        let bobConfiguration = RatchetConfiguration(
            messageKeyData: testableRatchetConfiguration.messageKeyData,
            chainKeyData: testableRatchetConfiguration.chainKeyData,
            rootKeyData: testableRatchetConfiguration.rootKeyData,
            associatedData: "DifferentAppContext".data(using: .ascii)!,
            maxSkippedMessageKeys: testableRatchetConfiguration.maxSkippedMessageKeys)
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: aliceConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: bobConfiguration)
        await bobManager.setDelegate(self)

        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()

            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.openAsSender(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)

            let message = try await aliceManager.encrypt(
                plainText: Data("aad-bound".utf8),
                sessionId: bobIdentityLatest.id)

            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.openAsRecipient(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: message.header,
                localKeys: bundle.bobPrivate)

            await #expect(throws: CryptoKitError.self) {
                _ = try await bobManager.decrypt(message, sessionId: aliceIdentityLatest.id)
            }

            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func testPayloadDecryptFailsWhenAuthenticatedHeaderChanges() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)

        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()

            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.openAsSender(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)

            let message = try await aliceManager.encrypt(
                plainText: Data("header-bound".utf8),
                sessionId: bobIdentityLatest.id)

            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.openAsRecipient(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: message.header,
                localKeys: bundle.bobPrivate)

            let tamperedHeader = EncryptedHeader(
                remoteLongTermPublicKey: message.header.remoteLongTermPublicKey,
                remoteOneTimePublicKey: message.header.remoteOneTimePublicKey,
                remoteMLKEMPublicKey: message.header.remoteMLKEMPublicKey,
                headerCiphertext: message.header.headerCiphertext,
                messageCiphertext: message.header.messageCiphertext,
                oneTimeKeyId: message.header.oneTimeKeyId,
                mlKEMOneTimeKeyId: UUID(),
                encrypted: message.header.encrypted)
            let tamperedMessage = RatchetMessage(
                header: tamperedHeader,
                ciphertext: message.ciphertext)

            await #expect(throws: CryptoKitError.self) {
                _ = try await bobManager.decrypt(tamperedMessage, sessionId: aliceIdentityLatest.id)
            }

            let recovered = try await bobManager.decrypt(message, sessionId: aliceIdentityLatest.id)
            #expect(recovered == Data("header-bound".utf8))

            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test("Binary Encoder/Decoder Object Test")
    func testBinaryObjectEncodingDecoding() async throws {
        let curve = Curve25519.KeyAgreement.PrivateKey()
        let mlkem = try MLKEM1024.PrivateKey()
        let someData = try EncryptedHeader(
            remoteLongTermPublicKey: .init(),
            remoteOneTimePublicKey: .init(curve.publicKey.rawRepresentation),
            remoteMLKEMPublicKey: .init(mlkem.publicKey.rawRepresentation),
            headerCiphertext: .init(),
            messageCiphertext: .init(),
            oneTimeKeyId: .init(),
            mlKEMOneTimeKeyId: .init(),
            encrypted: .init())
        
        let encoded = try BinaryEncoder().encode(someData)
        let decoded = try BinaryDecoder().decode(EncryptedHeader.self, from: encoded)
        #expect(decoded == someData)
    }

    @Test
    func testKeyModelSizeValidation() async throws {
        // Valid Curve25519 key wrappers (32-byte raw representations)
        let validCurveData = Data(repeating: 0x01, count: 32)
        let _ = try X25519PrivateKey(validCurveData)
        let _ = try X25519PublicKey(validCurveData)
        
        // Valid MLKEM public key wrapper (1568-byte raw representation)
        let validMLKEMPublicData = Data(repeating: 0x02, count: 1568)
        let _ = try MLKEMPublicKey(validMLKEMPublicData)
        
        // Invalid X25519PrivateKey size should throw KeyError.invalidKeySize
        #expect(throws: KeyError.invalidKeySize.self) {
            _ = try X25519PrivateKey(Data(repeating: 0x00, count: 16))
        }
        
        // Invalid X25519PublicKey size should throw KeyError.invalidKeySize
        #expect(throws: KeyError.invalidKeySize.self) {
            _ = try X25519PublicKey(Data(repeating: 0x00, count: 64))
        }
        
        // Invalid MLKEMPublicKey size should throw KeyError.invalidKeySize
        #expect(throws: KeyError.invalidKeySize.self) {
            _ = try MLKEMPublicKey(Data(repeating: 0x00, count: 32))
        }
    }

    @Test
    func testLegacyMessageHeaderRejectsMissingRatchetFields() throws {
        struct LegacyShapedHeader: Codable {
            enum CodingKeys: String, CodingKey {
                case previousChainLength = "a"
                case messageNumber = "b"
            }
            let previousChainLength: Int
            let messageNumber: Int
        }
        let legacyData = try BinaryEncoder().encode(
            LegacyShapedHeader(previousChainLength: 7, messageNumber: 42))
        #expect(throws: (any Error).self) {
            try BinaryDecoder().decode(MessageHeader.self, from: legacyData)
        }

        let curveKey = crypto.generateCurve25519PrivateKey().publicKey.rawRepresentation
        let kemPublic = Data(repeating: 0xAB, count: 1568)
        let kemCiphertext = Data(repeating: 0xCD, count: 1568)

        // Initiator first-send shape: publics required, ciphertext still absent.
        let bootstrap = MessageHeader(
            previousChainLength: 0,
            messageNumber: 0,
            ratchetPublicKey: curveKey,
            ratchetKEMPublicKey: kemPublic)
        let bootstrapData = try BinaryEncoder().encode(bootstrap)
        let decodedBootstrap = try BinaryDecoder().decode(MessageHeader.self, from: bootstrapData)
        #expect(decodedBootstrap.ratchetPublicKey == curveKey)
        #expect(decodedBootstrap.ratchetKEMPublicKey == kemPublic)
        #expect(decodedBootstrap.ratchetKEMCiphertext == nil)
        #expect(decodedBootstrap.previousChainLength == 0)
        #expect(decodedBootstrap.messageNumber == 0)

        // A full turn-boundary header round-trips all hybrid fields intact.
        let full = MessageHeader(
            previousChainLength: 3,
            messageNumber: 0,
            ratchetPublicKey: curveKey,
            ratchetKEMPublicKey: kemPublic,
            ratchetKEMCiphertext: kemCiphertext)
        let fullData = try BinaryEncoder().encode(full)
        let decodedFull = try BinaryDecoder().decode(MessageHeader.self, from: fullData)
        #expect(decodedFull.ratchetPublicKey == curveKey)
        #expect(decodedFull.ratchetKEMPublicKey == kemPublic)
        #expect(decodedFull.ratchetKEMCiphertext == kemCiphertext)
        #expect(decodedFull.previousChainLength == 3)
        #expect(decodedFull.messageNumber == 0)
    }

    @Test
    func testPreTurnRatchetStateBlobStillDecodes() throws {
        let curvePrivate = crypto.generateCurve25519PrivateKey()
        let kemPrivate = try MLKEM1024.PrivateKey()
        let localMLKEM = try MLKEMPrivateKey(kemPrivate.encode())
        let remoteMLKEM = try MLKEMPublicKey(kemPrivate.publicKey.rawRepresentation)
        let skippedKey = SymmetricKey(size: .bits256)

        struct LegacySkipped: Codable {
            enum CodingKeys: String, CodingKey {
                case remoteLongTermPublicKey = "a"
                case remoteOneTimePublicKey = "b"
                case remoteMLKEMPublicKey = "c"
                case messageIndex = "d"
                case messageKey = "e"
            }
            let remoteLongTermPublicKey: Data
            let remoteOneTimePublicKey: Data?
            let remoteMLKEMPublicKey: Data
            let messageIndex: Int
            let messageKey: SymmetricKey
        }

        struct LegacyState: Codable {
            enum CodingKeys: String, CodingKey {
                case localLongTermPrivateKey = "a"
                case localMLKEMPrivateKey = "c"
                case remoteLongTermPublicKey = "d"
                case remoteMLKEMPublicKey = "f"
                case skippedMessageKeys = "o"
            }
            let localLongTermPrivateKey: Data
            let localMLKEMPrivateKey: MLKEMPrivateKey
            let remoteLongTermPublicKey: Data
            let remoteMLKEMPublicKey: MLKEMPublicKey
            let skippedMessageKeys: [LegacySkipped]
        }

        let legacy = LegacyState(
            localLongTermPrivateKey: curvePrivate.rawRepresentation,
            localMLKEMPrivateKey: localMLKEM,
            remoteLongTermPublicKey: curvePrivate.publicKey.rawRepresentation,
            remoteMLKEMPublicKey: remoteMLKEM,
            skippedMessageKeys: [
                LegacySkipped(
                    remoteLongTermPublicKey: Data(repeating: 0x11, count: 32),
                    remoteOneTimePublicKey: nil,
                    remoteMLKEMPublicKey: remoteMLKEM.rawRepresentation,
                    messageIndex: 3,
                    messageKey: skippedKey)
            ])
        let legacyData = try JSONEncoder().encode(legacy)
        let decoded = try JSONDecoder().decode(RatchetState.self, from: legacyData)
        #expect(decoded.isSessionInitiator == false)
        #expect(decoded.skippedMessageKeys.isEmpty)
        #expect(decoded.suiteMarker == RatchetState.currentSuiteMarker)

        struct UnknownSuiteState: Codable {
            enum CodingKeys: String, CodingKey {
                case localLongTermPrivateKey = "a"
                case localMLKEMPrivateKey = "c"
                case remoteLongTermPublicKey = "d"
                case remoteMLKEMPublicKey = "f"
                case suiteMarker = "H"
            }
            let localLongTermPrivateKey: Data
            let localMLKEMPrivateKey: MLKEMPrivateKey
            let remoteLongTermPublicKey: Data
            let remoteMLKEMPublicKey: MLKEMPublicKey
            let suiteMarker: Int
        }
        let unknown = UnknownSuiteState(
            localLongTermPrivateKey: curvePrivate.rawRepresentation,
            localMLKEMPrivateKey: localMLKEM,
            remoteLongTermPublicKey: curvePrivate.publicKey.rawRepresentation,
            remoteMLKEMPublicKey: remoteMLKEM,
            suiteMarker: 99)
        let unknownData = try JSONEncoder().encode(unknown)
        #expect(throws: (any Error).self) {
            _ = try JSONDecoder().decode(RatchetState.self, from: unknownData)
        }

        let live = RatchetState(
            remoteLongTermPublicKey: curvePrivate.publicKey.rawRepresentation,
            remoteOneTimePublicKey: nil,
            remoteMLKEMPublicKey: remoteMLKEM,
            localLongTermPrivateKey: curvePrivate.rawRepresentation,
            localOneTimePrivateKey: nil,
            localMLKEMPrivateKey: localMLKEM)
        let liveData = try BinaryEncoder().encode(live)
        let liveDecoded = try BinaryDecoder().decode(RatchetState.self, from: liveData)
        #expect(liveDecoded.suiteMarker == RatchetState.currentSuiteMarker)
        #expect(liveDecoded.isSessionInitiator == false)
    }
}
