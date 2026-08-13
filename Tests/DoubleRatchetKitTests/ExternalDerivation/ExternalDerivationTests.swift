//
//  ExternalDerivationTests.swift
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
    func testExternalKeyDerivationWithoutRatchetAPIs() async throws {
        let aliceManager = KeyRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = KeyRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            // 1) Generate identities and key bundles
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // 2) Alice initializes sending session to Bob
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.openAsSender(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: self.aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate
            )
            
            // 3) Extract the initial MLKEM ciphertext directly from Alice's persisted state (no message encrypt)
            guard let updatedBobIdentity = getSessionIdentity(for: bobIdentity.id),
                  let bobProps = await updatedBobIdentity.props(symmetricKey: aliceDbsk),
                  let handshakeCiphertext = bobProps.state?.messageCiphertext else {
                #expect(Bool(false))
                return
            }
            
            // 4) Synthesize a minimal header containing Alice's public keys and the MLKEM ciphertext
            //    This avoids the message-encrypt path entirely while still bootstrapping Bob's receiver state.
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
        
            try await bobManager.openAsRecipient(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: self.bobDBSK,
                localKeys: bundle.bobPrivate,
                remoteKeys: bundle.alicePublic,
                ciphertext: handshakeCiphertext)
            
            // 5) Derive message 1 keys externally on both sides
            // Sender: derive next message key
            let (mk1Sender, msgNum1Sender) = try await aliceManager.nextSendKey(sessionId: bobIdentityLatest.id)
            // Receiver: derive next message key (receiving side). After initialization, rootKey is set
            // and the method advances receivingKey accordingly.
            let (mk1Receiver, msgNum1Receiver) = try await bobManager.receiveKey(
                for: aliceIdentityLatest.id,
                cipherText: handshakeCiphertext // not used in this branch but required by signature
            )
            
            // 6) External encryption/decryption roundtrip using derived keys (message 1)
            let p1 = Data("EXTERNAL_MESSAGE_1".utf8)
            let c1 = try #require(try crypto.encrypt(data: p1, symmetricKey: mk1Sender))
            let d1 = try #require(try crypto.decrypt(data: c1, symmetricKey: mk1Receiver))
            #expect(d1 == p1)
            #expect(msgNum1Sender == 0) // First message should be index 0
            #expect(msgNum1Receiver == 0) // First message should be index 0
            
            // 7) Derive message 2 keys and repeat to confirm ratchet progression
            let (mk2Sender, msgNum2Sender) = try await aliceManager.nextSendKey(sessionId: bobIdentityLatest.id)
            let (mk2Receiver, msgNum2Receiver) = try await bobManager.receiveKey(
                for: aliceIdentityLatest.id,
                cipherText: handshakeCiphertext
            )
            let p2 = Data("EXTERNAL_MESSAGE_2".utf8)
            let c2 = try #require(try crypto.encrypt(data: p2, symmetricKey: mk2Sender))
            let d2 = try #require(try crypto.decrypt(data: c2, symmetricKey: mk2Receiver))
            #expect(d2 == p2)
            #expect(msgNum2Sender == 1) // Second message should be index 1
            #expect(msgNum2Receiver == 1) // Second message should be index 1
            
            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func testTwoWayRatchetingWithExternalKeyDerivation() async throws {
        let aliceManager = KeyRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = KeyRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            // 1) Generate identities and key bundles
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // 2) Alice initializes sending session to Bob
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.openAsSender(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: self.aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate
            )
            
            // 3) Extract the initial MLKEM ciphertext from Alice's manager session state
            let aliceToBobCiphertext = try await aliceManager.getCipherText(sessionId: bobIdentityLatest.id)
            
            // 4) Bob initializes as receiver from Alice
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
        
            try await bobManager.openAsRecipient(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: self.bobDBSK,
                localKeys: bundle.bobPrivate,
                remoteKeys: bundle.alicePublic,
                ciphertext: aliceToBobCiphertext)
            
            // 5) Alice -> Bob: Message 1
            let (mk1AliceToBob, msgNum1AliceToBob) = try await aliceManager.nextSendKey(sessionId: bobIdentityLatest.id)
            let (mk1BobFromAlice, msgNum1BobFromAlice) = try await bobManager.receiveKey(
                for: aliceIdentityLatest.id,
                cipherText: aliceToBobCiphertext
            )
            
            let p1AliceToBob = Data("ALICE_TO_BOB_1".utf8)
            let c1AliceToBob = try #require(try crypto.encrypt(data: p1AliceToBob, symmetricKey: mk1AliceToBob))
            let d1AliceToBob = try #require(try crypto.decrypt(data: c1AliceToBob, symmetricKey: mk1BobFromAlice))
            #expect(d1AliceToBob == p1AliceToBob)
            #expect(msgNum1AliceToBob == 0)
            #expect(msgNum1BobFromAlice == 0)
            
            // 6) Bob initializes sending session to Alice (reverse direction)
            guard let aliceIdentityLatest2 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.openAsSender(
                sessionIdentity: aliceIdentityLatest2,
                sessionSymmetricKey: self.bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate
            )
            
            // 7) Extract the MLKEM ciphertext from Bob's manager session state
            let bobToAliceCiphertext = try await bobManager.getCipherText(sessionId: aliceIdentityLatest2.id)
            
            // 8) Alice initializes as receiver from Bob
            guard let bobIdentityLatest2 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.openAsRecipient(
                sessionIdentity: bobIdentityLatest2,
                sessionSymmetricKey: self.aliceDbsk,
                localKeys: bundle.alicePrivate,
                remoteKeys: bundle.bobPublic,
                ciphertext: bobToAliceCiphertext)
            
            // 9) Bob -> Alice: Message 1
            let (mk1BobToAlice, msgNum1BobToAlice) = try await bobManager.nextSendKey(sessionId: aliceIdentityLatest2.id)
            let (mk1AliceFromBob, msgNum1AliceFromBob) = try await aliceManager.receiveKey(
                for: bobIdentityLatest2.id,
                cipherText: bobToAliceCiphertext
            )
            
            let p1BobToAlice = Data("BOB_TO_ALICE_1".utf8)
            let c1BobToAlice = try #require(try crypto.encrypt(data: p1BobToAlice, symmetricKey: mk1BobToAlice))
            let d1BobToAlice = try #require(try crypto.decrypt(data: c1BobToAlice, symmetricKey: mk1AliceFromBob))
            #expect(d1BobToAlice == p1BobToAlice)
            #expect(msgNum1BobToAlice == 0)
            #expect(msgNum1AliceFromBob == 0)
            
            // 10) Alice -> Bob: Message 2 (continuing in original direction)
            let (mk2AliceToBob, msgNum2AliceToBob) = try await aliceManager.nextSendKey(sessionId: bobIdentityLatest.id)
            let (mk2BobFromAlice, msgNum2BobFromAlice) = try await bobManager.receiveKey(
                for: aliceIdentityLatest.id,
                cipherText: aliceToBobCiphertext
            )
            
            let p2AliceToBob = Data("ALICE_TO_BOB_2".utf8)
            let c2AliceToBob = try #require(try crypto.encrypt(data: p2AliceToBob, symmetricKey: mk2AliceToBob))
            let d2AliceToBob = try #require(try crypto.decrypt(data: c2AliceToBob, symmetricKey: mk2BobFromAlice))
            #expect(d2AliceToBob == p2AliceToBob)
            #expect(msgNum2AliceToBob == 1)
            #expect(msgNum2BobFromAlice == 1)
            
            // 11) Bob -> Alice: Message 2 (continuing in reverse direction)
            let (mk2BobToAlice, msgNum2BobToAlice) = try await bobManager.nextSendKey(sessionId: aliceIdentityLatest2.id)
            let (mk2AliceFromBob, msgNum2AliceFromBob) = try await aliceManager.receiveKey(
                for: bobIdentityLatest2.id,
                cipherText: bobToAliceCiphertext
            )
            
            let p2BobToAlice = Data("BOB_TO_ALICE_2".utf8)
            let c2BobToAlice = try #require(try crypto.encrypt(data: p2BobToAlice, symmetricKey: mk2BobToAlice))
            let d2BobToAlice = try #require(try crypto.decrypt(data: c2BobToAlice, symmetricKey: mk2AliceFromBob))
            #expect(d2BobToAlice == p2BobToAlice)
            #expect(msgNum2BobToAlice == 1)
            #expect(msgNum2AliceFromBob == 1)
            
            // 12) Verify bidirectional communication works by sending more messages in both directions
            // Alice -> Bob: Message 3
            let (mk3AliceToBob, msgNum3AliceToBob) = try await aliceManager.nextSendKey(sessionId: bobIdentityLatest.id)
            let (mk3BobFromAlice, msgNum3BobFromAlice) = try await bobManager.receiveKey(
                for: aliceIdentityLatest.id,
                cipherText: aliceToBobCiphertext
            )
            
            let p3AliceToBob = Data("ALICE_TO_BOB_3".utf8)
            let c3AliceToBob = try #require(try crypto.encrypt(data: p3AliceToBob, symmetricKey: mk3AliceToBob))
            let d3AliceToBob = try #require(try crypto.decrypt(data: c3AliceToBob, symmetricKey: mk3BobFromAlice))
            #expect(d3AliceToBob == p3AliceToBob)
            #expect(msgNum3AliceToBob == 2)
            #expect(msgNum3BobFromAlice == 2)
            
            // Bob -> Alice: Message 3
            let (mk3BobToAlice, msgNum3BobToAlice) = try await bobManager.nextSendKey(sessionId: aliceIdentityLatest2.id)
            let (mk3AliceFromBob, msgNum3AliceFromBob) = try await aliceManager.receiveKey(
                for: bobIdentityLatest2.id,
                cipherText: bobToAliceCiphertext
            )
            
            let p3BobToAlice = Data("BOB_TO_ALICE_3".utf8)
            let c3BobToAlice = try #require(try crypto.encrypt(data: p3BobToAlice, symmetricKey: mk3BobToAlice))
            let d3BobToAlice = try #require(try crypto.decrypt(data: c3BobToAlice, symmetricKey: mk3AliceFromBob))
            #expect(d3BobToAlice == p3BobToAlice)
            #expect(msgNum3BobToAlice == 2)
            #expect(msgNum3AliceFromBob == 2)
            
            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func testKeyRatchetMessageCounters() async throws {
        let aliceManager = KeyRatchet(
            executor: executor,
            ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        
        let bobManager = KeyRatchet(
            executor: executor,
            ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // Initialize sending and receiving sessions
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.openAsSender(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            let aliceToBobCiphertext = try await aliceManager.getCipherText(
                sessionId: bobIdentityLatest.id)
            
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.openAsRecipient(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                localKeys: bundle.bobPrivate,
                remoteKeys: bundle.alicePublic,
                ciphertext: aliceToBobCiphertext)
            
            // Initially, no messages have been sent or received
            let sent0 = try await aliceManager.sessionStatus(sessionId: bobIdentityLatest.id)
            let received0 = try await bobManager.sessionStatus(sessionId: aliceIdentityLatest.id)
            #expect(sent0.sentMessagesCount == 0)
            #expect(received0.receivedMessagesCount == 0)
            
            // Derive first message keys and verify counters
            _ = try await aliceManager.nextSendKey(sessionId: bobIdentityLatest.id)
            _ = try await bobManager.receiveKey(
                for: aliceIdentityLatest.id,
                cipherText: aliceToBobCiphertext)
            
            let sent1 = try await aliceManager.sessionStatus(sessionId: bobIdentityLatest.id)
            let received1 = try await bobManager.sessionStatus(sessionId: aliceIdentityLatest.id)
            #expect(sent1.sentMessagesCount == 1)
            #expect(received1.receivedMessagesCount == 1)
            
            // Derive second message keys and verify counters again
            _ = try await aliceManager.nextSendKey(sessionId: bobIdentityLatest.id)
            _ = try await bobManager.receiveKey(
                for: aliceIdentityLatest.id,
                cipherText: aliceToBobCiphertext)
            
            let sent2 = try await aliceManager.sessionStatus(sessionId: bobIdentityLatest.id)
            let received2 = try await bobManager.sessionStatus(sessionId: aliceIdentityLatest.id)
            #expect(sent2.sentMessagesCount == 2)
            #expect(received2.receivedMessagesCount == 2)
            
            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }
}
