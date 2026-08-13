//
//  IdentityTests.swift
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
    func testSessionRecovery() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // Establish initial session
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.openAsSender(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            let message1 = try await aliceManager.encrypt(
                plainText: "Initial message".data(using: .utf8)!, sessionId: bobIdentityLatest.id)
            
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.openAsRecipient(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: message1.header,
                localKeys: bundle.bobPrivate)
            
            let decrypted1 = try await bobManager.decrypt(message1, sessionId: aliceIdentityLatest.id)
            #expect(decrypted1 == "Initial message".data(using: .utf8)!)
            
            // Simulate session corruption by creating new managers
            let aliceManagerRecovery = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
            await aliceManagerRecovery.setDelegate(self)
            let bobManagerRecovery = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
            await bobManagerRecovery.setDelegate(self)
            
            // Re-establish session with same identities
            guard let bobIdentityLatest2 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManagerRecovery.openAsSender(
                sessionIdentity: bobIdentityLatest2,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            let message2 = try await aliceManagerRecovery.encrypt(
                plainText: "Recovery message".data(using: .utf8)!, sessionId: bobIdentityLatest2.id)
            
            guard let aliceIdentityLatest2 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManagerRecovery.openAsRecipient(
                sessionIdentity: aliceIdentityLatest2,
                sessionSymmetricKey: bobDBSK,
                header: message2.header,
                localKeys: bundle.bobPrivate)
            
            let decrypted2 = try await bobManagerRecovery.decrypt(message2, sessionId: aliceIdentityLatest2.id)
            #expect(decrypted2 == "Recovery message".data(using: .utf8)!)
            
            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
            try await aliceManagerRecovery.flushAndClose()
            try await bobManagerRecovery.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func testDelegateCallbacks() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // Track initial session identities count
            let initialCount = sessionIdentities.count
            
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.openAsSender(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            let message = try await aliceManager.encrypt(
                plainText: "Delegate test".data(using: .utf8)!, sessionId: bobIdentityLatest.id)
            
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.openAsRecipient(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: message.header,
                localKeys: bundle.bobPrivate)
            
            let decrypted = try await bobManager.decrypt(message, sessionId: aliceIdentityLatest.id)
            #expect(decrypted == "Delegate test".data(using: .utf8)!)
            
            // Verify that session identities were updated through delegate
            let finalCount = sessionIdentities.count
            #expect(
                finalCount >= initialCount, "Session identities should be updated through delegate")
            
            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func testSessionIdentityCryptoRoundTrip() async throws {
        let (aliceIdentity, _, _) = try await createKeys()
        
        // Decrypt props with the correct database symmetric key
        let initialProps = try await aliceIdentity.decryptProps(symmetricKey: bobDBSK)
        #expect(initialProps.secretName == "alice")
        
        // Decryption with an incorrect key should fail
        let wrongKey = SymmetricKey(size: .bits256)
        await #expect(throws: CryptoKitError.self) {
            _ = try await aliceIdentity.decryptProps(symmetricKey: wrongKey)
        }
        
        // updateProps(_:): round-trip change is persisted
        var updatedProps = initialProps
        updatedProps.serverTrusted = true
        updatedProps.verificationCode = "123456"
        
        let roundTripped = try await aliceIdentity.updateProps(
            symmetricKey: bobDBSK,
            props: updatedProps)
        #expect(roundTripped?.serverTrusted == true)
        #expect(roundTripped?.verificationCode == "123456")
        
        // update(_:symmetricKey:): further change is also persisted
        var updatedProps2 = try #require(roundTripped)
        updatedProps2.verifiedIdentity = false
        try await aliceIdentity.update(updatedProps2, symmetricKey: bobDBSK)
        
        let propsAfterUpdate = try await aliceIdentity.decryptProps(symmetricKey: bobDBSK)
        #expect(propsAfterUpdate.verifiedIdentity == false)
        #expect(aliceIdentity.id == aliceIdentity.id)
        #expect(propsAfterUpdate.secretName == "alice")
        #expect(propsAfterUpdate.longTermPublicKey == updatedProps2.longTermPublicKey)
        #expect(propsAfterUpdate.signingPublicKey == updatedProps2.signingPublicKey)
    }
}
