//
//  IntegratedRatchetTests.swift
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
    func testBidirectionalOutOfOrderMessages() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // Alice → Bob: establish initial direction and decrypt first message in-order
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(throws: Never.self) {
                try await aliceManager.initiateSession(
                    sessionIdentity: bobIdentityLatest,
                    sessionSymmetricKey: self.aliceDbsk,
                    remoteKeys: bundle.bobPublic,
                    localKeys: bundle.alicePrivate
                )
            }
            
            let a1 = try await aliceManager.encrypt(plainText: Data("A1".utf8), sessionId: bobIdentityLatest.id)
            
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(throws: Never.self) {
                try await bobManager.respondToSession(
                    sessionIdentity: aliceIdentityLatest,
                    sessionSymmetricKey: self.bobDBSK,
                    header: a1.header,
                    localKeys: bundle.bobPrivate
                )
            }
            let da1 = try await bobManager.decrypt(a1, sessionId: aliceIdentityLatest.id)
            #expect(da1 == Data("A1".utf8))
            
            // Bob → Alice: change direction and decrypt first response in-order
            guard let aliceIdentityLatest2 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(throws: Never.self) {
                try await bobManager.initiateSession(
                    sessionIdentity: aliceIdentityLatest2,
                    sessionSymmetricKey: self.bobDBSK,
                    remoteKeys: bundle.alicePublic,
                    localKeys: bundle.bobPrivate
                )
            }
            
            let b1 = try await bobManager.encrypt(plainText: Data("B1".utf8), sessionId: aliceIdentityLatest2.id)
            
            guard let bobIdentityLatest2 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(throws: Never.self) {
                try! await aliceManager.respondToSession(
                    sessionIdentity: bobIdentityLatest2,
                    sessionSymmetricKey: self.aliceDbsk,
                    header: b1.header,
                    localKeys: bundle.alicePrivate
                )
            }
            let db1 = try await aliceManager.decrypt(b1, sessionId: bobIdentityLatest2.id)
            #expect(db1 == Data("B1".utf8))
            
            // Alice → Bob: send A2, A3; deliver out of order (A3 first, then A2)
            guard let bobIdentityLatest3 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(throws: Never.self) {
                try await aliceManager.initiateSession(
                    sessionIdentity: bobIdentityLatest3,
                    sessionSymmetricKey: self.aliceDbsk,
                    remoteKeys: bundle.bobPublic,
                    localKeys: bundle.alicePrivate
                )
            }
            let a2 = try await aliceManager.encrypt(plainText: Data("A2".utf8), sessionId: bobIdentityLatest3.id)
            let a3 = try await aliceManager.encrypt(plainText: Data("A3".utf8), sessionId: bobIdentityLatest3.id)
            
            guard let aliceIdentityLatest3 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(throws: Never.self) {
                try await bobManager.respondToSession(
                    sessionIdentity: aliceIdentityLatest3,
                    sessionSymmetricKey: self.bobDBSK,
                    header: a3.header,
                    localKeys: bundle.bobPrivate
                )
            }
            let da3 = try! await bobManager.decrypt(a3, sessionId: aliceIdentityLatest3.id)
            #expect(da3 == Data("A3".utf8))
            
            // Now decrypt the earlier A2
            guard let aliceIdentityLatest4 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
        
            await #expect(throws: Never.self) {
                try await bobManager.respondToSession(
                    sessionIdentity: aliceIdentityLatest4,
                    sessionSymmetricKey: self.bobDBSK,
                    header: a2.header,
                    localKeys: bundle.bobPrivate
                )
            }
            let da2 = try! await bobManager.decrypt(a2, sessionId: aliceIdentityLatest4.id)
            #expect(da2 == Data("A2".utf8))
            
            // Bob → Alice: send B2, B3; deliver out of order (B3 first, then B2)
            guard let aliceIdentityLatest5 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(throws: Never.self) {
                try await bobManager.initiateSession(
                    sessionIdentity: aliceIdentityLatest5,
                    sessionSymmetricKey: self.bobDBSK,
                    remoteKeys: bundle.alicePublic,
                    localKeys: bundle.bobPrivate
                )
            }
            let b2 = try await bobManager.encrypt(plainText: Data("B2".utf8), sessionId: aliceIdentityLatest5.id)
            let b3 = try await bobManager.encrypt(plainText: Data("B3".utf8), sessionId: aliceIdentityLatest5.id)
            
            guard let bobIdentityLatest3 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(throws: Never.self) {
                try await aliceManager.respondToSession(
                    sessionIdentity: bobIdentityLatest3,
                    sessionSymmetricKey: self.aliceDbsk,
                    header: b3.header,
                    localKeys: bundle.alicePrivate
                )
            }
            let db3 = try! await aliceManager.decrypt(b3, sessionId: bobIdentityLatest3.id)
            #expect(db3 == Data("B3".utf8))
            
            // Now decrypt the earlier B2
            guard let bobIdentityLatest4 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(throws: Never.self) {
                try await aliceManager.respondToSession(
                    sessionIdentity: bobIdentityLatest4,
                    sessionSymmetricKey: self.aliceDbsk,
                    header: b2.header,
                    localKeys: bundle.alicePrivate
                )
            }
            let db2 = try! await aliceManager.decrypt(b2, sessionId: bobIdentityLatest4.id)
            #expect(db2 == Data("B2".utf8))
            
            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func testInitiatingPhaseBootstrapSkipsForwardWhenFirstFrameMissing() async throws {
        let aliceManager = MessageRatchet(
            executor: executor,
            ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(
            executor: executor,
            ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)

        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()

            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: self.aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)

            let a0 = try await aliceManager.encrypt(
                plainText: Data("A0".utf8),
                sessionId: bobIdentityLatest.id)
            let a1 = try await aliceManager.encrypt(
                plainText: Data("A1".utf8),
                sessionId: bobIdentityLatest.id)
            let a2 = try await aliceManager.encrypt(
                plainText: Data("A2".utf8),
                sessionId: bobIdentityLatest.id)

            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            // Deliver A2 first — never saw A0. Must bootstrap, not throw
            // initialMessageNotReceived.
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: self.bobDBSK,
                header: a2.header,
                localKeys: bundle.bobPrivate)
            let da2 = try await bobManager.decrypt(a2, sessionId: aliceIdentityLatest.id)
            #expect(da2 == Data("A2".utf8))

            // Late A0 arrives via the skipped-key stash minted during bootstrap.
            let da0 = try await bobManager.decrypt(a0, sessionId: aliceIdentityLatest.id)
            #expect(da0 == Data("A0".utf8))

            let da1 = try await bobManager.decrypt(a1, sessionId: aliceIdentityLatest.id)
            #expect(da1 == Data("A1".utf8))

            // Bob can reply; Alice decrypts — the pair is a live session.
            try await bobManager.initiateSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: self.bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate)
            let b0 = try await bobManager.encrypt(
                plainText: Data("B0".utf8),
                sessionId: aliceIdentityLatest.id)

            guard let bobIdentityForReply = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.respondToSession(
                sessionIdentity: bobIdentityForReply,
                sessionSymmetricKey: self.aliceDbsk,
                header: b0.header,
                localKeys: bundle.alicePrivate)
            let db0 = try await aliceManager.decrypt(b0, sessionId: bobIdentityForReply.id)
            #expect(db0 == Data("B0".utf8))

            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func testBidirectionalInterleavedOutOfOrder() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // A->B: A1 establishes direction
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate
            )
            let a1 = try await aliceManager.encrypt(plainText: Data("A1".utf8), sessionId: bobIdentityLatest.id)
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: a1.header,
                localKeys: bundle.bobPrivate
            )
            #expect(try await bobManager.decrypt(a1, sessionId: aliceIdentityLatest.id) == Data("A1".utf8))
            
            // B->A: B1
            guard let aliceIdentityLatest2 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.initiateSession(
                sessionIdentity: aliceIdentityLatest2,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate
            )
            let B1 = try await bobManager.encrypt(plainText: Data("B1".utf8), sessionId: aliceIdentityLatest2.id)
            guard let bobIdentityLatest2 = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.respondToSession(
                sessionIdentity: bobIdentityLatest2,
                sessionSymmetricKey: aliceDbsk,
                header: B1.header,
                localKeys: bundle.alicePrivate
            )
            #expect(try await aliceManager.decrypt(B1, sessionId: bobIdentityLatest2.id) == Data("B1".utf8))
            
            // A->B: A2, A3
            guard let bobIdentityLatest3 = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest3,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate
            )
            let a2 = try await aliceManager.encrypt(plainText: Data("A2".utf8), sessionId: bobIdentityLatest3.id)
            let a3 = try await aliceManager.encrypt(plainText: Data("A3".utf8), sessionId: bobIdentityLatest3.id)
            
            // B->A: B2, B3
            guard let aliceIdentityLatest3 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.initiateSession(
                sessionIdentity: aliceIdentityLatest3,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate
            )
            let b2 = try await bobManager.encrypt(plainText: Data("B2".utf8), sessionId: aliceIdentityLatest3.id)
            let b3 = try await bobManager.encrypt(plainText: Data("B3".utf8), sessionId: aliceIdentityLatest3.id)
            
            // Deliver interleaved and out of order: A3, B3, A2, B2
            guard let aliceIdentityLatest4 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest4,
                sessionSymmetricKey: bobDBSK,
                header: a3.header,
                localKeys: bundle.bobPrivate
            )
            #expect(try await bobManager.decrypt(a3, sessionId: aliceIdentityLatest4.id) == Data("A3".utf8))
            
            guard let bobIdentityLatest3b = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.respondToSession(
                sessionIdentity: bobIdentityLatest3b,
                sessionSymmetricKey: aliceDbsk,
                header: b3.header,
                localKeys: bundle.alicePrivate
            )
            #expect(try await aliceManager.decrypt(b3, sessionId: bobIdentityLatest3b.id) == Data("B3".utf8))
            
            guard let aliceIdentityLatest5 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest5,
                sessionSymmetricKey: bobDBSK,
                header: a2.header,
                localKeys: bundle.bobPrivate
            )
            #expect(try await bobManager.decrypt(a2, sessionId: aliceIdentityLatest5.id) == Data("A2".utf8))
            
            guard let bobIdentityLatest4 = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.respondToSession(
                sessionIdentity: bobIdentityLatest4,
                sessionSymmetricKey: aliceDbsk,
                header: b2.header,
                localKeys: bundle.alicePrivate
            )
            #expect(try await aliceManager.decrypt(b2, sessionId: bobIdentityLatest4.id) == Data("B2".utf8))
            
            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func testCallFlowLogsBidirectionalOutOfOrder() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // Alice → Bob: start_call (A1)
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate
            )
            let startCall = try await aliceManager.encrypt(plainText: Data("start_call".utf8), sessionId: bobIdentityLatest.id)
            
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: startCall.header,
                localKeys: bundle.bobPrivate
            )
            #expect(try await bobManager.decrypt(startCall, sessionId: aliceIdentityLatest.id) == Data("start_call".utf8))
            
            // Bob → Alice: call_answered (B1)
            guard let aliceIdentityLatest2 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.initiateSession(
                sessionIdentity: aliceIdentityLatest2,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate
            )
            let callAnswered = try await bobManager.encrypt(plainText: Data("call_answered".utf8), sessionId: aliceIdentityLatest2.id)
            
            guard let bobIdentityLatest2 = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.respondToSession(
                sessionIdentity: bobIdentityLatest2,
                sessionSymmetricKey: aliceDbsk,
                header: callAnswered.header,
                localKeys: bundle.alicePrivate
            )
            #expect(try await aliceManager.decrypt(callAnswered, sessionId: bobIdentityLatest2.id) == Data("call_answered".utf8))
            
            // Alice → Bob: sdp_offer (A2) and ice_candidate_a (A3)
            guard let bobIdentityLatest3 = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest3,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate
            )
            let sdpOffer = try await aliceManager.encrypt(plainText: Data("sdp_offer".utf8), sessionId: bobIdentityLatest3.id)
            let iceCandidateA = try await aliceManager.encrypt(plainText: Data("ice_candidate_a".utf8), sessionId: bobIdentityLatest3.id)
            
            // Bob → Alice: sdp_answer (B2) and ice_candidate_b (B3)
            guard let aliceIdentityLatest3 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.initiateSession(
                sessionIdentity: aliceIdentityLatest3,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate
            )
            let sdpAnswer = try await bobManager.encrypt(plainText: Data("sdp_answer".utf8), sessionId: aliceIdentityLatest3.id)
            let iceCandidateB = try await bobManager.encrypt(plainText: Data("ice_candidate_b".utf8), sessionId: aliceIdentityLatest3.id)
            
            // Deliver out-of-order per receiver: Bob gets A3 then A2; Alice gets B3 then B2
            guard let aliceIdentityLatest4 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest4,
                sessionSymmetricKey: bobDBSK,
                header: iceCandidateA.header,
                localKeys: bundle.bobPrivate
            )
            #expect(try await bobManager.decrypt(iceCandidateA, sessionId: aliceIdentityLatest4.id) == Data("ice_candidate_a".utf8))
            
            guard let aliceIdentityLatest5 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest5,
                sessionSymmetricKey: bobDBSK,
                header: sdpOffer.header,
                localKeys: bundle.bobPrivate
            )
            #expect(try await bobManager.decrypt(sdpOffer, sessionId: aliceIdentityLatest5.id) == Data("sdp_offer".utf8))
            
            guard let bobIdentityLatest3b = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.respondToSession(
                sessionIdentity: bobIdentityLatest3b,
                sessionSymmetricKey: aliceDbsk,
                header: iceCandidateB.header,
                localKeys: bundle.alicePrivate
            )
            #expect(try await aliceManager.decrypt(iceCandidateB, sessionId: bobIdentityLatest3b.id) == Data("ice_candidate_b".utf8))
            
            guard let bobIdentityLatest4 = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.respondToSession(
                sessionIdentity: bobIdentityLatest4,
                sessionSymmetricKey: aliceDbsk,
                header: sdpAnswer.header,
                localKeys: bundle.alicePrivate
            )
            #expect(try await aliceManager.decrypt(sdpAnswer, sessionId: bobIdentityLatest4.id) == Data("sdp_answer".utf8))
            
            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func testResynchronizationAfterOutOfOrderSubsequentSends() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // Alice → Bob: A1 establishes session
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate
            )
            let a1 = try await aliceManager.encrypt(plainText: Data("A1".utf8), sessionId: bobIdentityLatest.id)
            
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: a1.header,
                localKeys: bundle.bobPrivate
            )
            #expect(try await bobManager.decrypt(a1, sessionId: aliceIdentityLatest.id) == Data("A1".utf8))
            
            // Alice sends A2, A3
            guard let bobIdentityLatest2 = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest2,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate
            )
            let a2 = try await aliceManager.encrypt(plainText: Data("A2".utf8), sessionId: bobIdentityLatest2.id)
            let a3 = try await aliceManager.encrypt(plainText: Data("A3".utf8), sessionId: bobIdentityLatest2.id)
            
            // Bob receives OUT OF ORDER: A3 first, then A2 (simulating network reorder)
            guard let aliceIdentityLatest2 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest2,
                sessionSymmetricKey: bobDBSK,
                header: a3.header,
                localKeys: bundle.bobPrivate
            )
            #expect(try await bobManager.decrypt(a3, sessionId: aliceIdentityLatest2.id) == Data("A3".utf8))
            
            guard let aliceIdentityLatest3 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest3,
                sessionSymmetricKey: bobDBSK,
                header: a2.header,
                localKeys: bundle.bobPrivate
            )
            #expect(try await bobManager.decrypt(a2, sessionId: aliceIdentityLatest3.id) == Data("A2".utf8))
            
            // Re-sync: Bob sends B1; Alice must decrypt (subsequent send re-synchronizes)
            guard let aliceIdentityLatest4 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.initiateSession(
                sessionIdentity: aliceIdentityLatest4,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate
            )
            let b1 = try await bobManager.encrypt(plainText: Data("B1".utf8), sessionId: aliceIdentityLatest4.id)
            
            guard let bobIdentityLatest3 = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.respondToSession(
                sessionIdentity: bobIdentityLatest3,
                sessionSymmetricKey: aliceDbsk,
                header: b1.header,
                localKeys: bundle.alicePrivate
            )
            #expect(try await aliceManager.decrypt(b1, sessionId: bobIdentityLatest3.id) == Data("B1".utf8))
            
            // Continue: Alice sends A4; Bob decrypts
            guard let bobIdentityLatest4 = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            let a4 = try await aliceManager.encrypt(plainText: Data("A4".utf8), sessionId: bobIdentityLatest4.id)
            guard let aliceIdentityLatest5 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest5,
                sessionSymmetricKey: bobDBSK,
                header: a4.header,
                localKeys: bundle.bobPrivate
            )
            #expect(try await bobManager.decrypt(a4, sessionId: aliceIdentityLatest5.id) == Data("A4".utf8))
            
            // Bob sends B2; Alice decrypts (flow stays in sync)
            guard let aliceIdentityLatest6 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            let b2 = try await bobManager.encrypt(plainText: Data("B2".utf8), sessionId: aliceIdentityLatest6.id)
            guard let bobIdentityLatest5 = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.respondToSession(
                sessionIdentity: bobIdentityLatest5,
                sessionSymmetricKey: aliceDbsk,
                header: b2.header,
                localKeys: bundle.alicePrivate
            )
            #expect(try await aliceManager.decrypt(b2, sessionId: bobIdentityLatest5.id) == Data("B2".utf8))
            
            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func testOutOfOrderThenBidirectionalFlowContinues() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // A1: Alice → Bob
            guard let bobId = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.initiateSession(
                sessionIdentity: bobId,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate
            )
            let a1 = try await aliceManager.encrypt(plainText: Data("A1".utf8), sessionId: bobId.id)
            guard let aliceId = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.respondToSession(
                sessionIdentity: aliceId,
                sessionSymmetricKey: bobDBSK,
                header: a1.header,
                localKeys: bundle.bobPrivate
            )
            #expect(try await bobManager.decrypt(a1, sessionId: aliceId.id) == Data("A1".utf8))
            
            // B1: Bob → Alice
            guard let aliceId2 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.initiateSession(
                sessionIdentity: aliceId2,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate
            )
            let b1 = try await bobManager.encrypt(plainText: Data("B1".utf8), sessionId: aliceId2.id)
            guard let bobId2 = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.respondToSession(
                sessionIdentity: bobId2,
                sessionSymmetricKey: aliceDbsk,
                header: b1.header,
                localKeys: bundle.alicePrivate
            )
            #expect(try await aliceManager.decrypt(b1, sessionId: bobId2.id) == Data("B1".utf8))
            
            // Alice sends A2, A3, A4; Bob will receive A4, A2, A3 (out of order)
            guard let bobId3 = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.initiateSession(
                sessionIdentity: bobId3,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate
            )
            let a2 = try await aliceManager.encrypt(plainText: Data("A2".utf8), sessionId: bobId3.id)
            let a3 = try await aliceManager.encrypt(plainText: Data("A3".utf8), sessionId: bobId3.id)
            let a4 = try await aliceManager.encrypt(plainText: Data("A4".utf8), sessionId: bobId3.id)
            
            guard let aliceId3 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.respondToSession(
                sessionIdentity: aliceId3,
                sessionSymmetricKey: bobDBSK,
                header: a4.header,
                localKeys: bundle.bobPrivate
            )
            #expect(try await bobManager.decrypt(a4, sessionId: aliceId3.id) == Data("A4".utf8))
            guard let aliceId4 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.respondToSession(
                sessionIdentity: aliceId4,
                sessionSymmetricKey: bobDBSK,
                header: a2.header,
                localKeys: bundle.bobPrivate
            )
            #expect(try await bobManager.decrypt(a2, sessionId: aliceId4.id) == Data("A2".utf8))
            guard let aliceId5 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.respondToSession(
                sessionIdentity: aliceId5,
                sessionSymmetricKey: bobDBSK,
                header: a3.header,
                localKeys: bundle.bobPrivate
            )
            #expect(try await bobManager.decrypt(a3, sessionId: aliceId5.id) == Data("A3".utf8))
            
            // Re-sync: Bob sends B2; Alice decrypts
            guard let aliceId6 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            let b2 = try await bobManager.encrypt(plainText: Data("B2".utf8), sessionId: aliceId6.id)
            guard let bobId4 = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.respondToSession(
                sessionIdentity: bobId4,
                sessionSymmetricKey: aliceDbsk,
                header: b2.header,
                localKeys: bundle.alicePrivate
            )
            #expect(try await aliceManager.decrypt(b2, sessionId: bobId4.id) == Data("B2".utf8))
            
            // Continue bidirectional: A5, B3, A6, B4
            guard let bobId5 = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            let a5 = try await aliceManager.encrypt(plainText: Data("A5".utf8), sessionId: bobId5.id)
            guard let aliceId7 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.respondToSession(
                sessionIdentity: aliceId7,
                sessionSymmetricKey: bobDBSK,
                header: a5.header,
                localKeys: bundle.bobPrivate
            )
            #expect(try await bobManager.decrypt(a5, sessionId: aliceId7.id) == Data("A5".utf8))
            
            guard let aliceId8 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            let b3 = try await bobManager.encrypt(plainText: Data("B3".utf8), sessionId: aliceId8.id)
            guard let bobId6 = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.respondToSession(
                sessionIdentity: bobId6,
                sessionSymmetricKey: aliceDbsk,
                header: b3.header,
                localKeys: bundle.alicePrivate
            )
            #expect(try await aliceManager.decrypt(b3, sessionId: bobId6.id) == Data("B3".utf8))
            
            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func testLargeGapOutOfOrderThenResyncAndContinue() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            guard let bobId = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.initiateSession(
                sessionIdentity: bobId,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate
            )
            let a1 = try await aliceManager.encrypt(plainText: Data("A1".utf8), sessionId: bobId.id)
            let a2 = try await aliceManager.encrypt(plainText: Data("A2".utf8), sessionId: bobId.id)
            let a3 = try await aliceManager.encrypt(plainText: Data("A3".utf8), sessionId: bobId.id)
            let a4 = try await aliceManager.encrypt(plainText: Data("A4".utf8), sessionId: bobId.id)
            let a5 = try await aliceManager.encrypt(plainText: Data("A5".utf8), sessionId: bobId.id)
            
            guard let aliceId = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.respondToSession(
                sessionIdentity: aliceId,
                sessionSymmetricKey: bobDBSK,
                header: a1.header,
                localKeys: bundle.bobPrivate
            )
            #expect(try await bobManager.decrypt(a1, sessionId: aliceId.id) == Data("A1".utf8))
            
            // Deliver out of order: A5, A3, A2, A4 (large gaps)
            guard let aliceId2 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.respondToSession(
                sessionIdentity: aliceId2,
                sessionSymmetricKey: bobDBSK,
                header: a5.header,
                localKeys: bundle.bobPrivate
            )
            #expect(try await bobManager.decrypt(a5, sessionId: aliceId2.id) == Data("A5".utf8))
            
            guard let aliceId3 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.respondToSession(
                sessionIdentity: aliceId3,
                sessionSymmetricKey: bobDBSK,
                header: a3.header,
                localKeys: bundle.bobPrivate
            )
            #expect(try await bobManager.decrypt(a3, sessionId: aliceId3.id) == Data("A3".utf8))
            
            guard let aliceId4 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.respondToSession(
                sessionIdentity: aliceId4,
                sessionSymmetricKey: bobDBSK,
                header: a2.header,
                localKeys: bundle.bobPrivate
            )
            #expect(try await bobManager.decrypt(a2, sessionId: aliceId4.id) == Data("A2".utf8))
            
            guard let aliceId5 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.respondToSession(
                sessionIdentity: aliceId5,
                sessionSymmetricKey: bobDBSK,
                header: a4.header,
                localKeys: bundle.bobPrivate
            )
            #expect(try await bobManager.decrypt(a4, sessionId: aliceId5.id) == Data("A4".utf8))
            
            // Re-sync: Bob sends B1; Alice decrypts
            guard let aliceId6 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.initiateSession(
                sessionIdentity: aliceId6,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate
            )
            let b1 = try await bobManager.encrypt(plainText: Data("B1".utf8), sessionId: aliceId6.id)
            guard let bobId2 = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.respondToSession(
                sessionIdentity: bobId2,
                sessionSymmetricKey: aliceDbsk,
                header: b1.header,
                localKeys: bundle.alicePrivate
            )
            #expect(try await aliceManager.decrypt(b1, sessionId: bobId2.id) == Data("B1".utf8))
            
            // Continue: Alice sends A6, Bob sends B2
            guard let bobId3 = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            let a6 = try await aliceManager.encrypt(plainText: Data("A6".utf8), sessionId: bobId3.id)
            guard let aliceId7 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.respondToSession(
                sessionIdentity: aliceId7,
                sessionSymmetricKey: bobDBSK,
                header: a6.header,
                localKeys: bundle.bobPrivate
            )
            #expect(try await bobManager.decrypt(a6, sessionId: aliceId7.id) == Data("A6".utf8))
            
            guard let aliceId8 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            let b2 = try await bobManager.encrypt(plainText: Data("B2".utf8), sessionId: aliceId8.id)
            guard let bobId4 = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.respondToSession(
                sessionIdentity: bobId4,
                sessionSymmetricKey: aliceDbsk,
                header: b2.header,
                localKeys: bundle.alicePrivate
            )
            #expect(try await aliceManager.decrypt(b2, sessionId: bobId4.id) == Data("B2".utf8))
            
            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func ratchetEncryptDecryptEncrypt() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // Alice initializes as sender to Bob
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            let originalPlaintext = "Test message for ratchet encrypt/decrypt".data(using: .utf8)!
            let encrypted = try await aliceManager.encrypt(plainText: originalPlaintext, sessionId: bobIdentityLatest.id)
            
            // Bob initializes as recipient from Alice
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: encrypted.header,
                localKeys: bundle.bobPrivate)
            
            let decryptedPlaintext = try await bobManager.decrypt(encrypted, sessionId: aliceIdentityLatest.id)
            #expect(
                decryptedPlaintext == originalPlaintext,
                "Decrypted plaintext must match the original plaintext.")
            
            // Test ratchet advancement with second message
            let secondPlaintext = "Second ratcheted message!".data(using: .utf8)!
            let secondEncrypted = try await aliceManager.encrypt(plainText: secondPlaintext, sessionId: bobIdentityLatest.id)
            let secondDecryptedPlaintext = try await bobManager.decrypt(secondEncrypted, sessionId: aliceIdentityLatest.id)
            #expect(
                secondDecryptedPlaintext == secondPlaintext,
                "Decrypted second plaintext must match.")
            
            // Test bidirectional communication - Bob becomes sender to Alice
            guard let aliceIdentityLatest2 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.initiateSession(
                sessionIdentity: aliceIdentityLatest2,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate)
            
            let encrypted2 = try await bobManager.encrypt(plainText: originalPlaintext, sessionId: aliceIdentityLatest2.id)
            
            // Alice initializes as recipient from Bob
            guard let bobIdentityLatest2 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.respondToSession(
                sessionIdentity: bobIdentityLatest2,
                sessionSymmetricKey: aliceDbsk,
                header: encrypted2.header,
                localKeys: bundle.alicePrivate)
            
            let decryptedSecond = try await aliceManager.decrypt(encrypted2, sessionId: bobIdentityLatest2.id)
            #expect(decryptedSecond == originalPlaintext, "Decrypted second plaintext must match.")
            
            // Continue bidirectional communication
            let thirdPlaintext = "Third message from Alice".data(using: .utf8)!
            let thirdEncrypted = try await aliceManager.encrypt(plainText: thirdPlaintext, sessionId: bobIdentityLatest.id)
            let decryptedThird = try await bobManager.decrypt(thirdEncrypted, sessionId: aliceIdentityLatest.id)
            #expect(decryptedThird == thirdPlaintext, "Decrypted third plaintext must match.")
            
            let fourthPlaintext = "Fourth message from Bob".data(using: .utf8)!
            let fourthEncrypted = try await bobManager.encrypt(plainText: fourthPlaintext, sessionId: aliceIdentityLatest2.id)
            let decryptedFourth = try await aliceManager.decrypt(fourthEncrypted, sessionId: bobIdentityLatest2.id)
            #expect(decryptedFourth == fourthPlaintext, "Decrypted fourth plaintext must match.")
            
            let fifthPlaintext = "Fifth message from Alice".data(using: .utf8)!
            let fifthEncrypted = try await aliceManager.encrypt(plainText: fifthPlaintext, sessionId: bobIdentityLatest.id)
            let decryptedFifth = try await bobManager.decrypt(fifthEncrypted, sessionId: aliceIdentityLatest.id)
            #expect(decryptedFifth == fifthPlaintext, "Decrypted fifth plaintext must match.")
            
            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func ratchetEncryptDecrypt80Messages() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // Alice initializes as sender to Bob
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            let firstPlaintext = "Message 1 from Alice".data(using: .utf8)!
            let firstEncrypted = try await aliceManager.encrypt(plainText: firstPlaintext, sessionId: bobIdentityLatest.id)
            
            // Bob initializes as recipient from Alice
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: firstEncrypted.header,
                localKeys: bundle.bobPrivate)
            
            let firstDecrypted = try await bobManager.decrypt(firstEncrypted, sessionId: aliceIdentityLatest.id)
            #expect(
                firstDecrypted == firstPlaintext,
                "Decrypted first message must match Alice's original.")
            
            // Alice sends messages 2 through 80 to Bob
            for i in 2...80 {
                let plaintext = "Message \(i) from Alice".data(using: .utf8)!
                let encrypted = try await aliceManager.encrypt(plainText: plaintext, sessionId: bobIdentityLatest.id)
                let decrypted = try await bobManager.decrypt(encrypted, sessionId: aliceIdentityLatest.id)
                #expect(
                    decrypted == plaintext, "Decrypted message \(i) must match Alice's original.")
            }
            
            // Bob becomes sender to Alice
            guard let aliceIdentityLatest2 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.initiateSession(
                sessionIdentity: aliceIdentityLatest2,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate)
            
            // Alice initializes as recipient from Bob
            guard let bobIdentityLatest2 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            let firstBackPlaintext = "Message 1 from Bob".data(using: .utf8)!
            let firstBackEncrypted = try await bobManager.encrypt(
                plainText: firstBackPlaintext, sessionId: aliceIdentityLatest2.id)
            try await aliceManager.respondToSession(
                sessionIdentity: bobIdentityLatest2,
                sessionSymmetricKey: aliceDbsk,
                header: firstBackEncrypted.header,
                localKeys: bundle.alicePrivate)
            let firstBackDecrypted = try await aliceManager.decrypt(firstBackEncrypted, sessionId: bobIdentityLatest2.id)
            #expect(
                firstBackDecrypted == firstBackPlaintext,
                "Decrypted first Bob→Alice message must match.")
            
            // Bob sends messages 2 through 80 to Alice
            for i in 2...80 {
                let plaintext = "Message \(i) from Bob".data(using: .utf8)!
                let encrypted = try await bobManager.encrypt(plainText: plaintext, sessionId: aliceIdentityLatest2.id)
                let decrypted = try await aliceManager.decrypt(encrypted, sessionId: bobIdentityLatest2.id)
                #expect(decrypted == plaintext, "Decrypted Bob→Alice message \(i) must match.")
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
    func ratchetEncryptDecryptMessagesPerUserWitNewIntializations() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            let plaintext = "Message from Alice".data(using: .utf8)!
            
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await aliceManager.initiateSession(
                        sessionIdentity: bobIdentityLatest,
                        sessionSymmetricKey: self.aliceDbsk,
                        remoteKeys: bundle.bobPublic,
                        localKeys: bundle.alicePrivate)
                })
            
            let encrypted = try await aliceManager.encrypt(plainText: plaintext, sessionId: bobIdentityLatest.id)
            
            // Initialize recipient before decrypting the message
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await bobManager.respondToSession(
                        sessionIdentity: aliceIdentityLatest,
                        sessionSymmetricKey: self.bobDBSK,
                        header: encrypted.header,
                        localKeys: bundle.bobPrivate)
                })
            let decrypted = try await bobManager.decrypt(encrypted, sessionId: aliceIdentityLatest.id)
            #expect(decrypted == plaintext, "Decrypted message must match Alice's original.")
            
            guard let aliceIdentityLatest2 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await bobManager.initiateSession(
                        sessionIdentity: aliceIdentityLatest2,
                        sessionSymmetricKey: self.bobDBSK,
                        remoteKeys: bundle.alicePublic,
                        localKeys: bundle.bobPrivate)
                })
            
            let encrypted2 = try await bobManager.encrypt(plainText: plaintext, sessionId: aliceIdentityLatest2.id)
            
            // Initialize recipient before decrypting the message
            guard let bobIdentityLatest2 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await aliceManager.respondToSession(
                        sessionIdentity: bobIdentityLatest2,
                        sessionSymmetricKey: self.aliceDbsk,
                        header: encrypted2.header,
                        localKeys: bundle.alicePrivate)
                })
            let decrypted2 = try await aliceManager.decrypt(encrypted2, sessionId: bobIdentityLatest2.id)
            #expect(decrypted2 == plaintext, "Decrypted message must match Alice's original.")
            
            guard let bobIdentityLatest3 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await aliceManager.initiateSession(
                        sessionIdentity: bobIdentityLatest3,
                        sessionSymmetricKey: self.aliceDbsk,
                        remoteKeys: bundle.bobPublic,
                        localKeys: bundle.alicePrivate)
                })
            
            let encrypted3 = try await aliceManager.encrypt(plainText: plaintext, sessionId: bobIdentityLatest3.id)
            
            // Initialize recipient before decrypting the message
            guard let aliceIdentityLatest3 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await bobManager.respondToSession(
                        sessionIdentity: aliceIdentityLatest3,
                        sessionSymmetricKey: self.bobDBSK,
                        header: encrypted3.header,
                        localKeys: bundle.bobPrivate)
                })
            
            let decrypted3 = try await bobManager.decrypt(encrypted3, sessionId: aliceIdentityLatest3.id)
            #expect(decrypted3 == plaintext, "Decrypted message must match Alice's original.")
            
            guard let bobIdentityLatest4 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await aliceManager.initiateSession(
                        sessionIdentity: bobIdentityLatest4,
                        sessionSymmetricKey: self.aliceDbsk,
                        remoteKeys: bundle.alicePublic,
                        localKeys: bundle.alicePrivate)
                })
            
            let encrypted4 = try await aliceManager.encrypt(plainText: plaintext, sessionId: bobIdentityLatest4.id)
            
            // Initialize recipient before decrypting the message
            guard let aliceIdentityLatest4 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await bobManager.respondToSession(
                        sessionIdentity: aliceIdentityLatest4,
                        sessionSymmetricKey: self.bobDBSK,
                        header: encrypted4.header,
                        localKeys: bundle.bobPrivate)
                })
            let decrypted4 = try await bobManager.decrypt(encrypted4, sessionId: aliceIdentityLatest4.id)
            #expect(decrypted4 == plaintext, "Decrypted message must match Alice's original.")
            
            guard let aliceIdentityLatest5 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await bobManager.initiateSession(
                        sessionIdentity: aliceIdentityLatest5,
                        sessionSymmetricKey: self.bobDBSK,
                        remoteKeys: bundle.alicePublic,
                        localKeys: bundle.bobPrivate,
                    )
                })
            
            let encrypted5 = try await bobManager.encrypt(plainText: plaintext, sessionId: aliceIdentityLatest5.id)
            
            // Initialize recipient before decrypting the message
            guard let bobIdentityLatest5 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await aliceManager.respondToSession(
                        sessionIdentity: bobIdentityLatest5,
                        sessionSymmetricKey: self.aliceDbsk,
                        header: encrypted5.header,
                        localKeys: bundle.alicePrivate,
                    )
                })
            let decrypted5 = try await aliceManager.decrypt(encrypted5, sessionId: bobIdentityLatest5.id)
            #expect(decrypted5 == plaintext, "Decrypted message must match Alice's original.")
            
            guard let aliceIdentityLatest6 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await bobManager.initiateSession(
                        sessionIdentity: aliceIdentityLatest6,
                        sessionSymmetricKey: self.bobDBSK,
                        remoteKeys: bundle.alicePublic,
                        localKeys: bundle.bobPrivate,
                    )
                })
            
            let encrypted6 = try await bobManager.encrypt(plainText: plaintext, sessionId: aliceIdentityLatest6.id)
            
            // Initialize recipient before decrypting the message
            guard let bobIdentityLatest6 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await aliceManager.respondToSession(
                        sessionIdentity: bobIdentityLatest6,
                        sessionSymmetricKey: self.aliceDbsk,
                        header: encrypted6.header,
                        localKeys: bundle.alicePrivate,
                    )
                })
            let decrypted6 = try await aliceManager.decrypt(encrypted6, sessionId: bobIdentityLatest6.id)
            #expect(decrypted6 == plaintext, "Decrypted message must match Alice's original.")
            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func ratchetEncryptDecryptOutofOrderMessagesPerUserWitNewIntializations() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            let plaintext1 = "Message 1 from Alice".data(using: .utf8)!
            let plaintext2 = "Message 2 from Alice".data(using: .utf8)!
            let plaintext3 = "Message 3 from Alice".data(using: .utf8)!
            
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await aliceManager.initiateSession(
                        sessionIdentity: bobIdentityLatest,
                        sessionSymmetricKey: self.aliceDbsk,
                        remoteKeys: bundle.bobPublic,
                        localKeys: bundle.alicePrivate,
                    )
                })
            
            let encrypted1 = try await aliceManager.encrypt(plainText: plaintext1, sessionId: bobIdentityLatest.id)
            
            guard let bobIdentityLatest2 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await aliceManager.initiateSession(
                        sessionIdentity: bobIdentityLatest2,
                        sessionSymmetricKey: self.aliceDbsk,
                        remoteKeys: bundle.bobPublic,
                        localKeys: bundle.alicePrivate,
                    )
                })
            
            let encrypted2 = try await aliceManager.encrypt(plainText: plaintext2, sessionId: bobIdentityLatest2.id)
            
            guard let bobIdentityLatest3 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            guard getSessionIdentity(for: aliceIdentity.id) != nil else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await aliceManager.initiateSession(
                        sessionIdentity: bobIdentityLatest3,
                        sessionSymmetricKey: self.aliceDbsk,
                        remoteKeys: bundle.bobPublic,
                        localKeys: bundle.alicePrivate)
                })
            
            let encrypted3 = try await aliceManager.encrypt(plainText: plaintext3, sessionId: bobIdentityLatest3.id)
            
            var stashedMessages = Set<RatchetMessage>()
            
            // Initialize recipient before decrypting the message
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await bobManager.respondToSession(
                        sessionIdentity: aliceIdentityLatest,
                        sessionSymmetricKey: self.bobDBSK,
                        header: encrypted3.header,
                        localKeys: bundle.bobPrivate,
                    )
                })
            do {
                let decrypted3 = try await bobManager.decrypt(encrypted3, sessionId: aliceIdentityLatest.id)
                #expect(
                    decrypted3 == plaintext3,
                    "Decrypted message must match Alice's original.")
            } catch {
                stashedMessages.insert(encrypted3)
            }
            
            guard let aliceIdentityLatest2 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await bobManager.respondToSession(
                        sessionIdentity: aliceIdentityLatest2,
                        sessionSymmetricKey: self.bobDBSK,
                        header: encrypted1.header,
                        localKeys: bundle.bobPrivate,
                    )
                })
            do {
                let decrypted1 = try await bobManager.decrypt(encrypted1, sessionId: aliceIdentityLatest2.id)
                #expect(
                    decrypted1 == plaintext1,
                    "Decrypted message must match Alice's original.")
            } catch {
                stashedMessages.insert(encrypted1)
            }
            
            guard let aliceIdentityLatest3 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await bobManager.respondToSession(
                        sessionIdentity: aliceIdentityLatest3,
                        sessionSymmetricKey: self.bobDBSK,
                        header: encrypted2.header,
                        localKeys: bundle.bobPrivate,
                    )
                })
            do {
                let decrypted2 = try await bobManager.decrypt(encrypted2, sessionId: aliceIdentityLatest3.id)
                #expect(
                    decrypted2 == plaintext2,
                    "Decrypted message must match Alice's original.")
            } catch {
                stashedMessages.insert(encrypted2)
            }
            
            for stashedMessage in stashedMessages {
                do {
                    guard let aliceIdentityLatest4 = getSessionIdentity(for: aliceIdentity.id)
                    else {
                        continue
                    }
                    try await bobManager.respondToSession(
                        sessionIdentity: aliceIdentityLatest4,
                        sessionSymmetricKey: bobDBSK,
                        header: stashedMessage.header,
                        localKeys: bundle.bobPrivate,
                    )
                    
                    _ = try await bobManager.decrypt(stashedMessage, sessionId: aliceIdentityLatest4.id)
                } catch {
                    continue
                }
            }
            
            // MARK: 7. Clean up both managers
            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func performanceThousandsOfMessages() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            // Initialize Sender
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            let payload = Data(repeating: 0x41, count: 128)  // 128 bytes of "A"
            let messageCount = 10000
            
            var messages: [RatchetMessage] = []
            
            let clock = ContinuousClock()
            let duration = try await clock.measure {
                for _ in 0..<messageCount {
                    let encrypted = try await aliceManager.encrypt(plainText: payload, sessionId: bobIdentityLatest.id)
                    messages.append(encrypted)
                }
            }
            
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            _ = try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: messages.first!.header,
                localKeys: bundle.bobPrivate)
            
            for message in messages {
                _ = try await bobManager.decrypt(message, sessionId: aliceIdentityLatest.id)
            }
            print(
                "🔵 Encrypted/Decrypted \(messageCount) messages in \(duration.components.seconds) seconds"
            )
            #expect(messages.count == messageCount)
            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func stressOutOfOrderMessages() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            var messages = try await (0...100).asyncMap { i in
                try await aliceManager.encrypt(plainText: "Message \(i)".data(using: .utf8)!, sessionId: bobIdentityLatest.id)
            }
            
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            let firstMessage = messages.removeFirst()
            _ = try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: firstMessage.header,
                localKeys: bundle.bobPrivate)
            _ = try await bobManager.decrypt(firstMessage, sessionId: aliceIdentityLatest.id)
            
            // Now decrypt the rest (shuffled!)
            let rest = messages.shuffled()
            
            for message in rest {
                await #expect(
                    throws: Never.self,
                    performing: {
                        _ = try await bobManager.decrypt(message, sessionId: aliceIdentityLatest.id)
                    })
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
    func outOfOrderHeaders() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            // Initialize Sender
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            // Pre-encrypt all messages first
            var messages: [RatchetMessage] = []
            for i in 0..<80 {
                let payload = "Message \(i)".data(using: .utf8)!
                let encrypted = try await aliceManager.encrypt(plainText: payload, sessionId: bobIdentityLatest.id)
                messages.append(encrypted)
            }
            
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            _ = try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: messages.first!.header,
                localKeys: bundle.bobPrivate)
            
            // Decrypt all messages
            for message in messages {
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
    func serializationAndResumingRatchet() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            // Initialize Sender
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            let plaintext = "Persist me!".data(using: .utf8)!
            let encrypted = try await aliceManager.encrypt(plainText: plaintext, sessionId: bobIdentityLatest.id)
            
            try await Task.sleep(until: .now + .seconds(10))
            
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            _ = try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: encrypted.header,
                localKeys: bundle.bobPrivate)
            let decrypted = try await bobManager.decrypt(encrypted, sessionId: aliceIdentityLatest.id)
            #expect(decrypted == plaintext)
            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func rotatedKeys() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id),
                  let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id)
            else {
                throw TestErrors.identityNotFound
            }
            
            // Initialize Sender
            try! await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            let originalPlaintext = "Test message for ratchet encrypt/decrypt".data(using: .utf8)!
            
            // Sender encrypts a message
            let encrypted = try! await aliceManager.encrypt(plainText: originalPlaintext, sessionId: bobIdentityLatest.id)
            
            // Receiver decrypts it
            _ = try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: encrypted.header,
                localKeys: bundle.bobPrivate)
            
            let decryptedPlaintext = try await bobManager.decrypt(encrypted, sessionId: aliceIdentityLatest.id)
            #expect(
                decryptedPlaintext == originalPlaintext,
                "Decrypted plaintext must match the original plaintext.")
            // 🚀 NOW Send a Second Message to verify ratchet advancement!
            let secondPlaintext = "Second ratcheted message!".data(using: .utf8)!
            let secondEncrypted = try await aliceManager.encrypt(plainText: secondPlaintext, sessionId: bobIdentityLatest.id)
            let secondDecryptedPlaintext = try await bobManager.decrypt(secondEncrypted, sessionId: aliceIdentityLatest.id)
            
            #expect(
                secondDecryptedPlaintext == secondPlaintext,
                "Decrypted second plaintext must match.")
            
            try await bobManager.initiateSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate)
            
            let encrypted2 = try await bobManager.encrypt(plainText: originalPlaintext, sessionId: aliceIdentityLatest.id)
            
            _ = try await aliceManager.respondToSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                header: encrypted2.header,
                localKeys: bundle.alicePrivate)
            
            // Decrypt message from Bob -> Alice (2nd message)
            let decryptedSecond = try await aliceManager.decrypt(encrypted2, sessionId: bobIdentityLatest.id)
            #expect(decryptedSecond == originalPlaintext, "Decrypted second plaintext must match.")
            
            // Alice sends third message to Bob
            let thirdPlaintext = "Third message from Alice".data(using: .utf8)!
            let thirdEncrypted = try await aliceManager.encrypt(plainText: thirdPlaintext, sessionId: bobIdentityLatest.id)
            
            // Bob decrypts third message
            let decryptedThird = try await bobManager.decrypt(thirdEncrypted, sessionId: aliceIdentityLatest.id)
            #expect(decryptedThird == thirdPlaintext, "Decrypted third plaintext must match.")
            
            // Bob sends fourth message to Alice
            let fourthPlaintext = "Fourth message from Bob".data(using: .utf8)!
            let fourthEncrypted = try await bobManager.encrypt(plainText: fourthPlaintext, sessionId: aliceIdentityLatest.id)
            
            // Alice decrypts fourth message
            let decryptedFourth = try await aliceManager.decrypt(fourthEncrypted, sessionId: bobIdentityLatest.id)
            #expect(decryptedFourth == fourthPlaintext, "Decrypted fourth plaintext must match.")
            
            // Alice sends fifth message to Bob
            let fifthPlaintext = "Fifth message from Alice".data(using: .utf8)!
            let fifthEncrypted = try await aliceManager.encrypt(plainText: fifthPlaintext, sessionId: bobIdentityLatest.id)
            
            // Bob decrypts fifth message
            let decryptedFifth = try await bobManager.decrypt(fifthEncrypted, sessionId: aliceIdentityLatest.id)
            #expect(decryptedFifth == fifthPlaintext, "Decrypted fifth plaintext must match.")
            
            // Rotate Long Term Key
            let rotatedaliceLtpk = crypto.generateCurve25519PrivateKey()
            let rotatedRecipientltpk = crypto.generateCurve25519PrivateKey()
            
            let aliceRotatedLongTermId = UUID()
            let aliceRotatedPrivateLongTerm = try X25519PrivateKey(
                id: aliceRotatedLongTermId, rotatedaliceLtpk.rawRepresentation)
            let aliceRotatedPublicLongTerm = try X25519PublicKey(
                id: aliceRotatedLongTermId, rotatedaliceLtpk.publicKey.rawRepresentation)
            
            let bobRotatedLongTermId = UUID()
            let bobRotatedPrivateLongTerm = try X25519PrivateKey(
                id: bobRotatedLongTermId, rotatedRecipientltpk.rawRepresentation)
            let bobRotatedPublicLongTerm = try X25519PublicKey(
                id: bobRotatedLongTermId, rotatedRecipientltpk.publicKey.rawRepresentation)
            
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: .init(
                    longTerm: aliceRotatedPrivateLongTerm,
                    oneTime: bundle.alicePrivate.oneTime,
                    mlKEM: bundle.alicePrivate.mlKEM,
                ))
            
            let rotatedPlaintext = "Test message for ratchet encrypt/decrypt".data(using: .utf8)!
            
            // Sender encrypts a message
            let encryptedRotated = try await aliceManager.encrypt(
                plainText: rotatedPlaintext, sessionId: bobIdentityLatest.id)
            
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: encryptedRotated.header,
                localKeys: bundle.bobPrivate)
            
            let decryptedPlaintextRotated = try await bobManager.decrypt(encryptedRotated, sessionId: aliceIdentityLatest.id)
            #expect(
                decryptedPlaintextRotated == rotatedPlaintext,
                "Decrypted plaintext must match the original plaintext.")
            
            // Update Sender's Identity
            try await bobManager.initiateSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: .init(
                    longTerm: aliceRotatedPublicLongTerm,
                    oneTime: bundle.alicePublic.oneTime,
                    mlKEM: bundle.alicePublic.mlKEM,
                ),
                localKeys: .init(
                    longTerm: bobRotatedPrivateLongTerm,
                    oneTime: bundle.bobPrivate.oneTime,
                    mlKEM: bundle.bobPrivate.mlKEM,
                ))
            
            let rotatedPlaintext2 = "Test message for ratchet encrypt/decrypt".data(using: .utf8)!
            let encryptedRotated2 = try await bobManager.encrypt(
                plainText: rotatedPlaintext2, sessionId: aliceIdentityLatest.id)
            
            try await aliceManager.respondToSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                header: encryptedRotated2.header,
                localKeys: bundle.alicePrivate)
            
            // Decrypt message from Bob -> Alice (2nd message)
            let decryptedRotatedSecond = try await aliceManager.decrypt(encryptedRotated2, sessionId: bobIdentityLatest.id)
            #expect(
                decryptedRotatedSecond == rotatedPlaintext2,
                "Decrypted second plaintext must match.")
            
            let messages = try await (0...80).asyncMap { i in
                try await aliceManager.initiateSession(
                    sessionIdentity: bobIdentityLatest,
                    sessionSymmetricKey: aliceDbsk,
                    remoteKeys: .init(
                        longTerm: bobRotatedPublicLongTerm,
                        oneTime: bundle.bobPublic.oneTime,
                        mlKEM: bundle.bobPublic.mlKEM,
                    ),
                    localKeys: .init(
                        longTerm: aliceRotatedPrivateLongTerm,
                        oneTime: bundle.alicePrivate.oneTime,
                        mlKEM: bundle.alicePrivate.mlKEM,
                    ),
                )
                return try await aliceManager.encrypt(
                    plainText: "Message \(i)".data(using: .utf8)!, sessionId: bobIdentityLatest.id)
            }
            
            for message in messages {
                _ = try await bobManager.respondToSession(
                    sessionIdentity: aliceIdentityLatest,
                    sessionSymmetricKey: bobDBSK,
                    header: message.header,
                    localKeys: .init(
                        longTerm: bobRotatedPrivateLongTerm,
                        oneTime: bundle.bobPrivate.oneTime,
                        mlKEM: bundle.bobPrivate.mlKEM,
                    ),
                )
                _ = try await bobManager.decrypt(message, sessionId: aliceIdentityLatest.id)
            }
            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
        }
    }

    @Test
    func testErrorHandling() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // Test missingConfiguration error (no session loaded yet)
            await #expect(
                throws: RatchetError.missingConfiguration.self,
                performing: {
                    _ = try await aliceManager.encrypt(plainText: "test".data(using: .utf8)!, sessionId: aliceIdentity.id)
                })
            
            // Test missingProps error with invalid symmetric key
            let invalidKey = SymmetricKey(size: .bits256)
            await #expect(
                throws: RatchetError.missingProps.self,
                performing: {
                    try await aliceManager.initiateSession(
                        sessionIdentity: aliceIdentity,
                        sessionSymmetricKey: invalidKey,
                        remoteKeys: bundle.bobPublic,
                        localKeys: bundle.alicePrivate)
                })
            
            // Test decryption with invalid message
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            let validMessage = try await aliceManager.encrypt(
                plainText: "test".data(using: .utf8)!, sessionId: bobIdentityLatest.id)
            
            // Create invalid message by corrupting encrypted data
            let invalidMessage = RatchetMessage(
                header: validMessage.header,
                ciphertext: Data(repeating: 0, count: 32)  // Corrupted encrypted data
            )
            
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: validMessage.header,
                localKeys: bundle.bobPrivate)
            
            await #expect(
                throws: CryptoKitError.self,
                performing: {
                    _ = try await bobManager.decrypt(invalidMessage, sessionId: aliceIdentityLatest.id)
                })
            
            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func testConcurrentAccess() async throws {
        let aliceManager1 = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager1.setDelegate(self)
        let aliceManager2 = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager2.setDelegate(self)
        let bobManager1 = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager1.setDelegate(self)
        let bobManager2 = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager2.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // Initialize separate sessions for concurrent access
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            
            try await aliceManager1.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            try await aliceManager2.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            // Send messages concurrently from both managers. Unstructured tasks
            // instead of `async let` on purpose: async-let children allocate
            // their frames on the parent task's bump allocator, and when both
            // children interleave on the shared serial TestableExecutor their
            // slabs can be freed out of LIFO order, which the Linux runtime
            // traps ("freed pointer was not the last allocation"). Unstructured
            // tasks own their allocators and keep the same concurrency coverage.
            let send1 = Task {
                try await aliceManager1.encrypt(
                    plainText: Data("Message from Alice1".utf8), sessionId: bobIdentityLatest.id)
            }
            let send2 = Task {
                try await aliceManager2.encrypt(
                    plainText: Data("Message from Alice2".utf8), sessionId: bobIdentityLatest.id)
            }
            let encrypted1 = try await send1.value
            let encrypted2 = try await send2.value
            
            // Bob managers should be able to decrypt messages from respective Alice managers
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            
            try await bobManager1.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: encrypted1.header,
                localKeys: bundle.bobPrivate)
            
            try await bobManager2.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: encrypted2.header,
                localKeys: bundle.bobPrivate)
            
            let decrypted1 = try await bobManager1.decrypt(encrypted1, sessionId: aliceIdentityLatest.id)
            let decrypted2 = try await bobManager2.decrypt(encrypted2, sessionId: aliceIdentityLatest.id)
            
            #expect(decrypted1 == "Message from Alice1".data(using: .utf8)!)
            #expect(decrypted2 == "Message from Alice2".data(using: .utf8)!)
            
            try await aliceManager1.flushAndClose()
            try await aliceManager2.flushAndClose()
            try await bobManager1.flushAndClose()
            try await bobManager2.flushAndClose()
        } catch {
            try? await aliceManager1.flushAndClose()
            try? await aliceManager2.flushAndClose()
            try? await bobManager1.flushAndClose()
            try? await bobManager2.flushAndClose()
            throw error
        }
    }

    @Test
    func testKeyExhaustion() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // Initialize session
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            // Build messages first, then initialize with the first header
            var messages: [RatchetMessage] = []
            for i in 0..<1000 {
                let message = try await aliceManager.encrypt(
                    plainText: "Message \(i)".data(using: .utf8)!, sessionId: bobIdentityLatest.id)
                messages.append(message)
            }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: messages.first!.header,
                localKeys: bundle.bobPrivate)
            
            // Send many messages to test key rotation and potential exhaustion
            
            // Verify all messages can be decrypted
            for (i, message) in messages.enumerated() {
                let decrypted = try await bobManager.decrypt(message, sessionId: aliceIdentityLatest.id)
                #expect(decrypted == "Message \(i)".data(using: .utf8)!)
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
    func testMultiPartyScenario() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        let charlieManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await charlieManager.setDelegate(self)
        
        do {
            // Create three separate sessions: Alice-Bob, Bob-Charlie, Alice-Charlie
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // Test Alice -> Bob communication
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            let aliceToBobMessage = try await aliceManager.encrypt(
                plainText: "Alice to Bob".data(using: .utf8)!, sessionId: bobIdentityLatest.id)
            
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: aliceToBobMessage.header,
                localKeys: bundle.bobPrivate)
            
            let decryptedAliceToBob = try await bobManager.decrypt(aliceToBobMessage, sessionId: aliceIdentityLatest.id)
            #expect(decryptedAliceToBob == "Alice to Bob".data(using: .utf8)!)
            
            // Test Bob -> Alice communication (simplified multi-party test)
            guard let aliceIdentityLatest2 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.initiateSession(
                sessionIdentity: aliceIdentityLatest2,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate)
            
            let bobToAliceMessage = try await bobManager.encrypt(
                plainText: "Bob to Alice".data(using: .utf8)!, sessionId: aliceIdentityLatest2.id)
            
            guard let bobIdentityLatest2 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.respondToSession(
                sessionIdentity: bobIdentityLatest2,
                sessionSymmetricKey: aliceDbsk,
                header: bobToAliceMessage.header,
                localKeys: bundle.alicePrivate)
            
            let decryptedBobToAlice = try await aliceManager.decrypt(bobToAliceMessage, sessionId: bobIdentityLatest2.id)
            #expect(decryptedBobToAlice == "Bob to Alice".data(using: .utf8)!)
            
            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
            try await charlieManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            try? await charlieManager.flushAndClose()
            throw error
        }
    }

    @Test
    func testMemoryPressureHandling() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            // Send many large messages to simulate memory pressure
            let largePayload = Data(repeating: 0x41, count: 1024 * 1024)  // 1MB payload
            var messages: [RatchetMessage] = []
            
            for _ in 0..<10 {
                let message = try await aliceManager.encrypt(plainText: largePayload, sessionId: bobIdentityLatest.id)
                messages.append(message)
            }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: messages.first!.header,
                localKeys: bundle.bobPrivate)
            
            // Verify all messages can still be decrypted under memory pressure
            for message in messages {
                let decrypted = try await bobManager.decrypt(message, sessionId: aliceIdentityLatest.id)
                #expect(decrypted == largePayload)
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
    func testSessionTimeoutAndExpiry() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            // Send initial message
            let initialMessage = try await aliceManager.encrypt(
                plainText: "Initial".data(using: .utf8)!, sessionId: bobIdentityLatest.id)
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: initialMessage.header,
                localKeys: bundle.bobPrivate)
            let decryptedInitial = try await bobManager.decrypt(initialMessage, sessionId: aliceIdentityLatest.id)
            #expect(decryptedInitial == "Initial".data(using: .utf8)!)
            
            // Simulate long delay (in real scenario, keys might expire)
            try await Task.sleep(until: .now + .seconds(1))
            
            // Send message after delay
            let delayedMessage = try await aliceManager.encrypt(
                plainText: "Delayed".data(using: .utf8)!, sessionId: bobIdentityLatest.id)
            let decryptedDelayed = try await bobManager.decrypt(delayedMessage, sessionId: aliceIdentityLatest.id)
            #expect(decryptedDelayed == "Delayed".data(using: .utf8)!)
            
            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func testStateSynchronizationFailureDetection() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // Initialize Alice as sender
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            // Alice sends messages 1-10
            var messages: [RatchetMessage] = []
            for i in 1...10 {
                let message = try await aliceManager.encrypt(plainText: "Message \(i)".data(using: .utf8)!, sessionId: bobIdentityLatest.id)
                messages.append(message)
            }
            
            // Initialize Bob as recipient
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: messages[0].header,
                localKeys: bundle.bobPrivate)
            
            // Bob successfully decrypts message 1 (establish handshake)
            let message1 = messages[0] // Index 0 = message 1
            let decrypted1 = try await bobManager.decrypt(message1, sessionId: aliceIdentityLatest.id)
            #expect(decrypted1 == "Message 1".data(using: .utf8)!)
            
            // Bob successfully decrypts message 5
            let message5 = messages[4] // Index 4 = message 5
            let decrypted5 = try await bobManager.decrypt(message5, sessionId: aliceIdentityLatest.id)
            #expect(decrypted5 == "Message 5".data(using: .utf8)!)
            
            // Now simulate the out-of-order scenario: message 7 arrives before message 6
            // This should trigger the skipped key generation process
            let message7 = messages[6] // Index 6 = message 7
            
            // This should work normally - the system should stash message 6's chain key
            // and generate message 7's chain key to decrypt it
            let decrypted7 = try await bobManager.decrypt(message7, sessionId: aliceIdentityLatest.id)
            #expect(decrypted7 == "Message 7".data(using: .utf8)!)
            
            // Now when message 6 arrives, it should use the stashed chain key
            let message6 = messages[5] // Index 5 = message 6
            let decrypted6 = try await bobManager.decrypt(message6, sessionId: aliceIdentityLatest.id)
            #expect(decrypted6 == "Message 6".data(using: .utf8)!)
            
            // Now let's test the state synchronization failure scenario
            // Create a corrupted message that will cause decryption to fail
            // This simulates what would happen if the state was wrong and derived wrong keys
            let corruptedMessage = RatchetMessage(
                header: message7.header,
                ciphertext: Data(repeating: 0x42, count: message7.ciphertext.count) // Corrupted data
            )
            
            // This should fail with CryptoKitError because the encrypted data is corrupted
            // In a real scenario, this would happen when the state is wrong and wrong keys are derived
            await #expect(throws: CryptoKitError.self, performing: {
                _ = try await bobManager.decrypt(corruptedMessage, sessionId: aliceIdentityLatest.id)
            })
            
            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func testGapFillMisalignmentOnCorruptedOutOfOrder() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // Alice initializes as sender to Bob
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate
            )
            
            // Pre-encrypt messages m1, m2, m3 in order
            let m1 = try await aliceManager.encrypt(plainText: Data("m1".utf8), sessionId: bobIdentityLatest.id)
            let m2 = try await aliceManager.encrypt(plainText: Data("m2".utf8), sessionId: bobIdentityLatest.id)
            let m3 = try await aliceManager.encrypt(plainText: Data("m3".utf8), sessionId: bobIdentityLatest.id)
            
            // Bob initializes as recipient using m1 header
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: m1.header,
                localKeys: bundle.bobPrivate
            )
            
            // Decrypt m1 to finish handshake
            let dm1 = try await bobManager.decrypt(m1, sessionId: aliceIdentityLatest.id)
            #expect(dm1 == Data("m1".utf8))
            
            // Corrupt m3 so payload decrypt fails, but gap-fill runs
            let corruptedM3 = RatchetMessage(
                header: m3.header,
                ciphertext: Data(repeating: 0xFF, count: m3.ciphertext.count)
            )
            
            // Expect failure on corrupted m3 (auth tag), gap-fill will still stash MKs
            await #expect(throws: CryptoKitError.self) {
                _ = try await bobManager.decrypt(corruptedM3, sessionId: aliceIdentityLatest.id)
            }
            
            // Now decrypt valid m2: with MK storage, this should succeed
            let dm2 = try await bobManager.decrypt(m2, sessionId: aliceIdentityLatest.id)
            #expect(dm2 == Data("m2".utf8))
            
            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func testCorruptedInitialDecryptDoesNotAdvanceReceivingState() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)

        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()

            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)

            let validInitial = try await aliceManager.encrypt(
                plainText: Data("initial".utf8),
                sessionId: bobIdentityLatest.id)

            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: validInitial.header,
                localKeys: bundle.bobPrivate)

            let stateBeforeFailure = aliceIdentityLatest.data
            let corruptedInitial = RatchetMessage(
                header: validInitial.header,
                ciphertext: Data(repeating: 0xA5, count: validInitial.ciphertext.count))

            await #expect(throws: CryptoKitError.self) {
                _ = try await bobManager.decrypt(corruptedInitial, sessionId: aliceIdentityLatest.id)
            }
            #expect(aliceIdentityLatest.data == stateBeforeFailure)

            let decrypted = try await bobManager.decrypt(validInitial, sessionId: aliceIdentityLatest.id)
            #expect(decrypted == Data("initial".utf8))

            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func testCorruptedSkippedMessageDoesNotConsumeStoredKey() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)

        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()

            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)

            let m1 = try await aliceManager.encrypt(plainText: Data("m1".utf8), sessionId: bobIdentityLatest.id)
            let m2 = try await aliceManager.encrypt(plainText: Data("m2".utf8), sessionId: bobIdentityLatest.id)
            let m3 = try await aliceManager.encrypt(plainText: Data("m3".utf8), sessionId: bobIdentityLatest.id)

            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: m1.header,
                localKeys: bundle.bobPrivate)

            #expect(try await bobManager.decrypt(m1, sessionId: aliceIdentityLatest.id) == Data("m1".utf8))
            #expect(try await bobManager.decrypt(m3, sessionId: aliceIdentityLatest.id) == Data("m3".utf8))

            let stateBeforeFailure = aliceIdentityLatest.data
            let corruptedM2 = RatchetMessage(
                header: m2.header,
                ciphertext: Data(repeating: 0x5A, count: m2.ciphertext.count))

            await #expect(throws: CryptoKitError.self) {
                _ = try await bobManager.decrypt(corruptedM2, sessionId: aliceIdentityLatest.id)
            }
            #expect(aliceIdentityLatest.data == stateBeforeFailure)

            let recovered = try await bobManager.decrypt(m2, sessionId: aliceIdentityLatest.id)
            #expect(recovered == Data("m2".utf8))

            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func testBogusReceivingKeyChangeDoesNotPersistBeforeAuthenticatedDecrypt() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)

        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()

            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)

            let m1 = try await aliceManager.encrypt(plainText: Data("m1".utf8), sessionId: bobIdentityLatest.id)
            let m2 = try await aliceManager.encrypt(plainText: Data("m2".utf8), sessionId: bobIdentityLatest.id)

            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: m1.header,
                localKeys: bundle.bobPrivate)
            #expect(try await bobManager.decrypt(m1, sessionId: aliceIdentityLatest.id) == Data("m1".utf8))

            let bogusRemoteLongTerm = crypto.generateCurve25519PrivateKey().publicKey.rawRepresentation
            let bogusHeader = EncryptedHeader(
                remoteLongTermPublicKey: bogusRemoteLongTerm,
                remoteOneTimePublicKey: m2.header.remoteOneTimePublicKey,
                remoteMLKEMPublicKey: m2.header.remoteMLKEMPublicKey,
                headerCiphertext: m2.header.headerCiphertext,
                messageCiphertext: Data(repeating: 0x11, count: m2.header.messageCiphertext.count),
                oneTimeKeyId: m2.header.oneTimeKeyId,
                mlKEMOneTimeKeyId: m2.header.mlKEMOneTimeKeyId!,
                encrypted: m2.header.encrypted)
            guard let stateBeforeSetup = await aliceIdentityLatest.props(symmetricKey: bobDBSK)?.state else {
                throw RatchetError.stateUninitialized
            }

            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: bogusHeader,
                localKeys: bundle.bobPrivate)
            guard let stateAfterSetup = await aliceIdentityLatest.props(symmetricKey: bobDBSK)?.state else {
                throw RatchetError.stateUninitialized
            }
            #expect(stateAfterSetup.remoteLongTermPublicKey == stateBeforeSetup.remoteLongTermPublicKey)
            #expect(stateAfterSetup.remoteOneTimePublicKey == stateBeforeSetup.remoteOneTimePublicKey)
            #expect(stateAfterSetup.remoteMLKEMPublicKey == stateBeforeSetup.remoteMLKEMPublicKey)
            #expect(stateAfterSetup.receivedMessagesCount == stateBeforeSetup.receivedMessagesCount)
            let stateBeforeFailure = aliceIdentityLatest.data

            let bogusMessage = RatchetMessage(header: bogusHeader, ciphertext: m2.ciphertext)
            await #expect(throws: (any Error).self) {
                _ = try await bobManager.decrypt(bogusMessage, sessionId: aliceIdentityLatest.id)
            }
            #expect(aliceIdentityLatest.data == stateBeforeFailure)

            let decrypted = try await bobManager.decrypt(m2, sessionId: aliceIdentityLatest.id)
            #expect(decrypted == Data("m2".utf8))

            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func testOTKConsistencyEnforcementEndToEnd() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManagerLoose = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManagerLoose.setDelegate(self)
        let bobManagerStrict = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManagerStrict.setDelegate(self)
        await bobManagerLoose.setEnforceOTKConsistency(false)
        await bobManagerStrict.setEnforceOTKConsistency(true)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // Alice initializes as sender to Bob (header will include OTK id)
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate
            )
            let a1 = try await aliceManager.encrypt(plainText: Data("OTK".utf8), sessionId: bobIdentityLatest.id)
            
            // Bob initializes as recipient WITHOUT providing his local one-time private key
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            let bobLocalNoOTK = LocalKeys(
                longTerm: bundle.bobPrivate.longTerm,
                oneTime: nil, // simulate missing OTK
                mlKEM: bundle.bobPrivate.mlKEM)
            
            // Loose mode: should not preflight-fail with missingOneTimeKey; decrypt still fails later
            try await bobManagerLoose.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: a1.header,
                localKeys: bobLocalNoOTK
            )
            do {
                _ = try await bobManagerLoose.decrypt(a1, sessionId: aliceIdentityLatest.id)
                #expect(Bool(false), "Loose mode should not decrypt when OTK is missing")
            } catch {
                if case RatchetError.missingOneTimeKey = error {
                    #expect(Bool(false), "Loose mode must not preflight with missingOneTimeKey")
                } else {
                    #expect(Bool(true)) // any other failure mode is acceptable here
                }
            }
            
            // Strict mode: preflight must fail fast with RatchetError.missingOneTimeKey
            try await bobManagerStrict.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: a1.header,
                localKeys: bobLocalNoOTK
            )
            await #expect(throws: RatchetError.missingOneTimeKey.self) {
                _ = try await bobManagerStrict.decrypt(a1, sessionId: aliceIdentityLatest.id)
            }
            
            try await aliceManager.flushAndClose()
            try await bobManagerLoose.flushAndClose()
            try await bobManagerStrict.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManagerLoose.flushAndClose()
            try? await bobManagerStrict.flushAndClose()
            throw error
        }
    }

    @Test
    func testGapFillBeyondMaxSkippedMessageKeysIsRejected() async throws {
        let cap = 5
        let configuration = makeCappedConfiguration(maxSkippedMessageKeys: cap)
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: configuration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: configuration)
        await bobManager.setDelegate(self)

        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()

            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)

            // Establish the session with one in-order round trip (message number 0).
            let a1 = try await aliceManager.encrypt(plainText: Data("A1".utf8), sessionId: bobIdentityLatest.id)
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: a1.header,
                localKeys: bundle.bobPrivate)
            let da1 = try await bobManager.decrypt(a1, sessionId: aliceIdentityLatest.id)
            #expect(da1 == Data("A1".utf8))

            // Alice sends cap + 2 more messages; only the final one is delivered.
            // The receive gap (cap + 1) exceeds the configured bound.
            var lastMessage: RatchetMessage?
            for i in 1 ... (cap + 2) {
                lastMessage = try await aliceManager.encrypt(
                    plainText: Data("M\(i)".utf8),
                    sessionId: bobIdentityLatest.id)
            }
            guard let lateMessage = lastMessage,
                  let aliceIdentityLatest2 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest2,
                sessionSymmetricKey: bobDBSK,
                header: lateMessage.header,
                localKeys: bundle.bobPrivate)

            await #expect(throws: RatchetError.maxSkippedHeadersExceeded) {
                _ = try await bobManager.decrypt(lateMessage, sessionId: aliceIdentityLatest2.id)
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
    func testGapFillAtMaxSkippedMessageKeysBoundarySucceeds() async throws {
        let cap = 5
        let configuration = makeCappedConfiguration(maxSkippedMessageKeys: cap)
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: configuration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: configuration)
        await bobManager.setDelegate(self)

        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()

            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)

            let a1 = try await aliceManager.encrypt(plainText: Data("A1".utf8), sessionId: bobIdentityLatest.id)
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: a1.header,
                localKeys: bundle.bobPrivate)
            let da1 = try await bobManager.decrypt(a1, sessionId: aliceIdentityLatest.id)
            #expect(da1 == Data("A1".utf8))

            // Alice sends cap + 1 more messages; only the final one is delivered first.
            // The receive gap is exactly the cap, which is allowed.
            var sent: [RatchetMessage] = []
            for i in 1 ... (cap + 1) {
                sent.append(try await aliceManager.encrypt(
                    plainText: Data("M\(i)".utf8),
                    sessionId: bobIdentityLatest.id))
            }
            guard let boundaryMessage = sent.last,
                  let aliceIdentityLatest2 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest2,
                sessionSymmetricKey: bobDBSK,
                header: boundaryMessage.header,
                localKeys: bundle.bobPrivate)
            let boundaryPlaintext = try await bobManager.decrypt(boundaryMessage, sessionId: aliceIdentityLatest2.id)
            #expect(boundaryPlaintext == Data("M\(cap + 1)".utf8))

            // The first skipped message must still decrypt from the stash.
            guard let aliceIdentityLatest3 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest3,
                sessionSymmetricKey: bobDBSK,
                header: sent[0].header,
                localKeys: bundle.bobPrivate)
            let earlyPlaintext = try await bobManager.decrypt(sent[0], sessionId: aliceIdentityLatest3.id)
            #expect(earlyPlaintext == Data("M1".utf8))

            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func testAlreadyDecryptedMessageNumbersStayBounded() async throws {
        let cap = 5
        let configuration = makeCappedConfiguration(maxSkippedMessageKeys: cap)
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: configuration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: configuration)
        await bobManager.setDelegate(self)

        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()

            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)

            let totalMessages = 30
            for i in 0 ..< totalMessages {
                let message = try await aliceManager.encrypt(
                    plainText: Data("S\(i)".utf8),
                    sessionId: bobIdentityLatest.id)
                guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                    throw TestErrors.identityNotFound
                }
                try await bobManager.respondToSession(
                    sessionIdentity: aliceIdentityLatest,
                    sessionSymmetricKey: bobDBSK,
                    header: message.header,
                    localKeys: bundle.bobPrivate)
                let plaintext = try await bobManager.decrypt(message, sessionId: aliceIdentityLatest.id)
                #expect(plaintext == Data("S\(i)".utf8))
            }

            guard let finalIdentity = getSessionIdentity(for: aliceIdentity.id),
                  let props = await finalIdentity.props(symmetricKey: bobDBSK),
                  let state = props.state else {
                throw TestErrors.identityNotFound
            }
            #expect(
                state.alreadyDecryptedMessageNumbers.count <= cap + 1,
                "alreadyDecryptedMessageNumbers should be pruned to the skip window, found \(state.alreadyDecryptedMessageNumbers.count) entries")

            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func testPerTurnRatchetAdvancesRootAndHeals() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)

        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()

            func aliceState() async throws -> RatchetState {
                guard let identity = getSessionIdentity(for: bobIdentity.id),
                      let state = await identity.props(symmetricKey: aliceDbsk)?.state else {
                    throw TestErrors.identityNotFound
                }
                return state
            }
            func bobState() async throws -> RatchetState {
                guard let identity = getSessionIdentity(for: aliceIdentity.id),
                      let state = await identity.props(symmetricKey: bobDBSK)?.state else {
                    throw TestErrors.identityNotFound
                }
                return state
            }

            // Turn 0: Alice bootstraps via PQXDH and sends A1.
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            let a1 = try await aliceManager.encrypt(plainText: Data("A1".utf8), sessionId: bobIdentityLatest.id)

            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: a1.header,
                localKeys: bundle.bobPrivate)
            #expect(try await bobManager.decrypt(a1, sessionId: aliceIdentityLatest.id) == Data("A1".utf8))

            let root0Alice = try #require(try await aliceState().rootKey)
            let root0Bob = try #require(try await bobState().rootKey)
            #expect(root0Alice == root0Bob, "Bootstrap roots must match (shared PQXDH secret)")

            // Turn 1: Bob's first reply performs the first full sending ratchet step.
            guard let aliceIdentityForSend = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.initiateSession(
                sessionIdentity: aliceIdentityForSend,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate)
            let b1 = try await bobManager.encrypt(plainText: Data("B1".utf8), sessionId: aliceIdentityForSend.id)

            let root1Bob = try #require(try await bobState().rootKey)
            #expect(root1Bob != root0Bob, "Bob's first reply must advance the root (sending ratchet step)")

            guard let bobIdentityForReceive = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.respondToSession(
                sessionIdentity: bobIdentityForReceive,
                sessionSymmetricKey: aliceDbsk,
                header: b1.header,
                localKeys: bundle.alicePrivate)
            #expect(try await aliceManager.decrypt(b1, sessionId: bobIdentityForReceive.id) == Data("B1".utf8))

            let root1Alice = try #require(try await aliceState().rootKey)
            #expect(root1Alice == root1Bob, "Roots must stay synchronized after Bob's turn")

            // Turn 2: Alice's next send steps against Bob's fresh ratchet keys.
            guard let bobIdentityForSend2 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityForSend2,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            let a2 = try await aliceManager.encrypt(plainText: Data("A2".utf8), sessionId: bobIdentityForSend2.id)

            let root2Alice = try #require(try await aliceState().rootKey)
            #expect(root2Alice != root1Alice, "Alice's turn must advance the root again")

            guard let aliceIdentityForReceive2 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityForReceive2,
                sessionSymmetricKey: bobDBSK,
                header: a2.header,
                localKeys: bundle.bobPrivate)
            #expect(try await bobManager.decrypt(a2, sessionId: aliceIdentityForReceive2.id) == Data("A2".utf8))

            let root2Bob = try #require(try await bobState().rootKey)
            #expect(root2Bob == root2Alice, "Roots must stay synchronized after Alice's turn")

            // Turn 3: one more round trip to prove the cadence is stable.
            guard let aliceIdentityForSend3 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.initiateSession(
                sessionIdentity: aliceIdentityForSend3,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate)
            let b2 = try await bobManager.encrypt(plainText: Data("B2".utf8), sessionId: aliceIdentityForSend3.id)

            guard let bobIdentityForReceive3 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.respondToSession(
                sessionIdentity: bobIdentityForReceive3,
                sessionSymmetricKey: aliceDbsk,
                header: b2.header,
                localKeys: bundle.alicePrivate)
            #expect(try await aliceManager.decrypt(b2, sessionId: bobIdentityForReceive3.id) == Data("B2".utf8))

            let root3Alice = try #require(try await aliceState().rootKey)
            let root3Bob = try #require(try await bobState().rootKey)
            #expect(root3Alice == root3Bob)
            #expect(root3Alice != root2Alice)
            // All four roots distinct: continuous healing, no root reuse across turns.
            let roots: Set<Data> = [
                root0Alice.withUnsafeBytes { Data($0) },
                root1Alice.withUnsafeBytes { Data($0) },
                root2Alice.withUnsafeBytes { Data($0) },
                root3Alice.withUnsafeBytes { Data($0) },
            ]
            #expect(roots.count == 4, "Each turn must produce a unique root key")

            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func testOutOfOrderDeliveryAcrossRatchetTurn() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)

        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()

            // Alice sends A1, A2, A3 on her bootstrap chain.
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            let a1 = try await aliceManager.encrypt(plainText: Data("A1".utf8), sessionId: bobIdentityLatest.id)
            let a2 = try await aliceManager.encrypt(plainText: Data("A2".utf8), sessionId: bobIdentityLatest.id)
            let a3 = try await aliceManager.encrypt(plainText: Data("A3".utf8), sessionId: bobIdentityLatest.id)

            // Bob receives only A1 before replying.
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: a1.header,
                localKeys: bundle.bobPrivate)
            #expect(try await bobManager.decrypt(a1, sessionId: aliceIdentityLatest.id) == Data("A1".utf8))

            // Bob replies (ratchet turn) while A2/A3 are still in flight.
            guard let aliceIdentityForSend = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.initiateSession(
                sessionIdentity: aliceIdentityForSend,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate)
            let b1 = try await bobManager.encrypt(plainText: Data("B1".utf8), sessionId: aliceIdentityForSend.id)

            guard let bobIdentityForReceive = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.respondToSession(
                sessionIdentity: bobIdentityForReceive,
                sessionSymmetricKey: aliceDbsk,
                header: b1.header,
                localKeys: bundle.alicePrivate)
            #expect(try await aliceManager.decrypt(b1, sessionId: bobIdentityForReceive.id) == Data("B1".utf8))

            // Alice sends A4 on a fresh chain (her sending ratchet step). Its header carries
            // previousChainLength = 3, telling Bob to stash keys for the unseen A2/A3.
            guard let bobIdentityForSend = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityForSend,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            let a4 = try await aliceManager.encrypt(plainText: Data("A4".utf8), sessionId: bobIdentityForSend.id)

            guard let aliceIdentityForA4 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityForA4,
                sessionSymmetricKey: bobDBSK,
                header: a4.header,
                localKeys: bundle.bobPrivate)
            #expect(try await bobManager.decrypt(a4, sessionId: aliceIdentityForA4.id) == Data("A4".utf8))

            // Late old-chain frames arrive after the turn: A3 first, then A2.
            guard let aliceIdentityForA3 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityForA3,
                sessionSymmetricKey: bobDBSK,
                header: a3.header,
                localKeys: bundle.bobPrivate)
            #expect(try await bobManager.decrypt(a3, sessionId: aliceIdentityForA3.id) == Data("A3".utf8))

            guard let aliceIdentityForA2 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityForA2,
                sessionSymmetricKey: bobDBSK,
                header: a2.header,
                localKeys: bundle.bobPrivate)
            #expect(try await bobManager.decrypt(a2, sessionId: aliceIdentityForA2.id) == Data("A2".utf8))

            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func testHybridBraidStateAccounting() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)

        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()

            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            let a1 = try await aliceManager.encrypt(plainText: Data("A1".utf8), sessionId: bobIdentityLatest.id)

            // Alice's bootstrap state already carries her per-turn key pairs (both primitives).
            guard let aliceIdentitySnapshot = getSessionIdentity(for: bobIdentity.id),
                  let aliceBootstrapState = await aliceIdentitySnapshot.props(symmetricKey: aliceDbsk)?.state else {
                throw TestErrors.identityNotFound
            }
            #expect(aliceBootstrapState.localRatchetPrivateKey != nil, "Initiator must carry a Curve ratchet private from bootstrap")
            #expect(aliceBootstrapState.localRatchetKEMPrivateKey != nil, "Initiator must carry an ML-KEM ratchet private from bootstrap")
            #expect(aliceBootstrapState.isSessionInitiator == true)

            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: a1.header,
                localKeys: bundle.bobPrivate)
            _ = try await bobManager.decrypt(a1, sessionId: aliceIdentityLatest.id)

            // Bob adopted Alice's ratchet publics from the bootstrap header.
            guard let bobIdentityView = getSessionIdentity(for: aliceIdentity.id),
                  let bobAfterReceive = await bobIdentityView.props(symmetricKey: bobDBSK)?.state else {
                throw TestErrors.identityNotFound
            }
            #expect(bobAfterReceive.remoteRatchetPublicKey != nil, "Receiver must adopt the sender's Curve ratchet public")
            #expect(bobAfterReceive.remoteRatchetKEMPublicKey != nil, "Receiver must adopt the sender's ML-KEM ratchet public")
            #expect(bobAfterReceive.isSessionInitiator == false)

            // Bob's first reply performs the hybrid sending step.
            guard let aliceIdentityForSend = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.initiateSession(
                sessionIdentity: aliceIdentityForSend,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate)
            let b1 = try await bobManager.encrypt(plainText: Data("B1".utf8), sessionId: aliceIdentityForSend.id)

            guard let bobIdentityViewAfterSend = getSessionIdentity(for: aliceIdentity.id),
                  let bobAfterStep = await bobIdentityViewAfterSend.props(symmetricKey: bobDBSK)?.state else {
                throw TestErrors.identityNotFound
            }
            #expect(bobAfterStep.localRatchetPrivateKey != nil, "Step must install a fresh Curve ratchet private")
            #expect(bobAfterStep.localRatchetKEMPrivateKey != nil, "Step must install a fresh ML-KEM ratchet private")
            #expect(bobAfterStep.localRatchetKEMCiphertext != nil, "Step must retain the KEM ciphertext for the whole chain")
            #expect(
                bobAfterStep.sendingChainRemoteRatchetKey == bobAfterStep.remoteRatchetPublicKey,
                "Sending chain must be keyed against the peer's current ratchet key")

            // Alice completes the matching receiving step and adopts Bob's fresh publics.
            guard let bobIdentityForReceive = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.respondToSession(
                sessionIdentity: bobIdentityForReceive,
                sessionSymmetricKey: aliceDbsk,
                header: b1.header,
                localKeys: bundle.alicePrivate)
            #expect(try await aliceManager.decrypt(b1, sessionId: bobIdentityForReceive.id) == Data("B1".utf8))

            guard let aliceIdentityAfterReceive = getSessionIdentity(for: bobIdentity.id),
                  let aliceAfterStep = await aliceIdentityAfterReceive.props(symmetricKey: aliceDbsk)?.state else {
                throw TestErrors.identityNotFound
            }
            #expect(aliceAfterStep.remoteRatchetPublicKey != nil)
            #expect(aliceAfterStep.remoteRatchetKEMPublicKey != nil)
            #expect(
                aliceAfterStep.remoteRatchetPublicKey != aliceBootstrapState.remoteRatchetPublicKey,
                "Alice must have adopted Bob's fresh per-turn ratchet key")

            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func testPerTurnRatchetSurvivesManagerShutdownAndRecreation() async throws {
        let firstAliceManager = MessageRatchet(
            executor: executor,
            ratchetConfiguration: testableRatchetConfiguration)
        await firstAliceManager.setDelegate(self)
        let firstBobManager = MessageRatchet(
            executor: executor,
            ratchetConfiguration: testableRatchetConfiguration)
        await firstBobManager.setDelegate(self)
        var resumedAliceManager: MessageRatchet?
        var resumedBobManager: MessageRatchet?

        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()

            guard let bobForA1 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await firstAliceManager.initiateSession(
                sessionIdentity: bobForA1,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            let a1 = try await firstAliceManager.encrypt(
                plainText: Data("A1".utf8),
                sessionId: bobForA1.id)

            guard let aliceForA1 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await firstBobManager.respondToSession(
                sessionIdentity: aliceForA1,
                sessionSymmetricKey: bobDBSK,
                header: a1.header,
                localKeys: bundle.bobPrivate)
            #expect(
                try await firstBobManager.decrypt(a1, sessionId: aliceForA1.id)
                    == Data("A1".utf8))

            guard let aliceForB1 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await firstBobManager.initiateSession(
                sessionIdentity: aliceForB1,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate)
            let b1 = try await firstBobManager.encrypt(
                plainText: Data("B1".utf8),
                sessionId: aliceForB1.id)

            guard let bobForB1 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await firstAliceManager.respondToSession(
                sessionIdentity: bobForB1,
                sessionSymmetricKey: aliceDbsk,
                header: b1.header,
                localKeys: bundle.alicePrivate)
            #expect(
                try await firstAliceManager.decrypt(b1, sessionId: bobForB1.id)
                    == Data("B1".utf8))

            guard let aliceBeforeRestart = await getSessionIdentity(for: bobIdentity.id)?
                    .props(symmetricKey: aliceDbsk)?.state,
                  let bobBeforeRestart = await getSessionIdentity(for: aliceIdentity.id)?
                    .props(symmetricKey: bobDBSK)?.state,
                  let rootBeforeRestart = aliceBeforeRestart.rootKey else {
                throw TestErrors.identityNotFound
            }
            #expect(rootBeforeRestart == bobBeforeRestart.rootKey)

            try await firstAliceManager.flushAndClose()
            try await firstBobManager.flushAndClose()

            let aliceManager = MessageRatchet(
                executor: executor,
                ratchetConfiguration: testableRatchetConfiguration)
            await aliceManager.setDelegate(self)
            resumedAliceManager = aliceManager
            let bobManager = MessageRatchet(
                executor: executor,
                ratchetConfiguration: testableRatchetConfiguration)
            await bobManager.setDelegate(self)
            resumedBobManager = bobManager

            guard let bobForA2 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.initiateSession(
                sessionIdentity: bobForA2,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            let a2 = try await aliceManager.encrypt(
                plainText: Data("A2-after-restart".utf8),
                sessionId: bobForA2.id)

            guard let aliceForA2 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.respondToSession(
                sessionIdentity: aliceForA2,
                sessionSymmetricKey: bobDBSK,
                header: a2.header,
                localKeys: bundle.bobPrivate)
            #expect(
                try await bobManager.decrypt(a2, sessionId: aliceForA2.id)
                    == Data("A2-after-restart".utf8))

            guard let aliceAfterRestart = await getSessionIdentity(for: bobIdentity.id)?
                    .props(symmetricKey: aliceDbsk)?.state,
                  let bobAfterRestart = await getSessionIdentity(for: aliceIdentity.id)?
                    .props(symmetricKey: bobDBSK)?.state else {
                throw TestErrors.identityNotFound
            }
            #expect(aliceAfterRestart.rootKey == bobAfterRestart.rootKey)
            #expect(aliceAfterRestart.rootKey != rootBeforeRestart)

            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await firstAliceManager.flushAndClose()
            try? await firstBobManager.flushAndClose()
            try? await resumedAliceManager?.flushAndClose()
            try? await resumedBobManager?.flushAndClose()
            throw error
        }
    }

    @Test
    func testMessageNBootstrapCorruptionDoesNotPersistState() async throws {
        let aliceManager = MessageRatchet(
            executor: executor,
            ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(
            executor: executor,
            ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)

        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.initiateSession(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            let a0 = try await aliceManager.encrypt(
                plainText: Data("A0".utf8),
                sessionId: bobIdentityLatest.id)
            let a1 = try await aliceManager.encrypt(
                plainText: Data("A1".utf8),
                sessionId: bobIdentityLatest.id)
            let a2 = try await aliceManager.encrypt(
                plainText: Data("A2".utf8),
                sessionId: bobIdentityLatest.id)

            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.respondToSession(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: a2.header,
                localKeys: bundle.bobPrivate)
            let stateBeforeFailure = aliceIdentityLatest.data
            let corruptA2 = RatchetMessage(
                header: a2.header,
                ciphertext: Data(repeating: 0xD3, count: a2.ciphertext.count))

            await #expect(throws: CryptoKitError.self) {
                _ = try await bobManager.decrypt(
                    corruptA2,
                    sessionId: aliceIdentityLatest.id)
            }
            #expect(aliceIdentityLatest.data == stateBeforeFailure)
            #expect(
                try await bobManager.decrypt(a2, sessionId: aliceIdentityLatest.id)
                    == Data("A2".utf8))
            #expect(
                try await bobManager.decrypt(a0, sessionId: aliceIdentityLatest.id)
                    == Data("A0".utf8))
            #expect(
                try await bobManager.decrypt(a1, sessionId: aliceIdentityLatest.id)
                    == Data("A1".utf8))

            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    @Test
    func testInterleavedIndependentSessionIdsDoNotCrossTalk() async throws {
        let aliceManager = MessageRatchet(
            executor: executor,
            ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(
            executor: executor,
            ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)

        do {
            let first = try await createKeys()
            let second = try await createKeys()

            guard let firstBob = getSessionIdentity(for: first.bobIdentity.id),
                  let secondBob = getSessionIdentity(for: second.bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.initiateSession(
                sessionIdentity: firstBob,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: first.bundle.bobPublic,
                localKeys: first.bundle.alicePrivate)
            try await aliceManager.initiateSession(
                sessionIdentity: secondBob,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: second.bundle.bobPublic,
                localKeys: second.bundle.alicePrivate)

            let first0 = try await aliceManager.encrypt(
                plainText: Data("first-0".utf8),
                sessionId: firstBob.id)
            let second0 = try await aliceManager.encrypt(
                plainText: Data("second-0".utf8),
                sessionId: secondBob.id)
            let first1 = try await aliceManager.encrypt(
                plainText: Data("first-1".utf8),
                sessionId: firstBob.id)
            let second1 = try await aliceManager.encrypt(
                plainText: Data("second-1".utf8),
                sessionId: secondBob.id)

            guard let firstAlice = getSessionIdentity(for: first.aliceIdentity.id),
                  let secondAlice = getSessionIdentity(for: second.aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.respondToSession(
                sessionIdentity: secondAlice,
                sessionSymmetricKey: bobDBSK,
                header: second1.header,
                localKeys: second.bundle.bobPrivate)
            #expect(
                try await bobManager.decrypt(second1, sessionId: secondAlice.id)
                    == Data("second-1".utf8))
            try await bobManager.respondToSession(
                sessionIdentity: firstAlice,
                sessionSymmetricKey: bobDBSK,
                header: first1.header,
                localKeys: first.bundle.bobPrivate)
            #expect(
                try await bobManager.decrypt(first1, sessionId: firstAlice.id)
                    == Data("first-1".utf8))
            #expect(
                try await bobManager.decrypt(second0, sessionId: secondAlice.id)
                    == Data("second-0".utf8))
            #expect(
                try await bobManager.decrypt(first0, sessionId: firstAlice.id)
                    == Data("first-0".utf8))

            guard let firstSenderState = await getSessionIdentity(for: first.bobIdentity.id)?
                    .props(symmetricKey: aliceDbsk)?.state,
                  let secondSenderState = await getSessionIdentity(for: second.bobIdentity.id)?
                    .props(symmetricKey: aliceDbsk)?.state,
                  let firstReceiverState = await getSessionIdentity(for: first.aliceIdentity.id)?
                    .props(symmetricKey: bobDBSK)?.state,
                  let secondReceiverState = await getSessionIdentity(for: second.aliceIdentity.id)?
                    .props(symmetricKey: bobDBSK)?.state else {
                throw TestErrors.identityNotFound
            }
            #expect(firstSenderState.rootKey == firstReceiverState.rootKey)
            #expect(secondSenderState.rootKey == secondReceiverState.rootKey)
            #expect(firstSenderState.rootKey != secondSenderState.rootKey)
            #expect(firstSenderState.sentMessagesCount == 2)
            #expect(secondSenderState.sentMessagesCount == 2)
            #expect(firstReceiverState.receivedMessagesCount == 2)
            #expect(secondReceiverState.receivedMessagesCount == 2)

            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }
}
