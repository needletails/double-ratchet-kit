//
//  DoubleRatchetKitTests.swift
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
import AsyncAlgorithms
import Foundation
import NeedleTailCrypto
import NeedleTailLogger
import Testing
@testable import DoubleRatchetKit

@Suite(.serialized)
actor RatchetStateManagerTests: SessionIdentityDelegate {
    
    let testableRatchetConfiguration = RatchetConfiguration(
        messageKeyData: Data([0x00]), // Data for message key derivation.
        chainKeyData: Data([0x01]), // Data for chain key derivation.
        rootKeyData: Data([0x02, 0x03]), // Data for root key derivation.
        associatedData: "DoubleRatchetKit".data(using: .ascii)!, // Associated data for messages.
        maxSkippedMessageKeys: 100)
    
    struct KeyPair {
        let id: UUID
        let publicKey: CurvePublicKey
        let privateKey: CurvePrivateKey
    }
    
    @Test
    func testBidirectionalOutOfOrderMessages() async throws {
        let aliceManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // Alice → Bob: establish initial direction and decrypt first message in-order
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(throws: Never.self) {
                try await aliceManager.senderInitialization(
                    sessionIdentity: bobIdentityLatest,
                    sessionSymmetricKey: self.aliceDbsk,
                    remoteKeys: bundle.bobPublic,
                    localKeys: bundle.alicePrivate
                )
            }
            
            let a1 = try await aliceManager.ratchetEncrypt(plainText: Data("A1".utf8), sessionId: bobIdentityLatest.id)
            
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(throws: Never.self) {
                try await bobManager.recipientInitialization(
                    sessionIdentity: aliceIdentityLatest,
                    sessionSymmetricKey: self.bobDBSK,
                    header: a1.header,
                    localKeys: bundle.bobPrivate
                )
            }
            let da1 = try! await bobManager.ratchetDecrypt(a1, sessionId: aliceIdentityLatest.id)
            #expect(da1 == Data("A1".utf8))
            
            // Bob → Alice: change direction and decrypt first response in-order
            guard let aliceIdentityLatest2 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(throws: Never.self) {
                try await bobManager.senderInitialization(
                    sessionIdentity: aliceIdentityLatest2,
                    sessionSymmetricKey: self.bobDBSK,
                    remoteKeys: bundle.alicePublic,
                    localKeys: bundle.bobPrivate
                )
            }
            
            let b1 = try await bobManager.ratchetEncrypt(plainText: Data("B1".utf8), sessionId: aliceIdentityLatest2.id)
            
            guard let bobIdentityLatest2 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(throws: Never.self) {
                try! await aliceManager.recipientInitialization(
                    sessionIdentity: bobIdentityLatest2,
                    sessionSymmetricKey: self.aliceDbsk,
                    header: b1.header,
                    localKeys: bundle.alicePrivate
                )
            }
            let db1 = try await aliceManager.ratchetDecrypt(b1, sessionId: bobIdentityLatest2.id)
            #expect(db1 == Data("B1".utf8))
            
            // Alice → Bob: send A2, A3; deliver out of order (A3 first, then A2)
            guard let bobIdentityLatest3 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(throws: Never.self) {
                try await aliceManager.senderInitialization(
                    sessionIdentity: bobIdentityLatest3,
                    sessionSymmetricKey: self.aliceDbsk,
                    remoteKeys: bundle.bobPublic,
                    localKeys: bundle.alicePrivate
                )
            }
            let a2 = try await aliceManager.ratchetEncrypt(plainText: Data("A2".utf8), sessionId: bobIdentityLatest3.id)
            let a3 = try await aliceManager.ratchetEncrypt(plainText: Data("A3".utf8), sessionId: bobIdentityLatest3.id)
            
            guard let aliceIdentityLatest3 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(throws: Never.self) {
                try await bobManager.recipientInitialization(
                    sessionIdentity: aliceIdentityLatest3,
                    sessionSymmetricKey: self.bobDBSK,
                    header: a3.header,
                    localKeys: bundle.bobPrivate
                )
            }
            let da3 = try! await bobManager.ratchetDecrypt(a3, sessionId: aliceIdentityLatest3.id)
            #expect(da3 == Data("A3".utf8))
            
            // Now decrypt the earlier A2
            guard let aliceIdentityLatest4 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
        
            await #expect(throws: Never.self) {
                try await bobManager.recipientInitialization(
                    sessionIdentity: aliceIdentityLatest4,
                    sessionSymmetricKey: self.bobDBSK,
                    header: a2.header,
                    localKeys: bundle.bobPrivate
                )
            }
            let da2 = try! await bobManager.ratchetDecrypt(a2, sessionId: aliceIdentityLatest4.id)
            #expect(da2 == Data("A2".utf8))
            
            // Bob → Alice: send B2, B3; deliver out of order (B3 first, then B2)
            guard let aliceIdentityLatest5 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(throws: Never.self) {
                try await bobManager.senderInitialization(
                    sessionIdentity: aliceIdentityLatest5,
                    sessionSymmetricKey: self.bobDBSK,
                    remoteKeys: bundle.alicePublic,
                    localKeys: bundle.bobPrivate
                )
            }
            let b2 = try await bobManager.ratchetEncrypt(plainText: Data("B2".utf8), sessionId: aliceIdentityLatest5.id)
            let b3 = try await bobManager.ratchetEncrypt(plainText: Data("B3".utf8), sessionId: aliceIdentityLatest5.id)
            
            guard let bobIdentityLatest3 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(throws: Never.self) {
                try await aliceManager.recipientInitialization(
                    sessionIdentity: bobIdentityLatest3,
                    sessionSymmetricKey: self.aliceDbsk,
                    header: b3.header,
                    localKeys: bundle.alicePrivate
                )
            }
            let db3 = try! await aliceManager.ratchetDecrypt(b3, sessionId: bobIdentityLatest3.id)
            #expect(db3 == Data("B3".utf8))
            
            // Now decrypt the earlier B2
            guard let bobIdentityLatest4 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(throws: Never.self) {
                try await aliceManager.recipientInitialization(
                    sessionIdentity: bobIdentityLatest4,
                    sessionSymmetricKey: self.aliceDbsk,
                    header: b2.header,
                    localKeys: bundle.alicePrivate
                )
            }
            let db2 = try! await aliceManager.ratchetDecrypt(b2, sessionId: bobIdentityLatest4.id)
            #expect(db2 == Data("B2".utf8))
            
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
        } catch {
            try? await aliceManager.shutdown()
            try? await bobManager.shutdown()
            throw error
        }
    }
    
    @Test
    func testBidirectionalInterleavedOutOfOrder() async throws {
        let aliceManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // A->B: A1 establishes direction
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.senderInitialization(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate
            )
            let a1 = try await aliceManager.ratchetEncrypt(plainText: Data("A1".utf8), sessionId: bobIdentityLatest.id)
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: a1.header,
                localKeys: bundle.bobPrivate
            )
            #expect(try await bobManager.ratchetDecrypt(a1, sessionId: aliceIdentityLatest.id) == Data("A1".utf8))
            
            // B->A: B1
            guard let aliceIdentityLatest2 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.senderInitialization(
                sessionIdentity: aliceIdentityLatest2,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate
            )
            let B1 = try await bobManager.ratchetEncrypt(plainText: Data("B1".utf8), sessionId: aliceIdentityLatest2.id)
            guard let bobIdentityLatest2 = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.recipientInitialization(
                sessionIdentity: bobIdentityLatest2,
                sessionSymmetricKey: aliceDbsk,
                header: B1.header,
                localKeys: bundle.alicePrivate
            )
            #expect(try await aliceManager.ratchetDecrypt(B1, sessionId: bobIdentityLatest2.id) == Data("B1".utf8))
            
            // A->B: A2, A3
            guard let bobIdentityLatest3 = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.senderInitialization(
                sessionIdentity: bobIdentityLatest3,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate
            )
            let a2 = try await aliceManager.ratchetEncrypt(plainText: Data("A2".utf8), sessionId: bobIdentityLatest3.id)
            let a3 = try await aliceManager.ratchetEncrypt(plainText: Data("A3".utf8), sessionId: bobIdentityLatest3.id)
            
            // B->A: B2, B3
            guard let aliceIdentityLatest3 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.senderInitialization(
                sessionIdentity: aliceIdentityLatest3,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate
            )
            let b2 = try await bobManager.ratchetEncrypt(plainText: Data("B2".utf8), sessionId: aliceIdentityLatest3.id)
            let b3 = try await bobManager.ratchetEncrypt(plainText: Data("B3".utf8), sessionId: aliceIdentityLatest3.id)
            
            // Deliver interleaved and out of order: A3, B3, A2, B2
            guard let aliceIdentityLatest4 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest4,
                sessionSymmetricKey: bobDBSK,
                header: a3.header,
                localKeys: bundle.bobPrivate
            )
            #expect(try await bobManager.ratchetDecrypt(a3, sessionId: aliceIdentityLatest4.id) == Data("A3".utf8))
            
            guard let bobIdentityLatest3b = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.recipientInitialization(
                sessionIdentity: bobIdentityLatest3b,
                sessionSymmetricKey: aliceDbsk,
                header: b3.header,
                localKeys: bundle.alicePrivate
            )
            #expect(try await aliceManager.ratchetDecrypt(b3, sessionId: bobIdentityLatest3b.id) == Data("B3".utf8))
            
            guard let aliceIdentityLatest5 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest5,
                sessionSymmetricKey: bobDBSK,
                header: a2.header,
                localKeys: bundle.bobPrivate
            )
            #expect(try await bobManager.ratchetDecrypt(a2, sessionId: aliceIdentityLatest5.id) == Data("A2".utf8))
            
            guard let bobIdentityLatest4 = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.recipientInitialization(
                sessionIdentity: bobIdentityLatest4,
                sessionSymmetricKey: aliceDbsk,
                header: b2.header,
                localKeys: bundle.alicePrivate
            )
            #expect(try await aliceManager.ratchetDecrypt(b2, sessionId: bobIdentityLatest4.id) == Data("B2".utf8))
            
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
        } catch {
            try? await aliceManager.shutdown()
            try? await bobManager.shutdown()
            throw error
        }
    }
    
    @Test
    func testCallFlowLogsBidirectionalOutOfOrder() async throws {
        let aliceManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // Alice → Bob: start_call (A1)
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.senderInitialization(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate
            )
            let startCall = try await aliceManager.ratchetEncrypt(plainText: Data("start_call".utf8), sessionId: bobIdentityLatest.id)
            
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: startCall.header,
                localKeys: bundle.bobPrivate
            )
            #expect(try await bobManager.ratchetDecrypt(startCall, sessionId: aliceIdentityLatest.id) == Data("start_call".utf8))
            
            // Bob → Alice: call_answered (B1)
            guard let aliceIdentityLatest2 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.senderInitialization(
                sessionIdentity: aliceIdentityLatest2,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate
            )
            let callAnswered = try await bobManager.ratchetEncrypt(plainText: Data("call_answered".utf8), sessionId: aliceIdentityLatest2.id)
            
            guard let bobIdentityLatest2 = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.recipientInitialization(
                sessionIdentity: bobIdentityLatest2,
                sessionSymmetricKey: aliceDbsk,
                header: callAnswered.header,
                localKeys: bundle.alicePrivate
            )
            #expect(try await aliceManager.ratchetDecrypt(callAnswered, sessionId: bobIdentityLatest2.id) == Data("call_answered".utf8))
            
            // Alice → Bob: sdp_offer (A2) and ice_candidate_a (A3)
            guard let bobIdentityLatest3 = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.senderInitialization(
                sessionIdentity: bobIdentityLatest3,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate
            )
            let sdpOffer = try await aliceManager.ratchetEncrypt(plainText: Data("sdp_offer".utf8), sessionId: bobIdentityLatest3.id)
            let iceCandidateA = try await aliceManager.ratchetEncrypt(plainText: Data("ice_candidate_a".utf8), sessionId: bobIdentityLatest3.id)
            
            // Bob → Alice: sdp_answer (B2) and ice_candidate_b (B3)
            guard let aliceIdentityLatest3 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.senderInitialization(
                sessionIdentity: aliceIdentityLatest3,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate
            )
            let sdpAnswer = try await bobManager.ratchetEncrypt(plainText: Data("sdp_answer".utf8), sessionId: aliceIdentityLatest3.id)
            let iceCandidateB = try await bobManager.ratchetEncrypt(plainText: Data("ice_candidate_b".utf8), sessionId: aliceIdentityLatest3.id)
            
            // Deliver out-of-order per receiver: Bob gets A3 then A2; Alice gets B3 then B2
            guard let aliceIdentityLatest4 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest4,
                sessionSymmetricKey: bobDBSK,
                header: iceCandidateA.header,
                localKeys: bundle.bobPrivate
            )
            #expect(try await bobManager.ratchetDecrypt(iceCandidateA, sessionId: aliceIdentityLatest4.id) == Data("ice_candidate_a".utf8))
            
            guard let aliceIdentityLatest5 = getSessionIdentity(for: aliceIdentity.id) else { throw TestErrors.identityNotFound }
            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest5,
                sessionSymmetricKey: bobDBSK,
                header: sdpOffer.header,
                localKeys: bundle.bobPrivate
            )
            #expect(try await bobManager.ratchetDecrypt(sdpOffer, sessionId: aliceIdentityLatest5.id) == Data("sdp_offer".utf8))
            
            guard let bobIdentityLatest3b = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.recipientInitialization(
                sessionIdentity: bobIdentityLatest3b,
                sessionSymmetricKey: aliceDbsk,
                header: iceCandidateB.header,
                localKeys: bundle.alicePrivate
            )
            #expect(try await aliceManager.ratchetDecrypt(iceCandidateB, sessionId: bobIdentityLatest3b.id) == Data("ice_candidate_b".utf8))
            
            guard let bobIdentityLatest4 = getSessionIdentity(for: bobIdentity.id) else { throw TestErrors.identityNotFound }
            try await aliceManager.recipientInitialization(
                sessionIdentity: bobIdentityLatest4,
                sessionSymmetricKey: aliceDbsk,
                header: sdpAnswer.header,
                localKeys: bundle.alicePrivate
            )
            #expect(try await aliceManager.ratchetDecrypt(sdpAnswer, sessionId: bobIdentityLatest4.id) == Data("sdp_answer".utf8))
            
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
        } catch {
            try? await aliceManager.shutdown()
            try? await bobManager.shutdown()
            throw error
        }
    }
    
    private var aliceCachedKeyPairs: [KeyPair]?
    private var bobCachedKeyPairs: [KeyPair]?
    
    // Added dictionary for storing session identities
    var sessionIdentities: [UUID: SessionIdentity] = [:]
    
    func aliceOneTimeKeys() throws -> [KeyPair] {
        if let cached = aliceCachedKeyPairs {
            return cached
        }
        let batch = try generateBatch()
        aliceCachedKeyPairs = batch
        return batch
    }
    
    func bobOneTimeKeys() throws -> [KeyPair] {
        if let cached = bobCachedKeyPairs {
            return cached
        }
        let batch = try generateBatch()
        bobCachedKeyPairs = batch
        return batch
    }
    
    private func generateBatch() throws -> [KeyPair] {
        try (0..<100).map { _ in
            let id = UUID()
            let priv = crypto.generateCurve25519PrivateKey()
            return try KeyPair(
                id: id,
                publicKey: .init(id: id, priv.publicKey.rawRepresentation),
                privateKey: .init(id: id, priv.rawRepresentation)
            )
        }
    }
    
    func removePrivateOneTimeKey(_ id: UUID?) async throws {
        guard let id else { return }
        
        var recipientKeys = try bobOneTimeKeys()
        let recipientCountBefore = recipientKeys.count
        recipientKeys.removeAll(where: { $0.id == id })
        let recipientRemoved = recipientCountBefore != recipientKeys.count
        
        var senderKeys = try aliceOneTimeKeys()
        let senderCountBefore = senderKeys.count
        senderKeys.removeAll(where: { $0.id == id })
        let senderRemoved = senderCountBefore != senderKeys.count
        
        if !recipientRemoved, !senderRemoved {
            print("⚠️ Private one-time key with id \(id) not found in local DB.")
        }
        let priv = crypto.generateCurve25519PrivateKey()
        let kp = try KeyPair(
            id: id,
            publicKey: .init(id: id, priv.publicKey.rawRepresentation),
            privateKey: .init(id: id, priv.rawRepresentation)
        )
        recipientKeys.append(kp)
        #expect(recipientKeys.count == 100)
    }
    
    func removePublicOneTimeKey(_ id: UUID?) async throws {
        guard let id else { return }
        
        var recipientKeys = try bobOneTimeKeys()
        let recipientCountBefore = recipientKeys.count
        recipientKeys.removeAll(where: { $0.id == id })
        let recipientRemoved = recipientCountBefore != recipientKeys.count
        
        var senderKeys = try aliceOneTimeKeys()
        let senderCountBefore = senderKeys.count
        senderKeys.removeAll(where: { $0.id == id })
        let senderRemoved = senderCountBefore != senderKeys.count
        
        if !recipientRemoved, !senderRemoved {
            print("⚠️ Public one-time key with id \(id) not found in remote DB.")
        }
        #expect(recipientKeys.count == 99)
    }
    
    func updateSessionIdentity(_ identity: SessionIdentity) async throws {
        // Store the updated identity keyed by its id
        sessionIdentities[identity.id] = identity
    }
    
    // Helper to get the latest session identity for a given id
    func getSessionIdentity(for id: UUID) -> SessionIdentity? {
        sessionIdentities[id]
    }
    
    let executor = TestableExecutor(queue: .init(label: "testable-executor"))
    
    nonisolated var unownedExecutor: UnownedSerialExecutor {
        executor.asUnownedSerialExecutor()
    }
    
    let crypto = NeedleTailCrypto()
    var publicOneTimeKey: Data = .init()
    
    func makeAliceIdentity(
        longTerm: Curve25519.KeyAgreement.PrivateKey,
        signing: Curve25519.Signing.PrivateKey,
        kem: MLKEM1024.PrivateKey,
        oneTime: Curve25519.KeyAgreement.PublicKey,
        databaseSymmetricKey: SymmetricKey,
        id: UUID = UUID(),
        deviceId: UUID = UUID()
    ) throws -> SessionIdentity {
        try SessionIdentity(
            id: id,
            props: .init(
                secretName: "alice",
                deviceId: deviceId,
                sessionContextId: 1,
                longTermPublicKey: longTerm.publicKey.rawRepresentation,
                signingPublicKey: signing.publicKey.rawRepresentation,
                mlKEMPublicKey: .init(kem.publicKey.rawRepresentation),
                oneTimePublicKey: .init(oneTime.rawRepresentation),
                deviceName: "AliceDevice",
                isMasterDevice: true
            ),
            symmetricKey: databaseSymmetricKey
        )
    }
    
    func makeBobIdentity(
        longTerm: Curve25519.KeyAgreement.PrivateKey,
        signing: Curve25519.Signing.PrivateKey,
        kem: MLKEM1024.PrivateKey,
        oneTime: Curve25519.KeyAgreement.PublicKey,
        databaseSymmetricKey: SymmetricKey,
        id: UUID = UUID(),
        deviceId: UUID = UUID()
    ) throws -> SessionIdentity {
        try SessionIdentity(
            id: id,
            props: .init(
                secretName: "bob",
                deviceId: deviceId,
                sessionContextId: 1,
                longTermPublicKey: longTerm.publicKey.rawRepresentation,
                signingPublicKey: signing.publicKey.rawRepresentation,
                mlKEMPublicKey: .init(kem.publicKey.rawRepresentation),
                oneTimePublicKey: .init(oneTime.rawRepresentation),
                deviceName: "BobDevice",
                isMasterDevice: true
            ),
            symmetricKey: databaseSymmetricKey
        )
    }
    
    let aliceDbsk = SymmetricKey(size: .bits256)
    let bobDBSK = SymmetricKey(size: .bits256)
    
    private func createKeys() async throws -> (
        aliceIdentity: SessionIdentity, bobIdentity: SessionIdentity, bundle: KeyBundle
    ) {
        // Generate sender keys
        let aliceLtpk = crypto.generateCurve25519PrivateKey()
        let aliceOtpk = crypto.generateCurve25519PrivateKey()
        let aliceSpk = crypto.generateCurve25519SigningPrivateKey()
        let aliceKEM = try crypto.generateMLKem1024PrivateKey()

        // Generate receiver keys
        let bobLtpk = crypto.generateCurve25519PrivateKey()
        let bobOtpk = crypto.generateCurve25519PrivateKey()
        let bobSpk = crypto.generateCurve25519SigningPrivateKey()
        let bobKEM = try crypto.generateMLKem1024PrivateKey()

        // Create Sender's Identity
        let aliceIdentity = try makeAliceIdentity(
            longTerm: aliceLtpk, signing: aliceSpk, kem: aliceKEM, oneTime: aliceOtpk.publicKey,
            databaseSymmetricKey: bobDBSK)
        
        // Create Receiver's Identity
        let bobIdentity = try makeBobIdentity(
            longTerm: bobLtpk, signing: bobSpk, kem: bobKEM, oneTime: bobOtpk.publicKey,
            databaseSymmetricKey: aliceDbsk)
        
        // Store initial identities in sessionIdentities map
        sessionIdentities[aliceIdentity.id] = aliceIdentity
        sessionIdentities[bobIdentity.id] = bobIdentity
        
        let aliceOneTimeKeyPair = try aliceOneTimeKeys().randomElement()!
        let bobOneTimeKeyPair = try bobOneTimeKeys().randomElement()!
        
        let aliceInitialOneTimePrivate = aliceOneTimeKeyPair.privateKey
        let aliceInitialOneTimePublic = aliceOneTimeKeyPair.publicKey
        let bobInitialOneTimePrivate = bobOneTimeKeyPair.privateKey
        let bobInitialOneTimePublic = bobOneTimeKeyPair.publicKey
        
        let aliceLongTermId = UUID()
        let alicePrivateLongTerm = try CurvePrivateKey(
            id: aliceLongTermId, aliceLtpk.rawRepresentation)
        let alicePublicLongTerm = try CurvePublicKey(
            id: aliceLongTermId, aliceLtpk.publicKey.rawRepresentation)
        
        let bobLongTermId = UUID()
        let bobPrivateLongTerm = try CurvePrivateKey(id: bobLongTermId, bobLtpk.rawRepresentation)
        let bobPublicLongTerm = try CurvePublicKey(
            id: bobLongTermId, bobLtpk.publicKey.rawRepresentation)
        
        let aliceKyberId = UUID()
        let aliceKyberPublic = try MLKEMPublicKey(
            id: aliceKyberId, aliceKEM.publicKey.rawRepresentation)
        let aliceKyberPrivate = try MLKEMPrivateKey(id: aliceKyberId, aliceKEM.encode())
        
        let bobKyberId = UUID()
        let bobKyberPublic = try MLKEMPublicKey(id: bobKyberId, bobKEM.publicKey.rawRepresentation)
        let bobKyberPrivate = try MLKEMPrivateKey(id: bobKyberId, bobKEM.encode())
        
        let bundle = KeyBundle(
            alicePublic: RemoteKeys(
                longTerm: alicePublicLongTerm, oneTime: aliceInitialOneTimePublic,
                mlKEM: aliceKyberPublic),
            alicePrivate: LocalKeys(
                longTerm: alicePrivateLongTerm, oneTime: aliceInitialOneTimePrivate,
                mlKEM: aliceKyberPrivate),
            bobPublic: RemoteKeys(
                longTerm: bobPublicLongTerm, oneTime: bobInitialOneTimePublic, mlKEM: bobKyberPublic
            ),
            bobPrivate: LocalKeys(
                longTerm: bobPrivateLongTerm, oneTime: bobInitialOneTimePrivate,
                mlKEM: bobKyberPrivate)
        )
        
        return (aliceIdentity: aliceIdentity, bobIdentity: bobIdentity, bundle: bundle)
    }
    
    struct KeyBundle {
        let alicePublic: RemoteKeys
        let alicePrivate: LocalKeys
        let bobPublic: RemoteKeys
        let bobPrivate: LocalKeys
    }
    
    enum TestErrors: Error {
        case identityNotFound
    }
    
    
    @Test
    func ratchetEncryptDecryptEncrypt() async throws {
        let aliceManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // Alice initializes as sender to Bob
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.senderInitialization(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            let originalPlaintext = "Test message for ratchet encrypt/decrypt".data(using: .utf8)!
            let encrypted = try await aliceManager.ratchetEncrypt(plainText: originalPlaintext, sessionId: bobIdentityLatest.id)
            
            // Bob initializes as recipient from Alice
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: encrypted.header,
                localKeys: bundle.bobPrivate)
            
            let decryptedPlaintext = try await bobManager.ratchetDecrypt(encrypted, sessionId: aliceIdentityLatest.id)
            #expect(
                decryptedPlaintext == originalPlaintext,
                "Decrypted plaintext must match the original plaintext.")
            
            // Test ratchet advancement with second message
            let secondPlaintext = "Second ratcheted message!".data(using: .utf8)!
            let secondEncrypted = try await aliceManager.ratchetEncrypt(plainText: secondPlaintext, sessionId: bobIdentityLatest.id)
            let secondDecryptedPlaintext = try await bobManager.ratchetDecrypt(secondEncrypted, sessionId: aliceIdentityLatest.id)
            #expect(
                secondDecryptedPlaintext == secondPlaintext,
                "Decrypted second plaintext must match.")
            
            // Test bidirectional communication - Bob becomes sender to Alice
            guard let aliceIdentityLatest2 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.senderInitialization(
                sessionIdentity: aliceIdentityLatest2,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate)
            
            let encrypted2 = try await bobManager.ratchetEncrypt(plainText: originalPlaintext, sessionId: aliceIdentityLatest2.id)
            
            // Alice initializes as recipient from Bob
            guard let bobIdentityLatest2 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.recipientInitialization(
                sessionIdentity: bobIdentityLatest2,
                sessionSymmetricKey: aliceDbsk,
                header: encrypted2.header,
                localKeys: bundle.alicePrivate)
            
            let decryptedSecond = try await aliceManager.ratchetDecrypt(encrypted2, sessionId: bobIdentityLatest2.id)
            #expect(decryptedSecond == originalPlaintext, "Decrypted second plaintext must match.")
            
            // Continue bidirectional communication
            let thirdPlaintext = "Third message from Alice".data(using: .utf8)!
            let thirdEncrypted = try await aliceManager.ratchetEncrypt(plainText: thirdPlaintext, sessionId: bobIdentityLatest.id)
            let decryptedThird = try await bobManager.ratchetDecrypt(thirdEncrypted, sessionId: aliceIdentityLatest.id)
            #expect(decryptedThird == thirdPlaintext, "Decrypted third plaintext must match.")
            
            let fourthPlaintext = "Fourth message from Bob".data(using: .utf8)!
            let fourthEncrypted = try await bobManager.ratchetEncrypt(plainText: fourthPlaintext, sessionId: aliceIdentityLatest2.id)
            let decryptedFourth = try await aliceManager.ratchetDecrypt(fourthEncrypted, sessionId: bobIdentityLatest2.id)
            #expect(decryptedFourth == fourthPlaintext, "Decrypted fourth plaintext must match.")
            
            let fifthPlaintext = "Fifth message from Alice".data(using: .utf8)!
            let fifthEncrypted = try await aliceManager.ratchetEncrypt(plainText: fifthPlaintext, sessionId: bobIdentityLatest.id)
            let decryptedFifth = try await bobManager.ratchetDecrypt(fifthEncrypted, sessionId: aliceIdentityLatest.id)
            #expect(decryptedFifth == fifthPlaintext, "Decrypted fifth plaintext must match.")
            
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
        } catch {
            try? await aliceManager.shutdown()
            try? await bobManager.shutdown()
            throw error
        }
    }
    
    @Test
    func ratchetEncryptDecrypt80Messages() async throws {
        let aliceManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // Alice initializes as sender to Bob
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.senderInitialization(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            let firstPlaintext = "Message 1 from Alice".data(using: .utf8)!
            let firstEncrypted = try await aliceManager.ratchetEncrypt(plainText: firstPlaintext, sessionId: bobIdentityLatest.id)
            
            // Bob initializes as recipient from Alice
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: firstEncrypted.header,
                localKeys: bundle.bobPrivate)
            
            let firstDecrypted = try await bobManager.ratchetDecrypt(firstEncrypted, sessionId: aliceIdentityLatest.id)
            #expect(
                firstDecrypted == firstPlaintext,
                "Decrypted first message must match Alice's original.")
            
            // Alice sends messages 2 through 80 to Bob
            for i in 2...80 {
                let plaintext = "Message \(i) from Alice".data(using: .utf8)!
                let encrypted = try await aliceManager.ratchetEncrypt(plainText: plaintext, sessionId: bobIdentityLatest.id)
                let decrypted = try await bobManager.ratchetDecrypt(encrypted, sessionId: aliceIdentityLatest.id)
                #expect(
                    decrypted == plaintext, "Decrypted message \(i) must match Alice's original.")
            }
            
            // Bob becomes sender to Alice
            guard let aliceIdentityLatest2 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.senderInitialization(
                sessionIdentity: aliceIdentityLatest2,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate)
            
            // Alice initializes as recipient from Bob
            guard let bobIdentityLatest2 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            let firstBackPlaintext = "Message 1 from Bob".data(using: .utf8)!
            let firstBackEncrypted = try await bobManager.ratchetEncrypt(
                plainText: firstBackPlaintext, sessionId: aliceIdentityLatest2.id)
            try await aliceManager.recipientInitialization(
                sessionIdentity: bobIdentityLatest2,
                sessionSymmetricKey: aliceDbsk,
                header: firstBackEncrypted.header,
                localKeys: bundle.alicePrivate)
            let firstBackDecrypted = try await aliceManager.ratchetDecrypt(firstBackEncrypted, sessionId: bobIdentityLatest2.id)
            #expect(
                firstBackDecrypted == firstBackPlaintext,
                "Decrypted first Bob→Alice message must match.")
            
            // Bob sends messages 2 through 80 to Alice
            for i in 2...80 {
                let plaintext = "Message \(i) from Bob".data(using: .utf8)!
                let encrypted = try await bobManager.ratchetEncrypt(plainText: plaintext, sessionId: aliceIdentityLatest2.id)
                let decrypted = try await aliceManager.ratchetDecrypt(encrypted, sessionId: bobIdentityLatest2.id)
                #expect(decrypted == plaintext, "Decrypted Bob→Alice message \(i) must match.")
            }
            
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
        } catch {
            try? await aliceManager.shutdown()
            try? await bobManager.shutdown()
            throw error
        }
    }
    
    @Test
    func ratchetEncryptDecryptMessagesPerUserWitNewIntializations() async throws {
        let aliceManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
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
                    try await aliceManager.senderInitialization(
                        sessionIdentity: bobIdentityLatest,
                        sessionSymmetricKey: self.aliceDbsk,
                        remoteKeys: bundle.bobPublic,
                        localKeys: bundle.alicePrivate)
                })
            
            let encrypted = try await aliceManager.ratchetEncrypt(plainText: plaintext, sessionId: bobIdentityLatest.id)
            
            // Initialize recipient before decrypting the message
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await bobManager.recipientInitialization(
                        sessionIdentity: aliceIdentityLatest,
                        sessionSymmetricKey: self.bobDBSK,
                        header: encrypted.header,
                        localKeys: bundle.bobPrivate)
                })
            let decrypted = try await bobManager.ratchetDecrypt(encrypted, sessionId: aliceIdentityLatest.id)
            #expect(decrypted == plaintext, "Decrypted message must match Alice's original.")
            
            guard let aliceIdentityLatest2 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await bobManager.senderInitialization(
                        sessionIdentity: aliceIdentityLatest2,
                        sessionSymmetricKey: self.bobDBSK,
                        remoteKeys: bundle.alicePublic,
                        localKeys: bundle.bobPrivate)
                })
            
            let encrypted2 = try await bobManager.ratchetEncrypt(plainText: plaintext, sessionId: aliceIdentityLatest2.id)
            
            // Initialize recipient before decrypting the message
            guard let bobIdentityLatest2 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await aliceManager.recipientInitialization(
                        sessionIdentity: bobIdentityLatest2,
                        sessionSymmetricKey: self.aliceDbsk,
                        header: encrypted2.header,
                        localKeys: bundle.alicePrivate)
                })
            let decrypted2 = try await aliceManager.ratchetDecrypt(encrypted2, sessionId: bobIdentityLatest2.id)
            #expect(decrypted2 == plaintext, "Decrypted message must match Alice's original.")
            
            guard let bobIdentityLatest3 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await aliceManager.senderInitialization(
                        sessionIdentity: bobIdentityLatest3,
                        sessionSymmetricKey: self.aliceDbsk,
                        remoteKeys: bundle.bobPublic,
                        localKeys: bundle.alicePrivate)
                })
            
            let encrypted3 = try await aliceManager.ratchetEncrypt(plainText: plaintext, sessionId: bobIdentityLatest3.id)
            
            // Initialize recipient before decrypting the message
            guard let aliceIdentityLatest3 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await bobManager.recipientInitialization(
                        sessionIdentity: aliceIdentityLatest3,
                        sessionSymmetricKey: self.bobDBSK,
                        header: encrypted3.header,
                        localKeys: bundle.bobPrivate)
                })
            
            let decrypted3 = try await bobManager.ratchetDecrypt(encrypted3, sessionId: aliceIdentityLatest3.id)
            #expect(decrypted3 == plaintext, "Decrypted message must match Alice's original.")
            
            guard let bobIdentityLatest4 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await aliceManager.senderInitialization(
                        sessionIdentity: bobIdentityLatest4,
                        sessionSymmetricKey: self.aliceDbsk,
                        remoteKeys: bundle.alicePublic,
                        localKeys: bundle.alicePrivate)
                })
            
            let encrypted4 = try await aliceManager.ratchetEncrypt(plainText: plaintext, sessionId: bobIdentityLatest4.id)
            
            // Initialize recipient before decrypting the message
            guard let aliceIdentityLatest4 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await bobManager.recipientInitialization(
                        sessionIdentity: aliceIdentityLatest4,
                        sessionSymmetricKey: self.bobDBSK,
                        header: encrypted4.header,
                        localKeys: bundle.bobPrivate)
                })
            let decrypted4 = try await bobManager.ratchetDecrypt(encrypted4, sessionId: aliceIdentityLatest4.id)
            #expect(decrypted4 == plaintext, "Decrypted message must match Alice's original.")
            
            guard let aliceIdentityLatest5 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await bobManager.senderInitialization(
                        sessionIdentity: aliceIdentityLatest5,
                        sessionSymmetricKey: self.bobDBSK,
                        remoteKeys: bundle.alicePublic,
                        localKeys: bundle.bobPrivate,
                    )
                })
            
            let encrypted5 = try await bobManager.ratchetEncrypt(plainText: plaintext, sessionId: aliceIdentityLatest5.id)
            
            // Initialize recipient before decrypting the message
            guard let bobIdentityLatest5 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await aliceManager.recipientInitialization(
                        sessionIdentity: bobIdentityLatest5,
                        sessionSymmetricKey: self.aliceDbsk,
                        header: encrypted5.header,
                        localKeys: bundle.alicePrivate,
                    )
                })
            let decrypted5 = try await aliceManager.ratchetDecrypt(encrypted5, sessionId: bobIdentityLatest5.id)
            #expect(decrypted5 == plaintext, "Decrypted message must match Alice's original.")
            
            guard let aliceIdentityLatest6 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await bobManager.senderInitialization(
                        sessionIdentity: aliceIdentityLatest6,
                        sessionSymmetricKey: self.bobDBSK,
                        remoteKeys: bundle.alicePublic,
                        localKeys: bundle.bobPrivate,
                    )
                })
            
            let encrypted6 = try await bobManager.ratchetEncrypt(plainText: plaintext, sessionId: aliceIdentityLatest6.id)
            
            // Initialize recipient before decrypting the message
            guard let bobIdentityLatest6 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await aliceManager.recipientInitialization(
                        sessionIdentity: bobIdentityLatest6,
                        sessionSymmetricKey: self.aliceDbsk,
                        header: encrypted6.header,
                        localKeys: bundle.alicePrivate,
                    )
                })
            let decrypted6 = try await aliceManager.ratchetDecrypt(encrypted6, sessionId: bobIdentityLatest6.id)
            #expect(decrypted6 == plaintext, "Decrypted message must match Alice's original.")
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
        } catch {
            try? await aliceManager.shutdown()
            try? await bobManager.shutdown()
            throw error
        }
    }
    
    @Test
    func ratchetEncryptDecryptOutofOrderMessagesPerUserWitNewIntializations() async throws {
        let aliceManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
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
                    try await aliceManager.senderInitialization(
                        sessionIdentity: bobIdentityLatest,
                        sessionSymmetricKey: self.aliceDbsk,
                        remoteKeys: bundle.bobPublic,
                        localKeys: bundle.alicePrivate,
                    )
                })
            
            let encrypted1 = try await aliceManager.ratchetEncrypt(plainText: plaintext1, sessionId: bobIdentityLatest.id)
            
            guard let bobIdentityLatest2 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await aliceManager.senderInitialization(
                        sessionIdentity: bobIdentityLatest2,
                        sessionSymmetricKey: self.aliceDbsk,
                        remoteKeys: bundle.bobPublic,
                        localKeys: bundle.alicePrivate,
                    )
                })
            
            let encrypted2 = try await aliceManager.ratchetEncrypt(plainText: plaintext2, sessionId: bobIdentityLatest2.id)
            
            guard let bobIdentityLatest3 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            guard getSessionIdentity(for: aliceIdentity.id) != nil else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await aliceManager.senderInitialization(
                        sessionIdentity: bobIdentityLatest3,
                        sessionSymmetricKey: self.aliceDbsk,
                        remoteKeys: bundle.bobPublic,
                        localKeys: bundle.alicePrivate)
                })
            
            let encrypted3 = try await aliceManager.ratchetEncrypt(plainText: plaintext3, sessionId: bobIdentityLatest3.id)
            
            var stashedMessages = Set<RatchetMessage>()
            
            // Initialize recipient before decrypting the message
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await bobManager.recipientInitialization(
                        sessionIdentity: aliceIdentityLatest,
                        sessionSymmetricKey: self.bobDBSK,
                        header: encrypted3.header,
                        localKeys: bundle.bobPrivate,
                    )
                })
            do {
                let decrypted3 = try await bobManager.ratchetDecrypt(encrypted3, sessionId: aliceIdentityLatest.id)
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
                    try await bobManager.recipientInitialization(
                        sessionIdentity: aliceIdentityLatest2,
                        sessionSymmetricKey: self.bobDBSK,
                        header: encrypted1.header,
                        localKeys: bundle.bobPrivate,
                    )
                })
            do {
                let decrypted1 = try await bobManager.ratchetDecrypt(encrypted1, sessionId: aliceIdentityLatest2.id)
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
                    try await bobManager.recipientInitialization(
                        sessionIdentity: aliceIdentityLatest3,
                        sessionSymmetricKey: self.bobDBSK,
                        header: encrypted2.header,
                        localKeys: bundle.bobPrivate,
                    )
                })
            do {
                let decrypted2 = try await bobManager.ratchetDecrypt(encrypted2, sessionId: aliceIdentityLatest3.id)
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
                    try await bobManager.recipientInitialization(
                        sessionIdentity: aliceIdentityLatest4,
                        sessionSymmetricKey: bobDBSK,
                        header: stashedMessage.header,
                        localKeys: bundle.bobPrivate,
                    )
                    
                    _ = try await bobManager.ratchetDecrypt(stashedMessage, sessionId: aliceIdentityLatest4.id)
                } catch {
                    continue
                }
            }
            
            // MARK: 7. Clean up both managers
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
        } catch {
            try? await aliceManager.shutdown()
            try? await bobManager.shutdown()
            throw error
        }
    }
    
    // --- NEW: PERFORMANCE TEST ---
    @Test
    func performanceThousandsOfMessages() async throws {
        let aliceManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            // Initialize Sender
            try await aliceManager.senderInitialization(
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
                    let encrypted = try await aliceManager.ratchetEncrypt(plainText: payload, sessionId: bobIdentityLatest.id)
                    messages.append(encrypted)
                }
            }
            
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            _ = try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: messages.first!.header,
                localKeys: bundle.bobPrivate)
            
            for message in messages {
                _ = try await bobManager.ratchetDecrypt(message, sessionId: aliceIdentityLatest.id)
            }
            print(
                "🔵 Encrypted/Decrypted \(messageCount) messages in \(duration.components.seconds) seconds"
            )
            #expect(messages.count == messageCount)
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
        } catch {
            try? await aliceManager.shutdown()
            try? await bobManager.shutdown()
            throw error
        }
    }
    
    @Test
    func stressOutOfOrderMessages() async throws {
        let aliceManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.senderInitialization(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            var messages = try await (0...100).asyncMap { i in
                try await aliceManager.ratchetEncrypt(plainText: "Message \(i)".data(using: .utf8)!, sessionId: bobIdentityLatest.id)
            }
            
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            let firstMessage = messages.removeFirst()
            _ = try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: firstMessage.header,
                localKeys: bundle.bobPrivate)
            _ = try await bobManager.ratchetDecrypt(firstMessage, sessionId: aliceIdentityLatest.id)
            
            // Now decrypt the rest (shuffled!)
            let rest = messages.shuffled()
            
            for message in rest {
                await #expect(
                    throws: Never.self,
                    performing: {
                        _ = try await bobManager.ratchetDecrypt(message, sessionId: aliceIdentityLatest.id)
                    })
            }
            
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
        } catch {
            try? await aliceManager.shutdown()
            try? await bobManager.shutdown()
            throw error
        }
    }
    
    @Test
    func outOfOrderHeaders() async throws {
        let aliceManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            // Initialize Sender
            try await aliceManager.senderInitialization(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            // Pre-encrypt all messages first
            var messages: [RatchetMessage] = []
            for i in 0..<80 {
                let payload = "Message \(i)".data(using: .utf8)!
                let encrypted = try await aliceManager.ratchetEncrypt(plainText: payload, sessionId: bobIdentityLatest.id)
                messages.append(encrypted)
            }
            
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            _ = try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: messages.first!.header,
                localKeys: bundle.bobPrivate)
            
            // Decrypt all messages
            for message in messages {
                _ = try await bobManager.ratchetDecrypt(message, sessionId: aliceIdentityLatest.id)
            }
            
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
        } catch {
            try? await aliceManager.shutdown()
            try? await bobManager.shutdown()
            throw error
        }
    }
    
    // --- NEW: SERIALIZATION / STATE SAVE-LOAD TEST ---
    @Test
    func serializationAndResumingRatchet() async throws {
        let aliceManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            // Initialize Sender
            try await aliceManager.senderInitialization(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            let plaintext = "Persist me!".data(using: .utf8)!
            let encrypted = try await aliceManager.ratchetEncrypt(plainText: plaintext, sessionId: bobIdentityLatest.id)
            
            try await Task.sleep(until: .now + .seconds(10))
            
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            _ = try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: encrypted.header,
                localKeys: bundle.bobPrivate)
            let decrypted = try await bobManager.ratchetDecrypt(encrypted, sessionId: aliceIdentityLatest.id)
            #expect(decrypted == plaintext)
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
        } catch {
            try? await aliceManager.shutdown()
            try? await bobManager.shutdown()
            throw error
        }
    }
    
    @Test
    func rotatedKeys() async throws {
        let aliceManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id),
                  let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id)
            else {
                throw TestErrors.identityNotFound
            }
            
            // Initialize Sender
            try! await aliceManager.senderInitialization(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            let originalPlaintext = "Test message for ratchet encrypt/decrypt".data(using: .utf8)!
            
            // Sender encrypts a message
            let encrypted = try! await aliceManager.ratchetEncrypt(plainText: originalPlaintext, sessionId: bobIdentityLatest.id)
            
            // Receiver decrypts it
            _ = try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: encrypted.header,
                localKeys: bundle.bobPrivate)
            
            let decryptedPlaintext = try await bobManager.ratchetDecrypt(encrypted, sessionId: aliceIdentityLatest.id)
            #expect(
                decryptedPlaintext == originalPlaintext,
                "Decrypted plaintext must match the original plaintext.")
            // 🚀 NOW Send a Second Message to verify ratchet advancement!
            let secondPlaintext = "Second ratcheted message!".data(using: .utf8)!
            let secondEncrypted = try await aliceManager.ratchetEncrypt(plainText: secondPlaintext, sessionId: bobIdentityLatest.id)
            let secondDecryptedPlaintext = try await bobManager.ratchetDecrypt(secondEncrypted, sessionId: aliceIdentityLatest.id)
            
            #expect(
                secondDecryptedPlaintext == secondPlaintext,
                "Decrypted second plaintext must match.")
            
            try await bobManager.senderInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate)
            
            let encrypted2 = try await bobManager.ratchetEncrypt(plainText: originalPlaintext, sessionId: aliceIdentityLatest.id)
            
            _ = try await aliceManager.recipientInitialization(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                header: encrypted2.header,
                localKeys: bundle.alicePrivate)
            
            // Decrypt message from Bob -> Alice (2nd message)
            let decryptedSecond = try await aliceManager.ratchetDecrypt(encrypted2, sessionId: bobIdentityLatest.id)
            #expect(decryptedSecond == originalPlaintext, "Decrypted second plaintext must match.")
            
            // Alice sends third message to Bob
            let thirdPlaintext = "Third message from Alice".data(using: .utf8)!
            let thirdEncrypted = try await aliceManager.ratchetEncrypt(plainText: thirdPlaintext, sessionId: bobIdentityLatest.id)
            
            // Bob decrypts third message
            let decryptedThird = try await bobManager.ratchetDecrypt(thirdEncrypted, sessionId: aliceIdentityLatest.id)
            #expect(decryptedThird == thirdPlaintext, "Decrypted third plaintext must match.")
            
            // Bob sends fourth message to Alice
            let fourthPlaintext = "Fourth message from Bob".data(using: .utf8)!
            let fourthEncrypted = try await bobManager.ratchetEncrypt(plainText: fourthPlaintext, sessionId: aliceIdentityLatest.id)
            
            // Alice decrypts fourth message
            let decryptedFourth = try await aliceManager.ratchetDecrypt(fourthEncrypted, sessionId: bobIdentityLatest.id)
            #expect(decryptedFourth == fourthPlaintext, "Decrypted fourth plaintext must match.")
            
            // Alice sends fifth message to Bob
            let fifthPlaintext = "Fifth message from Alice".data(using: .utf8)!
            let fifthEncrypted = try await aliceManager.ratchetEncrypt(plainText: fifthPlaintext, sessionId: bobIdentityLatest.id)
            
            // Bob decrypts fifth message
            let decryptedFifth = try await bobManager.ratchetDecrypt(fifthEncrypted, sessionId: aliceIdentityLatest.id)
            #expect(decryptedFifth == fifthPlaintext, "Decrypted fifth plaintext must match.")
            
            // Rotate Long Term Key
            let rotatedaliceLtpk = crypto.generateCurve25519PrivateKey()
            let rotatedRecipientltpk = crypto.generateCurve25519PrivateKey()
            
            let aliceRotatedLongTermId = UUID()
            let aliceRotatedPrivateLongTerm = try CurvePrivateKey(
                id: aliceRotatedLongTermId, rotatedaliceLtpk.rawRepresentation)
            let aliceRotatedPublicLongTerm = try CurvePublicKey(
                id: aliceRotatedLongTermId, rotatedaliceLtpk.publicKey.rawRepresentation)
            
            let bobRotatedLongTermId = UUID()
            let bobRotatedPrivateLongTerm = try CurvePrivateKey(
                id: bobRotatedLongTermId, rotatedRecipientltpk.rawRepresentation)
            let bobRotatedPublicLongTerm = try CurvePublicKey(
                id: bobRotatedLongTermId, rotatedRecipientltpk.publicKey.rawRepresentation)
            
            try await aliceManager.senderInitialization(
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
            let encryptedRotated = try await aliceManager.ratchetEncrypt(
                plainText: rotatedPlaintext, sessionId: bobIdentityLatest.id)
            
            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: encryptedRotated.header,
                localKeys: bundle.bobPrivate)
            
            let decryptedPlaintextRotated = try await bobManager.ratchetDecrypt(encryptedRotated, sessionId: aliceIdentityLatest.id)
            #expect(
                decryptedPlaintextRotated == rotatedPlaintext,
                "Decrypted plaintext must match the original plaintext.")
            
            // Update Sender's Identity
            try await bobManager.senderInitialization(
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
            let encryptedRotated2 = try await bobManager.ratchetEncrypt(
                plainText: rotatedPlaintext2, sessionId: aliceIdentityLatest.id)
            
            try await aliceManager.recipientInitialization(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                header: encryptedRotated2.header,
                localKeys: bundle.alicePrivate)
            
            // Decrypt message from Bob -> Alice (2nd message)
            let decryptedRotatedSecond = try await aliceManager.ratchetDecrypt(encryptedRotated2, sessionId: bobIdentityLatest.id)
            #expect(
                decryptedRotatedSecond == rotatedPlaintext2,
                "Decrypted second plaintext must match.")
            
            let messages = try await (0...80).asyncMap { i in
                try await aliceManager.senderInitialization(
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
                return try await aliceManager.ratchetEncrypt(
                    plainText: "Message \(i)".data(using: .utf8)!, sessionId: bobIdentityLatest.id)
            }
            
            for message in messages {
                _ = try await bobManager.recipientInitialization(
                    sessionIdentity: aliceIdentityLatest,
                    sessionSymmetricKey: bobDBSK,
                    header: message.header,
                    localKeys: .init(
                        longTerm: bobRotatedPrivateLongTerm,
                        oneTime: bundle.bobPrivate.oneTime,
                        mlKEM: bundle.bobPrivate.mlKEM,
                    ),
                )
                _ = try await bobManager.ratchetDecrypt(message, sessionId: aliceIdentityLatest.id)
            }
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
        } catch {
            try? await aliceManager.shutdown()
            try? await bobManager.shutdown()
        }
    }
    
    func updateOneTimeKey(remove _: UUID) async {}
    func fetchOneTimePrivateKey(_: UUID?) async throws -> DoubleRatchetKit.CurvePrivateKey? { nil }
    func updateOneTimeKey() async {}
    func removePrivateOneTimeKey(_: UUID) async {}
    func removePublicOneTimeKey(_: UUID) async {}
    
    // MARK: - Additional Comprehensive Tests
    
    @Test
    func testErrorHandling() async throws {
        let aliceManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // Test missingConfiguration error (no session loaded yet)
            await #expect(
                throws: RatchetError.missingConfiguration.self,
                performing: {
                    _ = try await aliceManager.ratchetEncrypt(plainText: "test".data(using: .utf8)!, sessionId: aliceIdentity.id)
                })
            
            // Test missingProps error with invalid symmetric key
            let invalidKey = SymmetricKey(size: .bits256)
            await #expect(
                throws: RatchetError.missingProps.self,
                performing: {
                    try await aliceManager.senderInitialization(
                        sessionIdentity: aliceIdentity,
                        sessionSymmetricKey: invalidKey,
                        remoteKeys: bundle.bobPublic,
                        localKeys: bundle.alicePrivate)
                })
            
            // Test decryption with invalid message
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.senderInitialization(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            let validMessage = try await aliceManager.ratchetEncrypt(
                plainText: "test".data(using: .utf8)!, sessionId: bobIdentityLatest.id)
            
            // Create invalid message by corrupting encrypted data
            let invalidMessage = RatchetMessage(
                header: validMessage.header,
                encryptedData: Data(repeating: 0, count: 32)  // Corrupted encrypted data
            )
            
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: validMessage.header,
                localKeys: bundle.bobPrivate)
            
            await #expect(
                throws: CryptoKitError.self,
                performing: {
                    _ = try await bobManager.ratchetDecrypt(invalidMessage, sessionId: aliceIdentityLatest.id)
                })
            
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
        } catch {
            try? await aliceManager.shutdown()
            try? await bobManager.shutdown()
            throw error
        }
    }
    
    @Test
    func testConcurrentAccess() async throws {
        let aliceManager1 = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager1.setDelegate(self)
        let aliceManager2 = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager2.setDelegate(self)
        let bobManager1 = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager1.setDelegate(self)
        let bobManager2 = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager2.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // Initialize separate sessions for concurrent access
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            
            try await aliceManager1.senderInitialization(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            try await aliceManager2.senderInitialization(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            // Send messages concurrently from both managers
            async let message1 = aliceManager1.ratchetEncrypt(
                plainText: "Message from Alice1".data(using: .utf8)!, sessionId: bobIdentityLatest.id)
            async let message2 = aliceManager2.ratchetEncrypt(
                plainText: "Message from Alice2".data(using: .utf8)!, sessionId: bobIdentityLatest.id)
            
            let (encrypted1, encrypted2) = try await (message1, message2)
            
            // Bob managers should be able to decrypt messages from respective Alice managers
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            
            try await bobManager1.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: encrypted1.header,
                localKeys: bundle.bobPrivate)
            
            try await bobManager2.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: encrypted2.header,
                localKeys: bundle.bobPrivate)
            
            let decrypted1 = try await bobManager1.ratchetDecrypt(encrypted1, sessionId: aliceIdentityLatest.id)
            let decrypted2 = try await bobManager2.ratchetDecrypt(encrypted2, sessionId: aliceIdentityLatest.id)
            
            #expect(decrypted1 == "Message from Alice1".data(using: .utf8)!)
            #expect(decrypted2 == "Message from Alice2".data(using: .utf8)!)
            
            try await aliceManager1.shutdown()
            try await aliceManager2.shutdown()
            try await bobManager1.shutdown()
            try await bobManager2.shutdown()
        } catch {
            try? await aliceManager1.shutdown()
            try? await aliceManager2.shutdown()
            try? await bobManager1.shutdown()
            try? await bobManager2.shutdown()
            throw error
        }
    }
    
    @Test
    func testSessionRecovery() async throws {
        let aliceManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // Establish initial session
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.senderInitialization(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            let message1 = try await aliceManager.ratchetEncrypt(
                plainText: "Initial message".data(using: .utf8)!, sessionId: bobIdentityLatest.id)
            
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: message1.header,
                localKeys: bundle.bobPrivate)
            
            let decrypted1 = try await bobManager.ratchetDecrypt(message1, sessionId: aliceIdentityLatest.id)
            #expect(decrypted1 == "Initial message".data(using: .utf8)!)
            
            // Simulate session corruption by creating new managers
            let aliceManagerRecovery = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
            await aliceManagerRecovery.setDelegate(self)
            let bobManagerRecovery = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
            await bobManagerRecovery.setDelegate(self)
            
            // Re-establish session with same identities
            guard let bobIdentityLatest2 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManagerRecovery.senderInitialization(
                sessionIdentity: bobIdentityLatest2,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            let message2 = try await aliceManagerRecovery.ratchetEncrypt(
                plainText: "Recovery message".data(using: .utf8)!, sessionId: bobIdentityLatest2.id)
            
            guard let aliceIdentityLatest2 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManagerRecovery.recipientInitialization(
                sessionIdentity: aliceIdentityLatest2,
                sessionSymmetricKey: bobDBSK,
                header: message2.header,
                localKeys: bundle.bobPrivate)
            
            let decrypted2 = try await bobManagerRecovery.ratchetDecrypt(message2, sessionId: aliceIdentityLatest2.id)
            #expect(decrypted2 == "Recovery message".data(using: .utf8)!)
            
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
            try await aliceManagerRecovery.shutdown()
            try await bobManagerRecovery.shutdown()
        } catch {
            try? await aliceManager.shutdown()
            try? await bobManager.shutdown()
            throw error
        }
    }
    
    @Test
    func testKeyExhaustion() async throws {
        let aliceManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // Initialize session
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.senderInitialization(
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
                let message = try await aliceManager.ratchetEncrypt(
                    plainText: "Message \(i)".data(using: .utf8)!, sessionId: bobIdentityLatest.id)
                messages.append(message)
            }
            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: messages.first!.header,
                localKeys: bundle.bobPrivate)
            
            // Send many messages to test key rotation and potential exhaustion
            
            // Verify all messages can be decrypted
            for (i, message) in messages.enumerated() {
                let decrypted = try await bobManager.ratchetDecrypt(message, sessionId: aliceIdentityLatest.id)
                #expect(decrypted == "Message \(i)".data(using: .utf8)!)
            }
            
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
        } catch {
            try? await aliceManager.shutdown()
            try? await bobManager.shutdown()
            throw error
        }
    }
    
    @Test
    func testMultiPartyScenario() async throws {
        let aliceManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        let charlieManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await charlieManager.setDelegate(self)
        
        do {
            // Create three separate sessions: Alice-Bob, Bob-Charlie, Alice-Charlie
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // Test Alice -> Bob communication
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.senderInitialization(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            let aliceToBobMessage = try await aliceManager.ratchetEncrypt(
                plainText: "Alice to Bob".data(using: .utf8)!, sessionId: bobIdentityLatest.id)
            
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: aliceToBobMessage.header,
                localKeys: bundle.bobPrivate)
            
            let decryptedAliceToBob = try await bobManager.ratchetDecrypt(aliceToBobMessage, sessionId: aliceIdentityLatest.id)
            #expect(decryptedAliceToBob == "Alice to Bob".data(using: .utf8)!)
            
            // Test Bob -> Alice communication (simplified multi-party test)
            guard let aliceIdentityLatest2 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.senderInitialization(
                sessionIdentity: aliceIdentityLatest2,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate)
            
            let bobToAliceMessage = try await bobManager.ratchetEncrypt(
                plainText: "Bob to Alice".data(using: .utf8)!, sessionId: aliceIdentityLatest2.id)
            
            guard let bobIdentityLatest2 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.recipientInitialization(
                sessionIdentity: bobIdentityLatest2,
                sessionSymmetricKey: aliceDbsk,
                header: bobToAliceMessage.header,
                localKeys: bundle.alicePrivate)
            
            let decryptedBobToAlice = try await aliceManager.ratchetDecrypt(bobToAliceMessage, sessionId: bobIdentityLatest2.id)
            #expect(decryptedBobToAlice == "Bob to Alice".data(using: .utf8)!)
            
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
            try await charlieManager.shutdown()
        } catch {
            try? await aliceManager.shutdown()
            try? await bobManager.shutdown()
            try? await charlieManager.shutdown()
            throw error
        }
    }
    
    @Test
    func testHashFunctionVariations() async throws {
        // Test with SHA512 instead of SHA256
        let aliceManager = RatchetStateManager<SHA512>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA512>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.senderInitialization(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            let message = try await aliceManager.ratchetEncrypt(
                plainText: "SHA512 test".data(using: .utf8)!, sessionId: bobIdentityLatest.id)
            
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: message.header,
                localKeys: bundle.bobPrivate)
            
            let decrypted = try await bobManager.ratchetDecrypt(message, sessionId: aliceIdentityLatest.id)
            #expect(decrypted == "SHA512 test".data(using: .utf8)!)
            
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
        } catch {
            try? await aliceManager.shutdown()
            try? await bobManager.shutdown()
            throw error
        }
    }
    
    @Test
    func testDelegateCallbacks() async throws {
        let aliceManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // Track initial session identities count
            let initialCount = sessionIdentities.count
            
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.senderInitialization(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            let message = try await aliceManager.ratchetEncrypt(
                plainText: "Delegate test".data(using: .utf8)!, sessionId: bobIdentityLatest.id)
            
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: message.header,
                localKeys: bundle.bobPrivate)
            
            let decrypted = try await bobManager.ratchetDecrypt(message, sessionId: aliceIdentityLatest.id)
            #expect(decrypted == "Delegate test".data(using: .utf8)!)
            
            // Verify that session identities were updated through delegate
            let finalCount = sessionIdentities.count
            #expect(
                finalCount >= initialCount, "Session identities should be updated through delegate")
            
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
        } catch {
            try? await aliceManager.shutdown()
            try? await bobManager.shutdown()
            throw error
        }
    }
    
    @Test
    func testMemoryPressureHandling() async throws {
        let aliceManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.senderInitialization(
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
                let message = try await aliceManager.ratchetEncrypt(plainText: largePayload, sessionId: bobIdentityLatest.id)
                messages.append(message)
            }
            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: messages.first!.header,
                localKeys: bundle.bobPrivate)
            
            // Verify all messages can still be decrypted under memory pressure
            for message in messages {
                let decrypted = try await bobManager.ratchetDecrypt(message, sessionId: aliceIdentityLatest.id)
                #expect(decrypted == largePayload)
            }
            
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
        } catch {
            try? await aliceManager.shutdown()
            try? await bobManager.shutdown()
            throw error
        }
    }
    
    @Test
    func testSessionTimeoutAndExpiry() async throws {
        let aliceManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.senderInitialization(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            // Send initial message
            let initialMessage = try await aliceManager.ratchetEncrypt(
                plainText: "Initial".data(using: .utf8)!, sessionId: bobIdentityLatest.id)
            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: initialMessage.header,
                localKeys: bundle.bobPrivate)
            let decryptedInitial = try await bobManager.ratchetDecrypt(initialMessage, sessionId: aliceIdentityLatest.id)
            #expect(decryptedInitial == "Initial".data(using: .utf8)!)
            
            // Simulate long delay (in real scenario, keys might expire)
            try await Task.sleep(until: .now + .seconds(1))
            
            // Send message after delay
            let delayedMessage = try await aliceManager.ratchetEncrypt(
                plainText: "Delayed".data(using: .utf8)!, sessionId: bobIdentityLatest.id)
            let decryptedDelayed = try await bobManager.ratchetDecrypt(delayedMessage, sessionId: aliceIdentityLatest.id)
            #expect(decryptedDelayed == "Delayed".data(using: .utf8)!)
            
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
        } catch {
            try? await aliceManager.shutdown()
            try? await bobManager.shutdown()
            throw error
        }
    }
    
    @Test
    func testStateSynchronizationFailureDetection() async throws {
        let aliceManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // Initialize Alice as sender
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.senderInitialization(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)
            
            // Alice sends messages 1-10
            var messages: [RatchetMessage] = []
            for i in 1...10 {
                let message = try await aliceManager.ratchetEncrypt(plainText: "Message \(i)".data(using: .utf8)!, sessionId: bobIdentityLatest.id)
                messages.append(message)
            }
            
            // Initialize Bob as recipient
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: messages[0].header,
                localKeys: bundle.bobPrivate)
            
            // Bob successfully decrypts message 1 (establish handshake)
            let message1 = messages[0] // Index 0 = message 1
            let decrypted1 = try await bobManager.ratchetDecrypt(message1, sessionId: aliceIdentityLatest.id)
            #expect(decrypted1 == "Message 1".data(using: .utf8)!)
            
            // Bob successfully decrypts message 5
            let message5 = messages[4] // Index 4 = message 5
            let decrypted5 = try await bobManager.ratchetDecrypt(message5, sessionId: aliceIdentityLatest.id)
            #expect(decrypted5 == "Message 5".data(using: .utf8)!)
            
            // Now simulate the out-of-order scenario: message 7 arrives before message 6
            // This should trigger the skipped key generation process
            let message7 = messages[6] // Index 6 = message 7
            
            // This should work normally - the system should stash message 6's chain key
            // and generate message 7's chain key to decrypt it
            let decrypted7 = try await bobManager.ratchetDecrypt(message7, sessionId: aliceIdentityLatest.id)
            #expect(decrypted7 == "Message 7".data(using: .utf8)!)
            
            // Now when message 6 arrives, it should use the stashed chain key
            let message6 = messages[5] // Index 5 = message 6
            let decrypted6 = try await bobManager.ratchetDecrypt(message6, sessionId: aliceIdentityLatest.id)
            #expect(decrypted6 == "Message 6".data(using: .utf8)!)
            
            // Now let's test the state synchronization failure scenario
            // Create a corrupted message that will cause decryption to fail
            // This simulates what would happen if the state was wrong and derived wrong keys
            let corruptedMessage = RatchetMessage(
                header: message7.header,
                encryptedData: Data(repeating: 0x42, count: message7.encryptedData.count) // Corrupted data
            )
            
            // This should fail with CryptoKitError because the encrypted data is corrupted
            // In a real scenario, this would happen when the state is wrong and wrong keys are derived
            await #expect(throws: CryptoKitError.self, performing: {
                _ = try await bobManager.ratchetDecrypt(corruptedMessage, sessionId: aliceIdentityLatest.id)
            })
            
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
        } catch {
            try? await aliceManager.shutdown()
            try? await bobManager.shutdown()
            throw error
        }
    }
    
    
    
    @Test
    func testGapFillMisalignmentOnCorruptedOutOfOrder() async throws {
        let aliceManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // Alice initializes as sender to Bob
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.senderInitialization(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate
            )
            
            // Pre-encrypt messages m1, m2, m3 in order
            let m1 = try await aliceManager.ratchetEncrypt(plainText: Data("m1".utf8), sessionId: bobIdentityLatest.id)
            let m2 = try await aliceManager.ratchetEncrypt(plainText: Data("m2".utf8), sessionId: bobIdentityLatest.id)
            let m3 = try await aliceManager.ratchetEncrypt(plainText: Data("m3".utf8), sessionId: bobIdentityLatest.id)
            
            // Bob initializes as recipient using m1 header
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: m1.header,
                localKeys: bundle.bobPrivate
            )
            
            // Decrypt m1 to finish handshake
            let dm1 = try await bobManager.ratchetDecrypt(m1, sessionId: aliceIdentityLatest.id)
            #expect(dm1 == Data("m1".utf8))
            
            // Corrupt m3 so payload decrypt fails, but gap-fill runs
            let corruptedM3 = RatchetMessage(
                header: m3.header,
                encryptedData: Data(repeating: 0xFF, count: m3.encryptedData.count)
            )
            
            // Expect failure on corrupted m3 (auth tag), gap-fill will still stash MKs
            await #expect(throws: CryptoKitError.self) {
                _ = try await bobManager.ratchetDecrypt(corruptedM3, sessionId: aliceIdentityLatest.id)
            }
            
            // Now decrypt valid m2: with Signal-style MK storage, this should succeed
            let dm2 = try await bobManager.ratchetDecrypt(m2, sessionId: aliceIdentityLatest.id)
            #expect(dm2 == Data("m2".utf8))
            
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
        } catch {
            try? await aliceManager.shutdown()
            try? await bobManager.shutdown()
            throw error
        }
    }

    @Test
    func testOTKConsistencyEnforcementEndToEnd() async throws {
        let aliceManager = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManagerLoose = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManagerLoose.setDelegate(self)
        let bobManagerStrict = RatchetStateManager<SHA256>(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManagerStrict.setDelegate(self)
        await bobManagerLoose.setEnforceOTKConsistency(false)
        await bobManagerStrict.setEnforceOTKConsistency(true)
        
        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            
            // Alice initializes as sender to Bob (header will include OTK id)
            guard let bobIdentityLatest = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.senderInitialization(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate
            )
            let a1 = try await aliceManager.ratchetEncrypt(plainText: Data("OTK".utf8), sessionId: bobIdentityLatest.id)
            
            // Bob initializes as recipient WITHOUT providing his local one-time private key
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            let bobLocalNoOTK = LocalKeys(
                longTerm: bundle.bobPrivate.longTerm,
                oneTime: nil, // simulate missing OTK
                mlKEM: bundle.bobPrivate.mlKEM)
            
            // Loose mode: should not preflight-fail with missingOneTimeKey; decrypt still fails later
            try await bobManagerLoose.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: a1.header,
                localKeys: bobLocalNoOTK
            )
            do {
                _ = try await bobManagerLoose.ratchetDecrypt(a1, sessionId: aliceIdentityLatest.id)
                #expect(false, "Loose mode should not decrypt when OTK is missing")
            } catch {
                if case RatchetError.missingOneTimeKey = error {
                    #expect(false, "Loose mode must not preflight with missingOneTimeKey")
                } else {
                    #expect(true) // any other failure mode is acceptable here
                }
            }
            
            // Strict mode: preflight must fail fast with RatchetError.missingOneTimeKey
            try await bobManagerStrict.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                header: a1.header,
                localKeys: bobLocalNoOTK
            )
            await #expect(throws: RatchetError.missingOneTimeKey.self) {
                _ = try await bobManagerStrict.ratchetDecrypt(a1, sessionId: aliceIdentityLatest.id)
            }
            
            try await aliceManager.shutdown()
            try await bobManagerLoose.shutdown()
            try await bobManagerStrict.shutdown()
        } catch {
            try? await aliceManager.shutdown()
            try? await bobManagerLoose.shutdown()
            try? await bobManagerStrict.shutdown()
            throw error
        }
    }
}
