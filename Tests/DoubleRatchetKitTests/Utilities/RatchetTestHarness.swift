//
//  RatchetTestHarness.swift
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

@Suite(.serialized)
actor MessageRatchetTests: SessionIdentityDelegate {

    
    let testableRatchetConfiguration = RatchetConfiguration(
        messageKeyData: Data([0x00]), // Data for message key derivation.
        chainKeyData: Data([0x01]), // Data for chain key derivation.
        rootKeyData: Data([0x02, 0x03]), // Data for root key derivation.
        associatedData: "DoubleRatchetKit".data(using: .ascii)!, // Payload AEAD associated data.
        maxSkippedMessageKeys: 100)
    
    struct KeyPair {
        let id: UUID
        let publicKey: X25519PublicKey
        let privateKey: X25519PrivateKey
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
    
    func createKeys() async throws -> (
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
        let alicePrivateLongTerm = try X25519PrivateKey(
            id: aliceLongTermId, aliceLtpk.rawRepresentation)
        let alicePublicLongTerm = try X25519PublicKey(
            id: aliceLongTermId, aliceLtpk.publicKey.rawRepresentation)
        
        let bobLongTermId = UUID()
        let bobPrivateLongTerm = try X25519PrivateKey(id: bobLongTermId, bobLtpk.rawRepresentation)
        let bobPublicLongTerm = try X25519PublicKey(
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
    
    

    

    

    

    
    // --- NEW: PERFORMANCE TEST ---

    

    

    
    // --- NEW: SERIALIZATION / STATE SAVE-LOAD TEST ---

    

    
    func updateOneTimeKey(remove _: UUID) async {}
    func fetchOneTimePrivateKey(_: UUID?) async throws -> DoubleRatchetKit.X25519PrivateKey? { nil }
    func updateOneTimeKey() async {}
    func removePrivateOneTimeKey(_: UUID) async {}
    func removePublicOneTimeKey(_: UUID) async {}
    
    // MARK: - Additional Comprehensive Tests
    

    

    

    

    

    

    

    

    

    
    
    

    
    

    

    

    

    // MARK: - Skipped Message Key Bounds

    func makeCappedConfiguration(maxSkippedMessageKeys: Int) -> RatchetConfiguration {
        RatchetConfiguration(
            messageKeyData: Data([0x00]),
            chainKeyData: Data([0x01]),
            rootKeyData: Data([0x02, 0x03]),
            associatedData: "DoubleRatchetKit".data(using: .ascii)!,
            maxSkippedMessageKeys: maxSkippedMessageKeys)
    }
}
