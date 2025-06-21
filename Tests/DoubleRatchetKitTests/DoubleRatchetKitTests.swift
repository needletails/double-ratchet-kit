//
//  DoubleRatchetKitTests.swift
//  double-ratchet-kit
//
//  Created by Cole M on 4/15/25.
//
import Foundation
import Testing
import Crypto
import NeedleTailCrypto
import SwiftKyber
import AsyncAlgorithms
@testable import DoubleRatchetKit

@Suite(.serialized)
actor RatchetStateManagerTests: SessionIdentityDelegate {
    
    struct KeyPair {
        let id: UUID
        let publicKey: Curve25519PublicKeyRepresentable
        let privateKey: Curve25519PrivateKeyRepresentable
    }
    
    private var aliceCachedKeyPairs: [KeyPair]?
    private var bobCachedKeyPairs: [KeyPair]?
    
    func aliceOneTimeKeys() throws -> [KeyPair] {
        if let cached = aliceCachedKeyPairs { return cached }
        let batch = try generateBatch()
        aliceCachedKeyPairs = batch
        return batch
    }
    func bobOneTimeKeys() throws -> [KeyPair] {
        if let cached = bobCachedKeyPairs { return cached }
        let batch = try generateBatch()
        bobCachedKeyPairs = batch
        return batch
    }
    
    private func generateBatch() throws -> [KeyPair] {
        try (0..<100).map { _ in
            let id = UUID()
            let priv = crypto.generateCurve25519PrivateKey()
            return KeyPair(
                id: id,
                publicKey: try .init(id: id, priv.publicKey.rawRepresentation),
                privateKey: try .init(id: id, priv.rawRepresentation)
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
        
        if !recipientRemoved && !senderRemoved {
            print("⚠️ Private one-time key with id \(id) not found in local DB.")
        }
        let priv = crypto.generateCurve25519PrivateKey()
        let kp = KeyPair(
            id: id,
            publicKey: try .init(id: id, priv.publicKey.rawRepresentation),
            privateKey: try .init(id: id, priv.rawRepresentation))
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
        
        if !recipientRemoved && !senderRemoved {
            print("⚠️ Public one-time key with id \(id) not found in remote DB.")
        }
        #expect(recipientKeys.count == 99)
    }
    
    
    func updateSessionIdentity(_ identity: SessionIdentity) async throws {
        if identity.id == senderIdentity.id {
            senderIdentity = identity
        } else if identity.id == recipientIdentity.id {
            recipientIdentity = identity
        }
    }
    
    
    let executor = TestableExecutor(queue: .init(label: "testable-executor"))
    
    nonisolated var unownedExecutor: UnownedSerialExecutor {
        executor.asUnownedSerialExecutor()
    }
    
    let crypto = NeedleTailCrypto()
    var publicOneTimeKey: Data = Data()
    
    func makeSenderIdentity(_
                            lltpk: Curve25519PrivateKey,
                            _ lspk: Curve25519.Signing.PrivateKey,
                            _ aliceKEM: Kyber1024.KeyAgreement.PrivateKey,
                            _ publicOTK: Curve25519.KeyAgreement.PublicKey,
                            _ databaseSymmetricKey: SymmetricKey,
                            id: UUID = UUID(),
                            deviceId: UUID = UUID()
    ) throws -> SessionIdentity {
        try SessionIdentity(
            id: id,
            props: .init(
                secretName: "alice",
                deviceId: deviceId,
                sessionContextId: 1,
                publicLongTermKey: lltpk.publicKey.rawRepresentation,
                publicSigningKey: lspk.publicKey.rawRepresentation,
                kyber1024PublicKey:  .init(aliceKEM.publicKey.rawRepresentation),
                publicOneTimeKey: .init(publicOTK.rawRepresentation),
                deviceName: "AliceDevice",
                isMasterDevice: true),
            symmetricKey: databaseSymmetricKey)
    }
    
    func makeReceiverIdentity(_
                              rltpk: Curve25519PrivateKey,
                              _ rspk: Curve25519.Signing.PrivateKey,
                              _ publicOTK: Curve25519.KeyAgreement.PublicKey,
                              _ receiverKEM: Kyber1024.KeyAgreement.PrivateKey,
                              _ databaseSymmetricKey: SymmetricKey,
                              id: UUID = UUID(),
                              deviceId: UUID = UUID()
    ) throws -> SessionIdentity {
        try SessionIdentity(
            id: id,
            props: .init(
                secretName: "bob",
                deviceId: deviceId,
                sessionContextId: 1,
                publicLongTermKey: rltpk.publicKey.rawRepresentation,
                publicSigningKey: rspk.publicKey.rawRepresentation,
                kyber1024PublicKey: .init(receiverKEM.publicKey.rawRepresentation),
                publicOneTimeKey: .init(publicOTK.rawRepresentation),
                deviceName: "BobDevice",
                isMasterDevice: true),
            symmetricKey: databaseSymmetricKey
        )
    }
    
    @Test
    func testRatchetEncryptDecryptEncrypt() async throws {
        
        let aliceManager = RatchetStateManager<SHA256>(executor: executor)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor)
        await bobManager.setDelegate(self)
        do {
            // Generate sender keys
            let aliceLtpk = crypto.generateCurve25519PrivateKey()
            let aliceOtpk = crypto.generateCurve25519PrivateKey()
            let aliceSpk = crypto.generateCurve25519SigningPrivateKey()
            let aliceKEM = try crypto.generateKyber1024PrivateSigningKey()
            let aliceDbsk = SymmetricKey(size: .bits256)
            
            // Generate receiver keys
            let bobLtpk = crypto.generateCurve25519PrivateKey()
            let bobOtpk = crypto.generateCurve25519PrivateKey()
            let bobSpk = crypto.generateCurve25519SigningPrivateKey()
            let bobKEM = try crypto.generateKyber1024PrivateSigningKey()
            let bobDBSK = SymmetricKey(size: .bits256)
            // Create Sender's Identity
            senderIdentity = try makeSenderIdentity(aliceLtpk, aliceSpk, aliceKEM, aliceOtpk.publicKey, bobDBSK)
            
            // Create Receiver's Identity
            recipientIdentity = try makeReceiverIdentity(bobLtpk, bobSpk, bobOtpk.publicKey, bobKEM, aliceDbsk)
            
            let aliceOneTimeKeyPair = try aliceOneTimeKeys().randomElement()!
            let bobOneTimeKeyPair = try bobOneTimeKeys().randomElement()!
            
            let aliceInitialOneTimePrivate = aliceOneTimeKeyPair.privateKey
            let aliceInitialOneTimePublic = aliceOneTimeKeyPair.publicKey
            let bobInitialOneTimePrivate = bobOneTimeKeyPair.privateKey
            let bobInitialOneTimePublic = bobOneTimeKeyPair.publicKey
            
            let aliceLongTermId = UUID()
            let alicePrivateLongTerm = try Curve25519PrivateKeyRepresentable(id: aliceLongTermId, aliceLtpk.rawRepresentation)
            let alicePublicLongTerm = try Curve25519PublicKeyRepresentable(id: aliceLongTermId, aliceLtpk.publicKey.rawRepresentation)
            
            let bobLongTermId = UUID()
            let bobPrivateLongTerm = try Curve25519PrivateKeyRepresentable(id: bobLongTermId, bobLtpk.rawRepresentation)
            let bobPublicLongTerm = try Curve25519PublicKeyRepresentable(id: bobLongTermId, bobLtpk.publicKey.rawRepresentation)
            
            let aliceKyberId = UUID()
            let aliceKyberPublic = try Kyber1024PublicKeyRepresentable(id: aliceKyberId, aliceKEM.publicKey.rawRepresentation)
            let aliceKyberPrivate = try Kyber1024PrivateKeyRepresentable(id: aliceKyberId, aliceKEM.encode())
            
            let bobKyberId = UUID()
            let bobKyberPublic = try Kyber1024PublicKeyRepresentable(id: bobKyberId, bobKEM.publicKey.rawRepresentation)
            let bobKyberPrivate = try Kyber1024PrivateKeyRepresentable(id: bobKyberId, bobKEM.encode())
            
            
            // Initialize Sender
            try await aliceManager.senderInitialization(
                sessionIdentity: self.recipientIdentity,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: .init(
                    longTerm: bobPublicLongTerm,
                    oneTime: bobInitialOneTimePublic,
                    kyber: bobKyberPublic),
                localKeys: .init(
                    longTerm: alicePrivateLongTerm,
                    oneTime: aliceInitialOneTimePrivate,
                    kyber: aliceKyberPrivate))
            
            let originalPlaintext = "Test message for ratchet encrypt/decrypt".data(using: .utf8)!
            
            // Sender encrypts a message
            let encrypted = try await aliceManager.ratchetEncrypt(plainText: originalPlaintext)
            
            // Receiver decrypts it
            try await bobManager.recipientInitialization(
                sessionIdentity: self.senderIdentity,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: .init(
                    longTerm: alicePublicLongTerm,
                    oneTime: encrypted.header.remotePublicOneTimeKey!,
                    kyber: encrypted.header.remoteKyber1024PublicKey),
                localKeys: .init(
                    longTerm: bobPrivateLongTerm,
                    oneTime: bobInitialOneTimePrivate,
                    kyber: bobKyberPrivate))
            
            let decryptedPlaintext = try await bobManager.ratchetDecrypt(encrypted)
            #expect(decryptedPlaintext == originalPlaintext, "Decrypted plaintext must match the original plaintext.")
            // 🚀 NOW Send a Second Message to verify ratchet advancement!
            let secondPlaintext = "Second ratcheted message!".data(using: .utf8)!
            let secondEncrypted = try await aliceManager.ratchetEncrypt(plainText: secondPlaintext)
            let secondDecryptedPlaintext = try await bobManager.ratchetDecrypt(secondEncrypted)
            
            #expect(secondDecryptedPlaintext == secondPlaintext, "Decrypted second plaintext must match.")
            
            
            try await bobManager.senderInitialization(
                sessionIdentity: self.senderIdentity,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: .init(
                    longTerm: alicePublicLongTerm,
                    oneTime: aliceInitialOneTimePublic,
                    kyber: aliceKyberPublic),
                localKeys: .init(
                    longTerm: bobPrivateLongTerm,
                    oneTime: bobInitialOneTimePrivate,
                    kyber: bobKyberPrivate))
            
            let encrypted2 = try await bobManager.ratchetEncrypt(plainText: originalPlaintext)
            
            try await aliceManager.recipientInitialization(
                sessionIdentity: self.recipientIdentity,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: .init(
                    longTerm: bobPublicLongTerm,
                    oneTime: bobInitialOneTimePublic,
                    kyber: bobKyberPublic),
                localKeys: .init(
                    longTerm: alicePrivateLongTerm,
                    oneTime: aliceInitialOneTimePrivate,
                    kyber: aliceKyberPrivate))
            
            // Decrypt message from Bob -> Alice (2nd message)
            let decryptedSecond = try await aliceManager.ratchetDecrypt(encrypted2)
            #expect(decryptedSecond == originalPlaintext, "Decrypted second plaintext must match.")
            
            // Alice sends third message to Bob
            let thirdPlaintext = "Third message from Alice".data(using: .utf8)!
            let thirdEncrypted = try await aliceManager.ratchetEncrypt(plainText: thirdPlaintext)
            
            // Bob decrypts third message
            let decryptedThird = try await bobManager.ratchetDecrypt(thirdEncrypted)
            #expect(decryptedThird == thirdPlaintext, "Decrypted third plaintext must match.")
            
            // Bob sends fourth message to Alice
            let fourthPlaintext = "Fourth message from Bob".data(using: .utf8)!
            let fourthEncrypted = try await bobManager.ratchetEncrypt(plainText: fourthPlaintext)
            
            // Alice decrypts fourth message
            let decryptedFourth = try await aliceManager.ratchetDecrypt(fourthEncrypted)
            #expect(decryptedFourth == fourthPlaintext, "Decrypted fourth plaintext must match.")
            
            // Alice sends fifth message to Bob
            let fifthPlaintext = "Fifth message from Alice".data(using: .utf8)!
            let fifthEncrypted = try await aliceManager.ratchetEncrypt(plainText: fifthPlaintext)
            
            // Bob decrypts fifth message
            let decryptedFifth = try await bobManager.ratchetDecrypt(fifthEncrypted)
            #expect(decryptedFifth == fifthPlaintext, "Decrypted fifth plaintext must match.")
            
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
        } catch {
            print(error)
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
        }
    }
    
    @Test
    func testRatchetEncryptDecrypt80Messages() async throws {
        let aliceManager = RatchetStateManager<SHA256>(executor: executor)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor)
        await bobManager.setDelegate(self)
        
        // MARK: 1. Generate key material for both parties
        let aliceLtpk = crypto.generateCurve25519PrivateKey()
        let aliceOtpk = crypto.generateCurve25519PrivateKey()
        let aliceSpk = crypto.generateCurve25519SigningPrivateKey()
        let aliceKEM = try crypto.generateKyber1024PrivateSigningKey()
        let aliceDbsk = SymmetricKey(size: .bits256)
        
        let bobLtpk = crypto.generateCurve25519PrivateKey()
        let bobOtpk = crypto.generateCurve25519PrivateKey()
        let bobSpk = crypto.generateCurve25519SigningPrivateKey()
        let bobKEM = try crypto.generateKyber1024PrivateSigningKey()
        let bobDBSK = SymmetricKey(size: .bits256)
        
        let sKyberId = UUID()
        let sKyberPublic = try Kyber1024PublicKeyRepresentable(id: sKyberId, aliceKEM.publicKey.rawRepresentation)
        let sKyberPrivate = try Kyber1024PrivateKeyRepresentable(id: sKyberId, aliceKEM.encode())
        
        let rKyberId = UUID()
        let rKyberPublic = try Kyber1024PublicKeyRepresentable(id: rKyberId, bobKEM.publicKey.rawRepresentation)
        let rKyberPrivate = try Kyber1024PrivateKeyRepresentable(id: rKyberId, bobKEM.encode())
        
        let aliceLongTermId = UUID()
        let alicePrivateLongTerm = try Curve25519PrivateKeyRepresentable(id: aliceLongTermId, aliceLtpk.rawRepresentation)
        let alicePublicLongTerm = try Curve25519PublicKeyRepresentable(id: aliceLongTermId, aliceLtpk.publicKey.rawRepresentation)
        
        let bobLongTermId = UUID()
        let bobPrivateLongTerm = try Curve25519PrivateKeyRepresentable(id: bobLongTermId, bobLtpk.rawRepresentation)
        let bobPublicLongTerm = try Curve25519PublicKeyRepresentable(id: bobLongTermId, bobLtpk.publicKey.rawRepresentation)
        
        senderIdentity = try makeSenderIdentity(
            aliceLtpk,
            aliceSpk,
            aliceKEM,
            aliceOtpk.publicKey,
            bobDBSK
        )
        recipientIdentity = try makeReceiverIdentity(
            bobLtpk,
            bobSpk,
            bobOtpk.publicKey,
            bobKEM,
            aliceDbsk
        )
        
        // MARK: 2. Select one-time keys for the initial handshake
        let aliceOneTimeKeyPair = try aliceOneTimeKeys().randomElement()!
        let bobOneTimeKeyPair = try bobOneTimeKeys().randomElement()!
        
        let aliceInitialOneTimePrivate = aliceOneTimeKeyPair.privateKey
        let aliceInitialOneTimePublic = aliceOneTimeKeyPair.publicKey
        let bobInitialOneTimePrivate = bobOneTimeKeyPair.privateKey
        let bobInitialOneTimePublic = bobOneTimeKeyPair.publicKey
        
        // MARK: 3. Alice → Bob: Initial handshake and first message
        await #expect(throws: Never.self, performing: {
            try await aliceManager.senderInitialization(
                sessionIdentity: self.recipientIdentity,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: .init(
                    longTerm: bobPublicLongTerm,
                    oneTime: bobInitialOneTimePublic,
                    kyber: rKyberPublic),
                localKeys: .init(
                    longTerm: alicePrivateLongTerm,
                    oneTime: aliceInitialOneTimePrivate,
                    kyber: sKyberPrivate)
            )
        })
        
        let firstPlaintext = "Message 1 from Alice".data(using: .utf8)!
        let firstEncrypted = try await aliceManager.ratchetEncrypt(plainText: firstPlaintext)
        
        await #expect(throws: Never.self, performing: {
            try await bobManager.recipientInitialization(
                sessionIdentity: self.senderIdentity,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: .init(
                    longTerm: alicePublicLongTerm,
                    oneTime: firstEncrypted.header.remotePublicOneTimeKey!,
                    kyber: firstEncrypted.header.remoteKyber1024PublicKey),
                localKeys: .init(
                    longTerm: bobPrivateLongTerm,
                    oneTime: bobInitialOneTimePrivate,
                    kyber: rKyberPrivate)
            )
        })
        
        let firstDecrypted = try await bobManager.ratchetDecrypt(firstEncrypted)
        #expect(firstDecrypted == firstPlaintext, "Decrypted first message must match Alice’s original.")
        
        // MARK: 4. Alice → Bob: Continue sending messages 2 through 80
        for i in 2...80 {
            let plaintext = "Message \(i) from Alice".data(using: .utf8)!
            let encrypted = try await aliceManager.ratchetEncrypt(plainText: plaintext)
            let decrypted = try await bobManager.ratchetDecrypt(encrypted)
            #expect(decrypted == plaintext, "Decrypted message \(i) must match Alice’s original.")
        }
        
        // MARK: 5. Bob → Alice: Perform the reverse-direction handshake
        await #expect(throws: Never.self, performing: {
            try await bobManager.senderInitialization(
                sessionIdentity: self.senderIdentity,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: .init(
                    longTerm: alicePublicLongTerm,
                    oneTime: aliceInitialOneTimePublic,
                    kyber: sKyberPublic),
                localKeys: .init(
                    longTerm: bobPrivateLongTerm,
                    oneTime: bobInitialOneTimePrivate,
                    kyber: rKyberPrivate)
            )
        })
        
        await #expect(throws: Never.self, performing: {
            try await aliceManager.recipientInitialization(
                sessionIdentity: self.recipientIdentity,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: .init(
                    longTerm: bobPublicLongTerm,
                    oneTime: bobInitialOneTimePublic,
                    kyber: rKyberPublic),
                localKeys: .init(
                    longTerm: alicePrivateLongTerm,
                    oneTime: aliceInitialOneTimePrivate,
                    kyber: sKyberPrivate)
            )
        })
        
        let firstBackPlaintext = "Message 1 from Bob".data(using: .utf8)!
        let firstBackEncrypted = try await bobManager.ratchetEncrypt(plainText: firstBackPlaintext)
        let firstBackDecrypted = try await aliceManager.ratchetDecrypt(firstBackEncrypted)
        #expect(firstBackDecrypted == firstBackPlaintext, "Decrypted first Bob→Alice message must match.")
        
        // MARK: 6. Bob → Alice: Continue sending messages 2 through 80
        for i in 2...80 {
            let plaintext = "Message \(i) from Bob".data(using: .utf8)!
            let encrypted = try await bobManager.ratchetEncrypt(plainText: plaintext)
            let decrypted = try await aliceManager.ratchetDecrypt(encrypted)
            #expect(decrypted == plaintext, "Decrypted Bob→Alice message \(i) must match.")
        }
        
        // MARK: 7. Clean up both managers
        await #expect(throws: Never.self, performing: {
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
        })
    }
    
    
    @Test
    func testRatchetEncryptDecryptMessagesPerUserWitNewIntializations() async throws {
        let aliceManager = RatchetStateManager<SHA256>(executor: executor)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor)
        await bobManager.setDelegate(self)
        
        let aliceLtpk = crypto.generateCurve25519PrivateKey()
        let aliceOtpk = crypto.generateCurve25519PrivateKey()
        let aliceSpk = crypto.generateCurve25519SigningPrivateKey()
        let aliceKEM = try crypto.generateKyber1024PrivateSigningKey()
        let aliceDbsk = SymmetricKey(size: .bits256)
        
        let bobLtpk = crypto.generateCurve25519PrivateKey()
        let bobOtpk = crypto.generateCurve25519PrivateKey()
        let bobSpk = crypto.generateCurve25519SigningPrivateKey()
        let bobKEM = try crypto.generateKyber1024PrivateSigningKey()
        let bobDBSK = SymmetricKey(size: .bits256)
        
        let aliceKyberId = UUID()
        let aliceKyberPublic = try Kyber1024PublicKeyRepresentable(id: aliceKyberId, aliceKEM.publicKey.rawRepresentation)
        let aliceKyberPrivate = try Kyber1024PrivateKeyRepresentable(id: aliceKyberId, aliceKEM.encode())
        
        let bobKyberId = UUID()
        let bobKyberPublic = try Kyber1024PublicKeyRepresentable(id: bobKyberId, bobKEM.publicKey.rawRepresentation)
        let bobKyberPrivate = try Kyber1024PrivateKeyRepresentable(id: bobKyberId, bobKEM.encode())
        
        senderIdentity = try makeSenderIdentity(
            aliceLtpk,
            aliceSpk,
            aliceKEM,
            aliceOtpk.publicKey,
            bobDBSK
        )
        recipientIdentity = try makeReceiverIdentity(
            bobLtpk,
            bobSpk,
            bobOtpk.publicKey,
            bobKEM,
            aliceDbsk
        )
        
        let aliceOneTimeKeyPair = try aliceOneTimeKeys().randomElement()!
        let bobOneTimeKeyPair = try bobOneTimeKeys().randomElement()!
        
        let aliceInitialOneTimePrivate = aliceOneTimeKeyPair.privateKey
        let aliceInitialOneTimePublic = aliceOneTimeKeyPair.publicKey
        let bobInitialOneTimePrivate = bobOneTimeKeyPair.privateKey
        let bobInitialOneTimePublic = bobOneTimeKeyPair.publicKey
        
        let aliceLongTermId = UUID()
        let alicePrivateLongTerm = try Curve25519PrivateKeyRepresentable(id: aliceLongTermId, aliceLtpk.rawRepresentation)
        let alicePublicLongTerm = try Curve25519PublicKeyRepresentable(id: aliceLongTermId, aliceLtpk.publicKey.rawRepresentation)
        
        let bobLongTermId = UUID()
        let bobPrivateLongTerm = try Curve25519PrivateKeyRepresentable(id: bobLongTermId, bobLtpk.rawRepresentation)
        let bobPublicLongTerm = try Curve25519PublicKeyRepresentable(id: bobLongTermId, bobLtpk.publicKey.rawRepresentation)
        
        // MARK: 4. Alice → Bob: Continue sending messages 2 through 80
        let plaintext = "Message from Alice".data(using: .utf8)!
        
        await #expect(throws: Never.self, performing: {
            try await aliceManager.senderInitialization(
                sessionIdentity: self.recipientIdentity,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: .init(
                    longTerm: bobPublicLongTerm,
                    oneTime: bobInitialOneTimePublic,
                    kyber: bobKyberPublic),
                localKeys: .init(
                    longTerm: alicePrivateLongTerm,
                    oneTime: aliceInitialOneTimePrivate,
                    kyber: aliceKyberPrivate)
            )
        })
        
        let encrypted = try! await aliceManager.ratchetEncrypt(plainText: plaintext)
        
        // Initialize recipient before decrypting the message
        await #expect(throws: Never.self, performing: {
            try await bobManager.recipientInitialization(
                sessionIdentity: self.senderIdentity,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: .init(
                    longTerm: alicePublicLongTerm,
                    oneTime: encrypted.header.remotePublicOneTimeKey!,
                    kyber: encrypted.header.remoteKyber1024PublicKey),
                localKeys: .init(
                    longTerm: bobPrivateLongTerm,
                    oneTime: bobInitialOneTimePrivate,
                    kyber: bobKyberPrivate)
            )
        })
        let decrypted = try! await bobManager.ratchetDecrypt(encrypted)
        #expect(decrypted == plaintext, "Decrypted message must match Alice’s original.")
        
        await #expect(throws: Never.self, performing: {
            try await bobManager.senderInitialization(
                sessionIdentity: self.senderIdentity,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: .init(
                    longTerm: alicePublicLongTerm,
                    oneTime: aliceInitialOneTimePublic,
                    kyber: aliceKyberPublic),
                localKeys: .init(
                    longTerm: bobPrivateLongTerm,
                    oneTime: bobInitialOneTimePrivate,
                    kyber: bobKyberPrivate)
            )
        })
        
        let encrypted2 = try! await bobManager.ratchetEncrypt(plainText: plaintext)
        
        // Initialize recipient before decrypting the message
        await #expect(throws: Never.self, performing: {
            try await aliceManager.recipientInitialization(
                sessionIdentity: self.recipientIdentity,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: .init(
                    longTerm: bobPublicLongTerm,
                    oneTime: encrypted2.header.remotePublicOneTimeKey!,
                    kyber: encrypted2.header.remoteKyber1024PublicKey),
                localKeys: .init(
                    longTerm: alicePrivateLongTerm,
                    oneTime: aliceInitialOneTimePrivate,
                    kyber: aliceKyberPrivate)
            )
        })
        let decrypted2 = try! await aliceManager.ratchetDecrypt(encrypted2)
        #expect(decrypted2 == plaintext, "Decrypted message must match Alice’s original.")
        
        await #expect(throws: Never.self, performing: {
            try await aliceManager.senderInitialization(
                sessionIdentity: self.recipientIdentity,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: .init(
                    longTerm: bobPublicLongTerm,
                    oneTime: bobInitialOneTimePublic,
                    kyber: bobKyberPublic),
                localKeys: .init(
                    longTerm: alicePrivateLongTerm,
                    oneTime: aliceInitialOneTimePrivate,
                    kyber: aliceKyberPrivate)
            )
        })
        
        let encrypted3 = try await aliceManager.ratchetEncrypt(plainText: plaintext)
        
        await #expect(throws: Never.self, performing: {
            try await aliceManager.senderInitialization(
                sessionIdentity: self.recipientIdentity,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: .init(
                    longTerm: bobPublicLongTerm,
                    oneTime: bobInitialOneTimePublic,
                    kyber: bobKyberPublic),
                localKeys: .init(
                    longTerm: alicePrivateLongTerm,
                    oneTime: aliceInitialOneTimePrivate,
                    kyber: aliceKyberPrivate)
            )
        })
        
        let encrypted4 = try await aliceManager.ratchetEncrypt(plainText: plaintext)
        
        // Initialize recipient before decrypting the message
        await #expect(throws: Never.self, performing: {
            try await bobManager.recipientInitialization(
                sessionIdentity: self.senderIdentity,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: .init(
                    longTerm: alicePublicLongTerm,
                    oneTime: encrypted3.header.remotePublicOneTimeKey!,
                    kyber: encrypted3.header.remoteKyber1024PublicKey),
                localKeys: .init(
                    longTerm: bobPrivateLongTerm,
                    oneTime: bobInitialOneTimePrivate,
                    kyber: bobKyberPrivate)
            )
        })
        
        let decrypted3 = try! await bobManager.ratchetDecrypt(encrypted3)
        #expect(decrypted3 == plaintext, "Decrypted message must match Alice’s original.")
        
        // Initialize recipient before decrypting the message
        await #expect(throws: Never.self, performing: {
            try await bobManager.recipientInitialization(
                sessionIdentity: self.senderIdentity,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: .init(
                    longTerm: alicePublicLongTerm,
                    oneTime: encrypted4.header.remotePublicOneTimeKey!,
                    kyber: encrypted4.header.remoteKyber1024PublicKey),
                localKeys: .init(
                    longTerm: bobPrivateLongTerm,
                    oneTime: bobInitialOneTimePrivate,
                    kyber: bobKyberPrivate)
            )
        })
        let decrypted4 = try await bobManager.ratchetDecrypt(encrypted4)
        #expect(decrypted4 == plaintext, "Decrypted message must match Alice’s original.")
        
        await #expect(throws: Never.self, performing: {
            try await bobManager.senderInitialization(
                sessionIdentity: self.senderIdentity,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: .init(
                    longTerm: alicePublicLongTerm,
                    oneTime: aliceInitialOneTimePublic,
                    kyber: aliceKyberPublic),
                localKeys: .init(
                    longTerm: bobPrivateLongTerm,
                    oneTime: bobInitialOneTimePrivate,
                    kyber: bobKyberPrivate)
            )
        })
        
        let encrypted5 = try await aliceManager.ratchetEncrypt(plainText: plaintext)
        
        await #expect(throws: Never.self, performing: {
            try await aliceManager.recipientInitialization(
                sessionIdentity: self.recipientIdentity,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: .init(
                    longTerm: bobPublicLongTerm,
                    oneTime: encrypted5.header.remotePublicOneTimeKey!,
                    kyber: encrypted5.header.remoteKyber1024PublicKey),
                localKeys: .init(
                    longTerm: alicePrivateLongTerm,
                    oneTime: aliceInitialOneTimePrivate,
                    kyber: aliceKyberPrivate)
            )
        })
        let decrypted5 = try await bobManager.ratchetDecrypt(encrypted5)
        #expect(decrypted5 == plaintext, "Decrypted message must match Alice’s original.")
        
        await #expect(throws: Never.self, performing: {
            try await bobManager.senderInitialization(
                sessionIdentity: self.senderIdentity,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: .init(
                    longTerm: alicePublicLongTerm,
                    oneTime: aliceInitialOneTimePublic,
                    kyber: aliceKyberPublic),
                localKeys: .init(
                    longTerm: bobPrivateLongTerm,
                    oneTime: bobInitialOneTimePrivate,
                    kyber: bobKyberPrivate)
            )
        })
        
        let encrypted6 = try await aliceManager.ratchetEncrypt(plainText: plaintext)
        
        await #expect(throws: Never.self, performing: {
            try await aliceManager.recipientInitialization(
                sessionIdentity: self.recipientIdentity,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: .init(
                    longTerm: bobPublicLongTerm,
                    oneTime: encrypted6.header.remotePublicOneTimeKey!,
                    kyber: encrypted6.header.remoteKyber1024PublicKey),
                localKeys: .init(
                    longTerm: alicePrivateLongTerm,
                    oneTime: aliceInitialOneTimePrivate,
                    kyber: aliceKyberPrivate)
            )
        })
        let decrypted6 = try await bobManager.ratchetDecrypt(encrypted6)
        #expect(decrypted6 == plaintext, "Decrypted message must match Alice’s original.")
        
        // MARK: 7. Clean up both managers
        await #expect(throws: Never.self, performing: {
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
        })
    }
    
    
    @Test
    func testRatchetEncryptDecryptOutofOrderMessagesPerUserWitNewIntializations() async throws {
        let aliceManager = RatchetStateManager<SHA256>(executor: executor)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor)
        await bobManager.setDelegate(self)
        
        let aliceLtpk = crypto.generateCurve25519PrivateKey()
        let aliceOtpk = crypto.generateCurve25519PrivateKey()
        let aliceSpk = crypto.generateCurve25519SigningPrivateKey()
        let aliceKEM = try crypto.generateKyber1024PrivateSigningKey()
        let aliceDbsk = SymmetricKey(size: .bits256)
        
        let bobLtpk = crypto.generateCurve25519PrivateKey()
        let bobOtpk = crypto.generateCurve25519PrivateKey()
        let bobSpk = crypto.generateCurve25519SigningPrivateKey()
        let bobKEM = try crypto.generateKyber1024PrivateSigningKey()
        let bobDBSK = SymmetricKey(size: .bits256)
        
        senderIdentity = try makeSenderIdentity(
            aliceLtpk,
            aliceSpk,
            aliceKEM,
            aliceOtpk.publicKey,
            bobDBSK
        )
        recipientIdentity = try makeReceiverIdentity(
            bobLtpk,
            bobSpk,
            bobOtpk.publicKey,
            bobKEM,
            aliceDbsk
        )
        
        let aliceOneTimeKeyPair = try aliceOneTimeKeys().randomElement()!
        let bobOneTimeKeyPair = try bobOneTimeKeys().randomElement()!
        
        let aliceInitialOneTimePrivate = aliceOneTimeKeyPair.privateKey
        let bobInitialOneTimePublic = bobOneTimeKeyPair.publicKey
        let bobInitialOneTimePrivate = bobOneTimeKeyPair.privateKey
        
        let aliceLongTermId = UUID()
        let alicePrivateLongTerm = try Curve25519PrivateKeyRepresentable(id: aliceLongTermId, aliceLtpk.rawRepresentation)
        let alicePublicLongTerm = try Curve25519PublicKeyRepresentable(id: aliceLongTermId, aliceLtpk.publicKey.rawRepresentation)
        
        let bobLongTermId = UUID()
        let bobPrivateLongTerm = try Curve25519PrivateKeyRepresentable(id: bobLongTermId, bobLtpk.rawRepresentation)
        let bobPublicLongTerm = try Curve25519PublicKeyRepresentable(id: bobLongTermId, bobLtpk.publicKey.rawRepresentation)
        
        let aliceKyberId = UUID()
        let aliceKyberPrivate = try Kyber1024PrivateKeyRepresentable(id: aliceKyberId, aliceKEM.encode())
        
        let bobKyberId = UUID()
        let bobKyberPublic = try Kyber1024PublicKeyRepresentable(id: bobKyberId, bobKEM.publicKey.rawRepresentation)
        let bobKyberPrivate = try Kyber1024PrivateKeyRepresentable(id: bobKyberId, bobKEM.encode())
        
        // MARK: 4. Alice → Bob: Continue sending messages 2 through 80
        let plaintext1 = "Message 1 from Alice".data(using: .utf8)!
        let plaintext2 = "Message 2 from Alice".data(using: .utf8)!
        let plaintext3 = "Message 3 from Alice".data(using: .utf8)!
        
        await #expect(throws: Never.self, performing: {
            try await aliceManager.senderInitialization(
                sessionIdentity: self.recipientIdentity,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: .init(
                    longTerm: bobPublicLongTerm,
                    oneTime: bobInitialOneTimePublic,
                    kyber: bobKyberPublic
                ),
                localKeys: .init(
                    longTerm: alicePrivateLongTerm,
                    oneTime: aliceInitialOneTimePrivate,
                    kyber: aliceKyberPrivate
                )
            )
        })
        
        let encrypted1 = try await aliceManager.ratchetEncrypt(plainText: plaintext1)
        
        await #expect(throws: Never.self, performing: {
            try await aliceManager.senderInitialization(
                sessionIdentity: self.recipientIdentity,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: .init(
                    longTerm: bobPublicLongTerm,
                    oneTime: bobInitialOneTimePublic,
                    kyber: bobKyberPublic,
                ),
                localKeys: .init(
                    longTerm: alicePrivateLongTerm,
                    oneTime: aliceInitialOneTimePrivate,
                    kyber: aliceKyberPrivate
                )
            )
        })
        
        let encrypted2 = try await aliceManager.ratchetEncrypt(plainText: plaintext2)
        
        
        await #expect(throws: Never.self, performing: {
            try await aliceManager.senderInitialization(
                sessionIdentity: self.recipientIdentity,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: .init(
                    longTerm: bobPublicLongTerm,
                    oneTime: bobInitialOneTimePublic,
                    kyber: bobKyberPublic,
                ),
                localKeys: .init(
                    longTerm: alicePrivateLongTerm,
                    oneTime: aliceInitialOneTimePrivate,
                    kyber: aliceKyberPrivate
                )
            )
        })
        
        let encrypted3 = try await aliceManager.ratchetEncrypt(plainText: plaintext3)
        
        var stashedMessages = Set<RatchetMessage>()
        
        // Initialize recipient before decrypting the message
        await #expect(throws: Never.self, performing: {
            try await bobManager.recipientInitialization(
                sessionIdentity: self.senderIdentity,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: .init(
                    longTerm: alicePublicLongTerm,
                    oneTime: encrypted3.header.remotePublicOneTimeKey!,
                    kyber: encrypted3.header.remoteKyber1024PublicKey
                ),
                localKeys: .init(
                    longTerm: bobPrivateLongTerm,
                    oneTime: bobInitialOneTimePrivate,
                    kyber: bobKyberPrivate
                )
            )
        })
        await #expect(throws: Never.self, performing: {
            do {
                let decrypted3 = try await bobManager.ratchetDecrypt(encrypted3)
                #expect(decrypted3 == plaintext3, "Decrypted message must match Alice’s original.")
            } catch let error as RatchetError {
                if error == .initialMessageNotReceived {
                    stashedMessages.insert(encrypted3)
                }
            }
        })
        
        // Initialize recipient before decrypting the message
        await #expect(throws: Never.self, performing: {
            try await bobManager.recipientInitialization(
                sessionIdentity: self.senderIdentity,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: .init(
                    longTerm: alicePublicLongTerm,
                    oneTime: encrypted1.header.remotePublicOneTimeKey!,
                    kyber: encrypted1.header.remoteKyber1024PublicKey
                ),
                localKeys: .init(
                    longTerm: bobPrivateLongTerm,
                    oneTime: bobInitialOneTimePrivate,
                    kyber: bobKyberPrivate
                )
            )
        })
        await #expect(throws: Never.self, performing: {
            do {
                let decrypted1 = try await bobManager.ratchetDecrypt(encrypted1)
                #expect(decrypted1 == plaintext1, "Decrypted message must match Alice’s original.")
            } catch let error as RatchetError {
                if error == .initialMessageNotReceived {
                    stashedMessages.insert(encrypted1)
                }
            }
        })
        
        // Initialize recipient before decrypting the message
        await #expect(throws: Never.self, performing: {
            try await bobManager.recipientInitialization(
                sessionIdentity: self.senderIdentity,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: .init(
                    longTerm: alicePublicLongTerm,
                    oneTime: encrypted2.header.remotePublicOneTimeKey!,
                    kyber: encrypted2.header.remoteKyber1024PublicKey
                ),
                localKeys: .init(
                    longTerm: bobPrivateLongTerm,
                    oneTime: bobInitialOneTimePrivate,
                    kyber: bobKyberPrivate
                )
            )
        })
        await #expect(throws: Never.self, performing: {
            do {
                let decrypted2 = try await bobManager.ratchetDecrypt(encrypted2)
                #expect(decrypted2 == plaintext2, "Decrypted message must match Alice’s original.")
            } catch let error as RatchetError {
                if error == .initialMessageNotReceived {
                    stashedMessages.insert(encrypted2)
                }
            }
        })
        
        for stashedMessage in stashedMessages {
            do {
                try await bobManager.recipientInitialization(
                    sessionIdentity: self.senderIdentity,
                    sessionSymmetricKey: bobDBSK,
                    remoteKeys: .init(
                        longTerm: alicePublicLongTerm,
                        oneTime: encrypted1.header.remotePublicOneTimeKey!,
                        kyber: encrypted1.header.remoteKyber1024PublicKey
                    ),
                    localKeys: .init(
                        longTerm: bobPrivateLongTerm,
                        oneTime: bobInitialOneTimePrivate,
                        kyber: bobKyberPrivate
                    )
                )
                
                _ = try await bobManager.ratchetDecrypt(stashedMessage)
            } catch {
                continue
            }
        }
        
        
        // MARK: 7. Clean up both managers
        await #expect(throws: Never.self, performing: {
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
        })
    }
    
    // --- NEW: PERFORMANCE TEST ---
    @Test
    func testPerformanceThousandsOfMessages() async throws {
        let aliceManager = RatchetStateManager<SHA256>(executor: executor)
        await aliceManager.setDelegate(self)
        
        // Generate sender keys
        let aliceLtpk = crypto.generateCurve25519PrivateKey()
        let aliceSpk = crypto.generateCurve25519SigningPrivateKey()
        let aliceKEM = try crypto.generateKyber1024PrivateSigningKey()
        let aliceOtpk = crypto.generateCurve25519PrivateKey()
        let aliceDbsk = SymmetricKey(size: .bits256)
        
        let bobManager = RatchetStateManager<SHA256>(executor: executor)
        await bobManager.setDelegate(self)
        
        // Generate receiver keys
        let bobLtpk = crypto.generateCurve25519PrivateKey()
        let bobSpk = crypto.generateCurve25519SigningPrivateKey()
        let bobKEM = try crypto.generateKyber1024PrivateSigningKey()
        let bobOtpk = crypto.generateCurve25519PrivateKey()
        let bobDBSK = SymmetricKey(size: .bits256)
        
        // Create Sender's Identity
        senderIdentity = try makeSenderIdentity(aliceLtpk, aliceSpk, aliceKEM, aliceOtpk.publicKey, aliceDbsk)
        recipientIdentity = try makeReceiverIdentity(bobLtpk, bobSpk, bobOtpk.publicKey, bobKEM, bobDBSK)
        
        let aliceOneTimeKeyPair = try aliceOneTimeKeys().randomElement()!
        let bobOneTimeKeyPair = try bobOneTimeKeys().randomElement()!
        
        let aliceInitialOneTimePrivate = aliceOneTimeKeyPair.privateKey
        let aliceInitialOneTimePublic = aliceOneTimeKeyPair.publicKey
        let bobInitialOneTimePrivate = bobOneTimeKeyPair.privateKey
        let bobInitialOneTimePublic = bobOneTimeKeyPair.publicKey
        
        let aliceLongTermId = UUID()
        let alicePrivateLongTerm = try Curve25519PrivateKeyRepresentable(id: aliceLongTermId, aliceLtpk.rawRepresentation)
        let alicePublicLongTerm = try Curve25519PublicKeyRepresentable(id: aliceLongTermId, aliceLtpk.publicKey.rawRepresentation)
        
        let bobLongTermId = UUID()
        let bobPrivateLongTerm = try Curve25519PrivateKeyRepresentable(id: bobLongTermId, bobLtpk.rawRepresentation)
        let bobPublicLongTerm = try Curve25519PublicKeyRepresentable(id: bobLongTermId, bobLtpk.publicKey.rawRepresentation)
        
        let aliceKyberId = UUID()
        let aliceKyberPublic = try Kyber1024PublicKeyRepresentable(id: aliceKyberId, aliceKEM.publicKey.rawRepresentation)
        let aliceKyberPrivate = try Kyber1024PrivateKeyRepresentable(id: aliceKyberId, aliceKEM.encode())
        
        let bobKyberId = UUID()
        let bobKyberPublic = try Kyber1024PublicKeyRepresentable(id: bobKyberId, bobKEM.publicKey.rawRepresentation)
        let bobKyberPrivate = try Kyber1024PrivateKeyRepresentable(id: bobKyberId, bobKEM.encode())
        
        // Initialize Sender
        try await aliceManager.senderInitialization(
            sessionIdentity: senderIdentity,
            sessionSymmetricKey: aliceDbsk,
            remoteKeys: .init(
                longTerm: bobPublicLongTerm,
                oneTime: bobInitialOneTimePublic,
                kyber: bobKyberPublic),
            localKeys: .init(
                longTerm: alicePrivateLongTerm,
                oneTime: aliceInitialOneTimePrivate,
                kyber: aliceKyberPrivate))
        
        let payload = Data(repeating: 0x41, count: 128) // 128 bytes of "A"
        let messageCount = 10_000
        
        var messages: [RatchetMessage] = []
        
        let clock = ContinuousClock()
        let duration = try await clock.measure {
            for _ in 0..<messageCount {
                let encrypted = try await aliceManager.ratchetEncrypt(plainText: payload)
                messages.append(encrypted)
            }
        }
        
        _ = try await bobManager.recipientInitialization(
            sessionIdentity: recipientIdentity,
            sessionSymmetricKey: bobDBSK,
            remoteKeys: .init(
                longTerm: alicePublicLongTerm,
                oneTime: aliceInitialOneTimePublic,
                kyber: aliceKyberPublic),
            localKeys: .init(
                longTerm: bobPrivateLongTerm,
                oneTime: bobInitialOneTimePrivate,
                kyber: bobKyberPrivate))
        
        for message in messages {
            _ = try await bobManager.ratchetDecrypt(message)
        }
        print("🔵 Encrypted/Decrypted \(messageCount) messages in \(duration.components.seconds) seconds")
        #expect(messages.count == messageCount)
        try await aliceManager.shutdown()
        try await bobManager.shutdown()
    }
    
    
    var senderIdentity: SessionIdentity!
    var recipientIdentity: SessionIdentity!
    // --- NEW: STRESS TEST OUT OF ORDER ---
    @Test
    func testStressOutOfOrderMessages() async throws {
        let aliceManager = RatchetStateManager<SHA256>(executor: executor)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor)
        await bobManager.setDelegate(self)
        
        // Generate keys
        let aliceLtpk = crypto.generateCurve25519PrivateKey()
        let aliceSpk = crypto.generateCurve25519SigningPrivateKey()
        let aliceKEM = try crypto.generateKyber1024PrivateSigningKey()
        let aliceOtpk = crypto.generateCurve25519PrivateKey()
        let aliceDbsk = SymmetricKey(size: .bits256)
        
        let bobLtpk = crypto.generateCurve25519PrivateKey()
        let bobSpk = crypto.generateCurve25519SigningPrivateKey()
        let bobKEM = try crypto.generateKyber1024PrivateSigningKey()
        let bobOtpk = crypto.generateCurve25519PrivateKey()
        let bobDBSK = SymmetricKey(size: .bits256)
        
        senderIdentity = try makeSenderIdentity(aliceLtpk, aliceSpk, aliceKEM, aliceOtpk.publicKey, aliceDbsk)
        recipientIdentity = try makeReceiverIdentity(bobLtpk, bobSpk, bobOtpk.publicKey, bobKEM, bobDBSK)
        
        let aliceOneTimeKeyPair = try aliceOneTimeKeys().randomElement()!
        let bobOneTimeKeyPair = try bobOneTimeKeys().randomElement()!
        
        let aliceInitialOneTimePrivate = aliceOneTimeKeyPair.privateKey
        let aliceInitialOneTimePublic = aliceOneTimeKeyPair.publicKey
        let bobInitialOneTimePrivate = bobOneTimeKeyPair.privateKey
        let bobInitialOneTimePublic = bobOneTimeKeyPair.publicKey
        
        let aliceLongTermId = UUID()
        let alicePrivateLongTerm = try Curve25519PrivateKeyRepresentable(id: aliceLongTermId, aliceLtpk.rawRepresentation)
        let alicePublicLongTerm = try Curve25519PublicKeyRepresentable(id: aliceLongTermId, aliceLtpk.publicKey.rawRepresentation)
        
        let bobLongTermId = UUID()
        let bobPrivateLongTerm = try Curve25519PrivateKeyRepresentable(id: bobLongTermId, bobLtpk.rawRepresentation)
        let bobPublicLongTerm = try Curve25519PublicKeyRepresentable(id: bobLongTermId, bobLtpk.publicKey.rawRepresentation)
        
        let aliceKyberId = UUID()
        let aliceKyberPublic = try Kyber1024PublicKeyRepresentable(id: aliceKyberId, aliceKEM.publicKey.rawRepresentation)
        let aliceKyberPrivate = try Kyber1024PrivateKeyRepresentable(id: aliceKyberId, aliceKEM.encode())
        
        let bobKyberId = UUID()
        let bobKyberPublic = try Kyber1024PublicKeyRepresentable(id: bobKyberId, bobKEM.publicKey.rawRepresentation)
        let bobKyberPrivate = try Kyber1024PrivateKeyRepresentable(id: bobKyberId, bobKEM.encode())
        
        try await aliceManager.senderInitialization(
            sessionIdentity: senderIdentity,
            sessionSymmetricKey: aliceDbsk,
            remoteKeys: .init(
                longTerm: bobPublicLongTerm,
                oneTime: bobInitialOneTimePublic,
                kyber: bobKyberPublic),
            localKeys: .init(
                longTerm: alicePrivateLongTerm,
                oneTime: aliceInitialOneTimePrivate,
                kyber: aliceKyberPrivate))
        
        var messages = try await (0...80).asyncMap { i in
            try await aliceManager.ratchetEncrypt(plainText: "Message \(i)".data(using: .utf8)!)
        }
        
        _ = try await bobManager.recipientInitialization(
            sessionIdentity: recipientIdentity,
            sessionSymmetricKey: bobDBSK,
            remoteKeys: .init(
                longTerm: alicePublicLongTerm,
                oneTime: aliceInitialOneTimePublic,
                kyber: aliceKyberPublic),
            localKeys: .init(
                longTerm: bobPrivateLongTerm,
                oneTime: bobInitialOneTimePrivate,
                kyber: bobKyberPrivate))
        
        let firstMessage = messages.removeFirst()
        _ = try await bobManager.ratchetDecrypt(firstMessage)
        
        // Now decrypt the rest (shuffled!)
        let rest = messages.shuffled()
        
        for await message in rest.async {
            await #expect(throws: Never.self, performing: {
                _ = try await bobManager.ratchetDecrypt(message)
            })
        }
        try await aliceManager.shutdown()
        try await bobManager.shutdown()
    }
    
    @Test
    func outOfOrderHeaders() async throws {
        let aliceManager = RatchetStateManager<SHA256>(executor: executor)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor)
        await bobManager.setDelegate(self)
        
        // Generate keys
        let aliceLtpk = crypto.generateCurve25519PrivateKey()
        let aliceSpk = crypto.generateCurve25519SigningPrivateKey()
        let aliceKEM = try crypto.generateKyber1024PrivateSigningKey()
        let aliceOtpk = crypto.generateCurve25519PrivateKey()
        let aliceDbsk = SymmetricKey(size: .bits256)
        
        let bobLtpk = crypto.generateCurve25519PrivateKey()
        let bobSpk = crypto.generateCurve25519SigningPrivateKey()
        let bobKEM = try crypto.generateKyber1024PrivateSigningKey()
        let bobOtpk = crypto.generateCurve25519PrivateKey()
        let bobDBSK = SymmetricKey(size: .bits256)
        
        senderIdentity = try makeSenderIdentity(aliceLtpk, aliceSpk, aliceKEM, aliceOtpk.publicKey, aliceDbsk)
        recipientIdentity = try makeReceiverIdentity(bobLtpk, bobSpk, bobOtpk.publicKey, bobKEM, bobDBSK)
        
        let aliceOneTimeKeyPair = try aliceOneTimeKeys().randomElement()!
        let bobOneTimeKeyPair = try bobOneTimeKeys().randomElement()!
        
        let aliceInitialOneTimePrivate = aliceOneTimeKeyPair.privateKey
        let aliceInitialOneTimePublic = aliceOneTimeKeyPair.publicKey
        let bobInitialOneTimePrivate = bobOneTimeKeyPair.privateKey
        let bobInitialOneTimePublic = bobOneTimeKeyPair.publicKey
        
        let aliceLongTermId = UUID()
        let alicePrivateLongTerm = try Curve25519PrivateKeyRepresentable(id: aliceLongTermId, aliceLtpk.rawRepresentation)
        let alicePublicLongTerm = try Curve25519PublicKeyRepresentable(id: aliceLongTermId, aliceLtpk.publicKey.rawRepresentation)
        
        let bobLongTermId = UUID()
        let bobPrivateLongTerm = try Curve25519PrivateKeyRepresentable(id: bobLongTermId, bobLtpk.rawRepresentation)
        let bobPublicLongTerm = try Curve25519PublicKeyRepresentable(id: bobLongTermId, bobLtpk.publicKey.rawRepresentation)
        
        let aliceKyberId = UUID()
        let aliceKyberPublic = try Kyber1024PublicKeyRepresentable(id: aliceKyberId, aliceKEM.publicKey.rawRepresentation)
        let aliceKyberPrivate = try Kyber1024PrivateKeyRepresentable(id: aliceKyberId, aliceKEM.encode())
        
        let bobKyberId = UUID()
        let bobKyberPublic = try Kyber1024PublicKeyRepresentable(id: bobKyberId, bobKEM.publicKey.rawRepresentation)
        let bobKyberPrivate = try Kyber1024PrivateKeyRepresentable(id: bobKyberId, bobKEM.encode())
        
        try await aliceManager.senderInitialization(
            sessionIdentity: senderIdentity,
            sessionSymmetricKey: aliceDbsk,
            remoteKeys: .init(
                longTerm: bobPublicLongTerm,
                oneTime: bobInitialOneTimePublic,
                kyber: bobKyberPublic),
            localKeys: .init(
                longTerm: alicePrivateLongTerm,
                oneTime: aliceInitialOneTimePrivate,
                kyber: aliceKyberPrivate)
        )
        
        _ = try await bobManager.recipientInitialization(
            sessionIdentity: recipientIdentity,
            sessionSymmetricKey: bobDBSK,
            remoteKeys: .init(
                longTerm: alicePublicLongTerm,
                oneTime: aliceInitialOneTimePublic,
                kyber: aliceKyberPublic),
            localKeys: .init(
                longTerm: bobPrivateLongTerm,
                oneTime: bobInitialOneTimePrivate,
                kyber: bobKyberPrivate))
        
        
        var messages = try await (1...80).asyncMap { i in
            try await aliceManager.ratchetEncrypt(plainText: "Message \(i)".data(using: .utf8)!)
        }
        
        let firstMessage = messages.removeFirst()
        _ = try await bobManager.ratchetDecrypt(firstMessage)
        
        // Shuffle messages to simulate out-of-order delivery
        var shuffledMessages = messages.shuffled()
        
        var seenMessageNumbers: Set<Int> = []
        
        while !shuffledMessages.isEmpty {
            guard let randomIndex = shuffledMessages.indices.randomElement() else { continue }
            let message = shuffledMessages[randomIndex]
            
            do {
                let decryptedHeader = try await bobManager.decryptHeader(message.header)
                
                if let number = decryptedHeader.decrypted?.messageNumber {
                    seenMessageNumbers.insert(number)
                }
                
                // Remove the message once processed
                shuffledMessages.remove(at: randomIndex)
                
            } catch {
                print("❌ Failed to decrypt message at index \(randomIndex): \(error)")
                shuffledMessages.remove(at: randomIndex)  // optionally retry later
            }
        }
        #expect(seenMessageNumbers.count == messages.count)
        for expected in 1...79 {
            #expect(seenMessageNumbers.contains(expected), "Expected to see message number \(expected)")
        }
        try await aliceManager.shutdown()
        try await bobManager.shutdown()
    }
    
    
    // --- NEW: SERIALIZATION / STATE SAVE-LOAD TEST ---
    @Test
    func testSerializationAndResumingRatchet() async throws {
        let aliceManager = RatchetStateManager<SHA256>(executor: executor)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor)
        await bobManager.setDelegate(self)
        
        // Generate sender keys
        let aliceLtpk = crypto.generateCurve25519PrivateKey()
        let aliceSpk = crypto.generateCurve25519SigningPrivateKey()
        let aliceKEM = try crypto.generateKyber1024PrivateSigningKey()
        let aliceOtpk = crypto.generateCurve25519PrivateKey()
        let aliceDbsk = SymmetricKey(size: .bits256)
        
        // Generate receiver keys
        let bobLtpk = crypto.generateCurve25519PrivateKey()
        let bobSpk = crypto.generateCurve25519SigningPrivateKey()
        let bobKEM = try crypto.generateKyber1024PrivateSigningKey()
        let bobOtpk = crypto.generateCurve25519PrivateKey()
        let bobDBSK = SymmetricKey(size: .bits256)
        // Create Sender's Identity
        senderIdentity = try makeSenderIdentity(aliceLtpk, aliceSpk, aliceKEM, aliceOtpk.publicKey, aliceDbsk)
        
        // Create Receiver's Identity
        recipientIdentity = try makeReceiverIdentity(bobLtpk, bobSpk, bobOtpk.publicKey, bobKEM, bobDBSK)
        
        let aliceOneTimeKeyPair = try aliceOneTimeKeys().randomElement()!
        let bobOneTimeKeyPair = try bobOneTimeKeys().randomElement()!
        
        let aliceInitialOneTimePrivate = aliceOneTimeKeyPair.privateKey
        let aliceInitialOneTimePublic = aliceOneTimeKeyPair.publicKey
        let bobInitialOneTimePrivate = bobOneTimeKeyPair.privateKey
        let bobInitialOneTimePublic = bobOneTimeKeyPair.publicKey
        
        let aliceLongTermId = UUID()
        let alicePrivateLongTerm = try Curve25519PrivateKeyRepresentable(id: aliceLongTermId, aliceLtpk.rawRepresentation)
        let alicePublicLongTerm = try Curve25519PublicKeyRepresentable(id: aliceLongTermId, aliceLtpk.publicKey.rawRepresentation)
        
        let bobLongTermId = UUID()
        let bobPrivateLongTerm = try Curve25519PrivateKeyRepresentable(id: bobLongTermId, bobLtpk.rawRepresentation)
        let bobPublicLongTerm = try Curve25519PublicKeyRepresentable(id: bobLongTermId, bobLtpk.publicKey.rawRepresentation)
        
        let aliceKyberId = UUID()
        let aliceKyberPublic = try Kyber1024PublicKeyRepresentable(id: aliceKyberId, aliceKEM.publicKey.rawRepresentation)
        let aliceKyberPrivate = try Kyber1024PrivateKeyRepresentable(id: aliceKyberId, aliceKEM.encode())
        
        let bobKyberId = UUID()
        let bobKyberPublic = try Kyber1024PublicKeyRepresentable(id: bobKyberId, bobKEM.publicKey.rawRepresentation)
        let bobKyberPrivate = try Kyber1024PrivateKeyRepresentable(id: bobKyberId, bobKEM.encode())
        
        // Initialize Sender
        try await aliceManager.senderInitialization(
            sessionIdentity: senderIdentity,
            sessionSymmetricKey: aliceDbsk,
            remoteKeys: .init(
                longTerm: bobPublicLongTerm,
                oneTime: bobInitialOneTimePublic,
                kyber: bobKyberPublic),
            localKeys: .init(
                longTerm: alicePrivateLongTerm,
                oneTime: aliceInitialOneTimePrivate,
                kyber: aliceKyberPrivate)
        )
        
        let plaintext = "Persist me!".data(using: .utf8)!
        let encrypted = try await aliceManager.ratchetEncrypt(plainText: plaintext)
        
        try await Task.sleep(until: .now + .seconds(10))
        
        _ = try await bobManager.recipientInitialization(
            sessionIdentity: recipientIdentity,
            sessionSymmetricKey: bobDBSK,
            remoteKeys: .init(
                longTerm: alicePublicLongTerm,
                oneTime: aliceInitialOneTimePublic,
                kyber: aliceKyberPublic),
            localKeys: .init(
                longTerm: bobPrivateLongTerm,
                oneTime: bobInitialOneTimePrivate,
                kyber: bobKyberPrivate))
        let decrypted = try await bobManager.ratchetDecrypt(encrypted)
        #expect(decrypted == plaintext)
        try await aliceManager.shutdown()
        try await bobManager.shutdown()
    }
    
    @Test
    func testRotatedKeys() async throws {
        
        let aliceManager = RatchetStateManager<SHA256>(executor: executor)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor)
        await bobManager.setDelegate(self)
        
        let aliceId = UUID()
        let aliceDid = UUID()
        
        let bobId = UUID()
        let bobDid = UUID()
        
        do {
            // Generate sender keys
            let aliceLtpk = crypto.generateCurve25519PrivateKey()
            let aliceOtpk = crypto.generateCurve25519PrivateKey()
            let aliceSpk = crypto.generateCurve25519SigningPrivateKey()
            let aliceKEM = try crypto.generateKyber1024PrivateSigningKey()
            let aliceDbsk = SymmetricKey(size: .bits256)
            
            // Generate receiver keys
            let bobLtpk = crypto.generateCurve25519PrivateKey()
            let bobOtpk = crypto.generateCurve25519PrivateKey()
            let bobSpk = crypto.generateCurve25519SigningPrivateKey()
            let bobKEM = try crypto.generateKyber1024PrivateSigningKey()
            let bobDBSK = SymmetricKey(size: .bits256)
            // Create Sender's Identity
            senderIdentity = try makeSenderIdentity(aliceLtpk, aliceSpk, aliceKEM, aliceOtpk.publicKey, bobDBSK, id: aliceId, deviceId: aliceDid)
            
            // Create Receiver's Identity
            recipientIdentity = try makeReceiverIdentity(bobLtpk, bobSpk, bobOtpk.publicKey, bobKEM, aliceDbsk, id: bobId, deviceId: bobDid)
            
            let aliceOneTimeKeyPair = try aliceOneTimeKeys().randomElement()!
            let bobOneTimeKeyPair = try bobOneTimeKeys().randomElement()!
            
            let aliceInitialOneTimePrivate = aliceOneTimeKeyPair.privateKey
            let aliceInitialOneTimePublic = aliceOneTimeKeyPair.publicKey
            let bobInitialOneTimePrivate = bobOneTimeKeyPair.privateKey
            let bobInitialOneTimePublic = bobOneTimeKeyPair.publicKey
            
            let aliceLongTermId = UUID()
            let alicePrivateLongTerm = try Curve25519PrivateKeyRepresentable(id: aliceLongTermId, aliceLtpk.rawRepresentation)
            let alicePublicLongTerm = try Curve25519PublicKeyRepresentable(id: aliceLongTermId, aliceLtpk.publicKey.rawRepresentation)
            
            let bobLongTermId = UUID()
            let bobPrivateLongTerm = try Curve25519PrivateKeyRepresentable(id: bobLongTermId, bobLtpk.rawRepresentation)
            let bobPublicLongTerm = try Curve25519PublicKeyRepresentable(id: bobLongTermId, bobLtpk.publicKey.rawRepresentation)
            
            let aliceKyberId = UUID()
            let aliceKyberPublic = try Kyber1024PublicKeyRepresentable(id: aliceKyberId, aliceKEM.publicKey.rawRepresentation)
            let aliceKyberPrivate = try Kyber1024PrivateKeyRepresentable(id: aliceKyberId, aliceKEM.encode())
            
            let bobKyberId = UUID()
            let bobKyberPublic = try Kyber1024PublicKeyRepresentable(id: bobKyberId, bobKEM.publicKey.rawRepresentation)
            let bobKyberPrivate = try Kyber1024PrivateKeyRepresentable(id: bobKyberId, bobKEM.encode())
            
            // Initialize Sender
            try! await aliceManager.senderInitialization(
                sessionIdentity: recipientIdentity,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: .init(
                    longTerm: bobPublicLongTerm,
                    oneTime: bobInitialOneTimePublic,
                    kyber: bobKyberPublic),
                localKeys: .init(
                    longTerm: alicePrivateLongTerm,
                    oneTime: aliceInitialOneTimePrivate,
                    kyber: aliceKyberPrivate))
            
            let originalPlaintext = "Test message for ratchet encrypt/decrypt".data(using: .utf8)!
            
            // Sender encrypts a message
            let encrypted = try! await aliceManager.ratchetEncrypt(plainText: originalPlaintext)
            
            // Receiver decrypts it
            _ = try! await bobManager.recipientInitialization(
                sessionIdentity: senderIdentity,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: .init(
                    longTerm: alicePublicLongTerm,
                    oneTime: aliceInitialOneTimePublic,
                    kyber: aliceKyberPublic),
                localKeys: .init(
                    longTerm: bobPrivateLongTerm,
                    oneTime: bobInitialOneTimePrivate,
                    kyber: bobKyberPrivate))
            
            let decryptedPlaintext = try! await bobManager.ratchetDecrypt(encrypted)
            #expect(decryptedPlaintext == originalPlaintext, "Decrypted plaintext must match the original plaintext.")
            // 🚀 NOW Send a Second Message to verify ratchet advancement!
            let secondPlaintext = "Second ratcheted message!".data(using: .utf8)!
            let secondEncrypted = try await aliceManager.ratchetEncrypt(plainText: secondPlaintext)
            let secondDecryptedPlaintext = try await bobManager.ratchetDecrypt(secondEncrypted)
            
            #expect(secondDecryptedPlaintext == secondPlaintext, "Decrypted second plaintext must match.")
            
            try! await bobManager.senderInitialization(
                sessionIdentity: senderIdentity,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: .init(
                    longTerm: alicePublicLongTerm,
                    oneTime: aliceInitialOneTimePublic,
                    kyber: aliceKyberPublic),
                localKeys: .init(
                    longTerm: bobPrivateLongTerm,
                    oneTime: bobInitialOneTimePrivate,
                    kyber: bobKyberPrivate))
            
            let encrypted2 = try! await bobManager.ratchetEncrypt(plainText: originalPlaintext)
            
            _ = try! await aliceManager.recipientInitialization(
                sessionIdentity: recipientIdentity,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: .init(
                    longTerm: bobPublicLongTerm,
                    oneTime: bobInitialOneTimePublic,
                    kyber: bobKyberPublic),
                localKeys: .init(
                    longTerm: alicePrivateLongTerm,
                    oneTime: aliceInitialOneTimePrivate,
                    kyber: aliceKyberPrivate))
            
            // Decrypt message from Bob -> Alice (2nd message)
            let decryptedSecond = try! await aliceManager.ratchetDecrypt(encrypted2)
            #expect(decryptedSecond == originalPlaintext, "Decrypted second plaintext must match.")
            
            // Alice sends third message to Bob
            let thirdPlaintext = "Third message from Alice".data(using: .utf8)!
            let thirdEncrypted = try! await aliceManager.ratchetEncrypt(plainText: thirdPlaintext)
            
            // Bob decrypts third message
            let decryptedThird = try! await bobManager.ratchetDecrypt(thirdEncrypted)
            #expect(decryptedThird == thirdPlaintext, "Decrypted third plaintext must match.")
            
            // Bob sends fourth message to Alice
            let fourthPlaintext = "Fourth message from Bob".data(using: .utf8)!
            let fourthEncrypted = try! await bobManager.ratchetEncrypt(plainText: fourthPlaintext)
            
            // Alice decrypts fourth message
            let decryptedFourth = try! await aliceManager.ratchetDecrypt(fourthEncrypted)
            #expect(decryptedFourth == fourthPlaintext, "Decrypted fourth plaintext must match.")
            
            // Alice sends fifth message to Bob
            let fifthPlaintext = "Fifth message from Alice".data(using: .utf8)!
            let fifthEncrypted = try! await aliceManager.ratchetEncrypt(plainText: fifthPlaintext)
            
            // Bob decrypts fifth message
            let decryptedFifth = try! await bobManager.ratchetDecrypt(fifthEncrypted)
            #expect(decryptedFifth == fifthPlaintext, "Decrypted fifth plaintext must match.")
            
            
            //Rotate Long Term Key
            let rotatedaliceLtpk = crypto.generateCurve25519PrivateKey()
            let rotatedRecipientltpk = crypto.generateCurve25519PrivateKey()
            
            let aliceRotatedLongTermId = UUID()
            let aliceRotatedPrivateLongTerm = try Curve25519PrivateKeyRepresentable(id: aliceRotatedLongTermId, rotatedaliceLtpk.rawRepresentation)
            let aliceRotatedPublicLongTerm = try Curve25519PublicKeyRepresentable(id: aliceRotatedLongTermId, rotatedaliceLtpk.publicKey.rawRepresentation)
            
            let bobRotatedLongTermId = UUID()
            let bobRotatedPrivateLongTerm = try Curve25519PrivateKeyRepresentable(id: bobRotatedLongTermId, rotatedRecipientltpk.rawRepresentation)
            let bobRotatedPublicLongTerm = try Curve25519PublicKeyRepresentable(id: bobRotatedLongTermId, rotatedRecipientltpk.publicKey.rawRepresentation)
            
            try! await aliceManager.senderInitialization(
                sessionIdentity: recipientIdentity,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: .init(
                    longTerm: bobPublicLongTerm,
                    oneTime: bobInitialOneTimePublic,
                    kyber: bobKyberPublic),
                localKeys: .init(
                    longTerm: aliceRotatedPrivateLongTerm,
                    oneTime: aliceInitialOneTimePrivate,
                    kyber: aliceKyberPrivate))
            
            let rotatedPlaintext = "Test message for ratchet encrypt/decrypt".data(using: .utf8)!
            
            // Sender encrypts a message
            let encryptedRotated = try! await aliceManager.ratchetEncrypt(plainText: rotatedPlaintext)
            
            try! await bobManager.recipientInitialization(
                sessionIdentity: senderIdentity,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: .init(
                    longTerm: aliceRotatedPublicLongTerm,
                    oneTime: encryptedRotated.header.remotePublicOneTimeKey!,
                    kyber: encryptedRotated.header.remoteKyber1024PublicKey),
                localKeys: .init(
                    longTerm: bobPrivateLongTerm,
                    oneTime: bobInitialOneTimePrivate,
                    kyber: bobKyberPrivate))
            
            let decryptedPlaintextRotated = try! await bobManager.ratchetDecrypt(encryptedRotated)
            #expect(decryptedPlaintextRotated == rotatedPlaintext, "Decrypted plaintext must match the original plaintext.")
            
            // Update Sender's Identity
            try! await bobManager.senderInitialization(
                sessionIdentity: senderIdentity,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: .init(
                    longTerm: aliceRotatedPublicLongTerm,
                    oneTime: aliceInitialOneTimePublic,
                    kyber: aliceKyberPublic),
                localKeys: .init(
                    longTerm: bobRotatedPrivateLongTerm,
                    oneTime: bobInitialOneTimePrivate,
                    kyber: bobKyberPrivate))
            
            
            let rotatedPlaintext2 = "Test message for ratchet encrypt/decrypt".data(using: .utf8)!
            let encryptedRotated2 = try! await bobManager.ratchetEncrypt(plainText: rotatedPlaintext2)
            
            try! await aliceManager.recipientInitialization(
                sessionIdentity: recipientIdentity,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: .init(
                    longTerm: bobRotatedPublicLongTerm,
                    oneTime: encryptedRotated2.header.remotePublicOneTimeKey!,
                    kyber: encryptedRotated2.header.remoteKyber1024PublicKey),
                localKeys: .init(
                    longTerm: alicePrivateLongTerm,
                    oneTime: aliceInitialOneTimePrivate,
                    kyber: aliceKyberPrivate))
            
            // Decrypt message from Bob -> Alice (2nd message)
            let decryptedRotatedSecond = try! await aliceManager.ratchetDecrypt(encryptedRotated2)
            #expect(decryptedRotatedSecond == rotatedPlaintext2, "Decrypted second plaintext must match.")
            
            let messages = try await (0...80).asyncMap { i in
                try! await aliceManager.senderInitialization(
                    sessionIdentity: recipientIdentity,
                    sessionSymmetricKey: aliceDbsk,
                    remoteKeys: .init(
                        longTerm: bobRotatedPublicLongTerm,
                        oneTime: bobInitialOneTimePublic,
                        kyber: bobKyberPublic),
                    localKeys: .init(
                        longTerm: aliceRotatedPrivateLongTerm,
                        oneTime: aliceInitialOneTimePrivate,
                        kyber: aliceKyberPrivate))
                return try! await aliceManager.ratchetEncrypt(plainText: "Message \(i)".data(using: .utf8)!)
            }
            
            for message in messages {
                _ = try! await bobManager.recipientInitialization(
                    sessionIdentity: senderIdentity,
                    sessionSymmetricKey: bobDBSK,
                    remoteKeys: .init(
                        longTerm: aliceRotatedPublicLongTerm,
                        oneTime: aliceInitialOneTimePublic,
                        kyber: aliceKyberPublic),
                    localKeys: .init(
                        longTerm: bobRotatedPrivateLongTerm,
                        oneTime: bobInitialOneTimePrivate,
                        kyber: bobKyberPrivate))
                _ = try await bobManager.ratchetDecrypt(message)
            }
            
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
        } catch {
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
        }
    }
    
    func updateOneTimeKey(remove id: UUID) async { }
    func fetchPrivateOneTimeKey(_ id: UUID?) async throws -> DoubleRatchetKit.Curve25519PrivateKeyRepresentable? { nil }
    func updateOneTimeKey() async { }
    func removePrivateOneTimeKey(_ id: UUID) async { }
    func removePublicOneTimeKey(_ id: UUID) async { }
}


final class TestableExecutor: SerialExecutor {
    
    let queue: DispatchQueue
    
    init(queue: DispatchQueue) {
        self.queue = queue
    }
    
    func checkIsolated() {
        dispatchPrecondition(condition: .onQueue(queue))
    }
    
    func enqueue(_ job: consuming ExecutorJob) {
        let job = UnownedJob(job)
        self.queue.async { [weak self] in
            guard let self else { return }
            job.runSynchronously(on: self.asUnownedSerialExecutor())
        }
    }
    
    func asUnownedSerialExecutor() -> UnownedSerialExecutor {
        UnownedSerialExecutor(complexEquality: self)
    }
}

extension Sequence {
    public func asyncMap<T>(
        transform: @Sendable (Element) async throws -> T
    ) async throws -> [T] {
        var results = [T]()
        for element in self {
            let result = try await transform(element)
            results.append(result)
        }
        return results
    }
}
