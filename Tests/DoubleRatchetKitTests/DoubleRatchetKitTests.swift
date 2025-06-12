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
 
    func updateOneTimeKey(remove id: UUID) async {
        
    }
    
    func fetchPrivateOneTimeKey(_ id: UUID?) async throws -> DoubleRatchetKit.Curve25519PrivateKeyRepresentable? {
        try recipientOneTimeKeys().first(where: { $0.id == id } )!.privateKey
    }
    
    func updateOneTimeKey() async {
        
    }
    
    func removePrivateOneTimeKey(_ id: UUID) async {
        
    }
    
    func removePublicOneTimeKey(_ id: UUID) async {
        
    }
    
    
    struct KeyPair {
        let id: UUID
        let publicKey: Curve25519PublicKeyRepresentable
        let privateKey: Curve25519PrivateKeyRepresentable
    }
    
    private var senderCachedKeyPairs: [KeyPair]?
    private var recipientCachedKeyPairs: [KeyPair]?

    func senderOneTimeKeys() throws -> [KeyPair] {
            if let cached = senderCachedKeyPairs { return cached }
            let batch = try generateBatch()
            senderCachedKeyPairs = batch
            return batch
        }
    func recipientOneTimeKeys() throws -> [KeyPair] {
            if let cached = senderCachedKeyPairs { return cached }
            let batch = try generateBatch()
            senderCachedKeyPairs = batch
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

        var recipientKeys = try recipientOneTimeKeys()
        let recipientCountBefore = recipientKeys.count
        recipientKeys.removeAll(where: { $0.id == id })
        let recipientRemoved = recipientCountBefore != recipientKeys.count

        var senderKeys = try senderOneTimeKeys()
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

        var recipientKeys = try recipientOneTimeKeys()
        let recipientCountBefore = recipientKeys.count
        recipientKeys.removeAll(where: { $0.id == id })
        let recipientRemoved = recipientCountBefore != recipientKeys.count

        var senderKeys = try senderOneTimeKeys()
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
                                _ senderKEM: Kyber1024.KeyAgreement.PrivateKey,
                                _ publicOTK: Curve25519.KeyAgreement.PublicKey,
                                _ databaseSymmetricKey: SymmetricKey
                               ) throws -> SessionIdentity {
        try SessionIdentity(
            id: UUID(),
            props: .init(
                    secretName: "sender",
                    deviceId: UUID(),
                    sessionContextId: 1,
                    publicLongTermKey: lltpk.publicKey.rawRepresentation,
                    publicSigningKey: lspk.publicKey.rawRepresentation,
                    kyber1024PublicKey:  .init(senderKEM.publicKey.rawRepresentation),
                    publicOneTimeKey: .init(publicOTK.rawRepresentation),
                    deviceName: "SenderDevice",
                    isMasterDevice: true),
            symmetricKey: databaseSymmetricKey)
    }

    func makeReceiverIdentity(_
                              rltpk: Curve25519PrivateKey,
                              _ rspk: Curve25519.Signing.PrivateKey,
                              _ publicOTK: Curve25519.KeyAgreement.PublicKey,
                              _ receiverKEM: Kyber1024.KeyAgreement.PrivateKey,
                              _ databaseSymmetricKey: SymmetricKey
    ) throws -> SessionIdentity {
        try SessionIdentity(
            id: UUID(),
            props: .init(
                secretName: "receiver",
                deviceId: UUID(),
                sessionContextId: 1,
                publicLongTermKey: rltpk.publicKey.rawRepresentation,
                publicSigningKey: rspk.publicKey.rawRepresentation,
                kyber1024PublicKey: .init(receiverKEM.publicKey.rawRepresentation),
                publicOneTimeKey: .init(publicOTK.rawRepresentation),
                deviceName: "ReceiverDevice",
                isMasterDevice: true),
            symmetricKey: databaseSymmetricKey
        )
    }
    
    @Test
    func testRatchetEncryptDecryptEncrypt() async throws {
       
            let sendingManager = RatchetStateManager<SHA256>(executor: executor)
            await sendingManager.setDelegate(self)
            let receivingManager = RatchetStateManager<SHA256>(executor: executor)
            await receivingManager.setDelegate(self)
        do {
            // Generate sender keys
            let senderltpk = crypto.generateCurve25519PrivateKey()
            let senderotpk = crypto.generateCurve25519PrivateKey()
            let senderspk = crypto.generateCurve25519SigningPrivateKey()
            let senderKEM = try crypto.generateKyber1024PrivateSigningKey()
            let senderDBSK = SymmetricKey(size: .bits256)
            
            // Generate receiver keys
            let recipientltpk = crypto.generateCurve25519PrivateKey()
            let recipientotpk = crypto.generateCurve25519PrivateKey()
            let recipientspk = crypto.generateCurve25519SigningPrivateKey()
            let recipientKEM = try crypto.generateKyber1024PrivateSigningKey()
            let recipientDBSK = SymmetricKey(size: .bits256)
            // Create Sender's Identity
            senderIdentity = try! makeSenderIdentity(senderltpk, senderspk, senderKEM, senderotpk.publicKey, recipientDBSK)

            // Create Receiver's Identity
            recipientIdentity = try! makeReceiverIdentity(recipientltpk, recipientspk, recipientotpk.publicKey, recipientKEM, senderDBSK)
            
            let localPrivateOneTimeKey = try senderOneTimeKeys().randomElement()
            let remotePublicOneTimeKey = try recipientOneTimeKeys().randomElement()!.publicKey
            
            // Initialize Sender
            try! await sendingManager.senderInitialization(
                sessionIdentity: recipientIdentity,
                sessionSymmetricKey: senderDBSK,
                remoteKeys: .init(longTerm: .init(recipientltpk.publicKey.rawRepresentation), oneTime: remotePublicOneTimeKey, kyber: .init(recipientKEM.publicKey.rawRepresentation)),
                localKeys: .init(longTerm: .init(senderltpk.rawRepresentation), oneTime: localPrivateOneTimeKey!.privateKey, kyber: .init(senderKEM.encode())))
            
            let originalPlaintext = "Test message for ratchet encrypt/decrypt".data(using: .utf8)!
            
            // Sender encrypts a message
            let encrypted = try! await sendingManager.ratchetEncrypt(plainText: originalPlaintext)
            let localPrivateOneTimeKey1 = try! await fetchPrivateOneTimeKey(encrypted.header.curveOneTimeKeyId)
            
            // Receiver decrypts it
            try! await receivingManager.recipientInitialization(
                sessionIdentity: senderIdentity,
                sessionSymmetricKey: recipientDBSK,
                remoteKeys: .init(longTerm: .init(senderltpk.publicKey.rawRepresentation), oneTime: encrypted.header.remotePublicOneTimeKey!, kyber: .init(senderKEM.publicKey.rawRepresentation)),
                localKeys: .init(longTerm: .init(recipientltpk.rawRepresentation), oneTime: localPrivateOneTimeKey1, kyber: .init(recipientKEM.encode())))
            
            let decryptedPlaintext = try! await receivingManager.ratchetDecrypt(encrypted)
            #expect(decryptedPlaintext == originalPlaintext, "Decrypted plaintext must match the original plaintext.")
            // 🚀 NOW Send a Second Message to verify ratchet advancement!
            let secondPlaintext = "Second ratcheted message!".data(using: .utf8)!
            let secondEncrypted = try! await sendingManager.ratchetEncrypt(plainText: secondPlaintext)
            let secondDecryptedPlaintext = try! await receivingManager.ratchetDecrypt(secondEncrypted)
            
            #expect(secondDecryptedPlaintext == secondPlaintext, "Decrypted second plaintext must match.")
            
            
            try! await receivingManager.senderInitialization(
                sessionIdentity: senderIdentity,
                sessionSymmetricKey: recipientDBSK,
                remoteKeys: .init(longTerm: .init(senderltpk.publicKey.rawRepresentation), oneTime: localPrivateOneTimeKey!.publicKey, kyber: .init(senderKEM.publicKey.rawRepresentation)),
                localKeys: .init(longTerm: .init(recipientltpk.rawRepresentation), oneTime: localPrivateOneTimeKey1, kyber: .init(recipientKEM.encode())))

            let encrypted2 = try! await receivingManager.ratchetEncrypt(plainText: originalPlaintext)
            
            try! await sendingManager.recipientInitialization(
                sessionIdentity: recipientIdentity,
                sessionSymmetricKey: senderDBSK,
                remoteKeys: .init(longTerm: .init(recipientltpk.publicKey.rawRepresentation), oneTime: remotePublicOneTimeKey, kyber: .init(recipientKEM.publicKey.rawRepresentation)),
                localKeys: .init(longTerm: .init(senderltpk.rawRepresentation), oneTime: localPrivateOneTimeKey!.privateKey, kyber: .init(senderKEM.encode())))
            
            // Decrypt message from Bob -> Alice (2nd message)
            let decryptedSecond = try! await sendingManager.ratchetDecrypt(encrypted2)
            #expect(decryptedSecond == originalPlaintext, "Decrypted second plaintext must match.")

            // Alice sends third message to Bob
            let thirdPlaintext = "Third message from Alice".data(using: .utf8)!
            let thirdEncrypted = try! await sendingManager.ratchetEncrypt(plainText: thirdPlaintext)

            // Bob decrypts third message
            let decryptedThird = try! await receivingManager.ratchetDecrypt(thirdEncrypted)
            #expect(decryptedThird == thirdPlaintext, "Decrypted third plaintext must match.")

            // Bob sends fourth message to Alice
            let fourthPlaintext = "Fourth message from Bob".data(using: .utf8)!
            let fourthEncrypted = try! await receivingManager.ratchetEncrypt(plainText: fourthPlaintext)

            // Alice decrypts fourth message
            let decryptedFourth = try! await sendingManager.ratchetDecrypt(fourthEncrypted)
            #expect(decryptedFourth == fourthPlaintext, "Decrypted fourth plaintext must match.")

            // Alice sends fifth message to Bob
            let fifthPlaintext = "Fifth message from Alice".data(using: .utf8)!
            let fifthEncrypted = try! await sendingManager.ratchetEncrypt(plainText: fifthPlaintext)

            // Bob decrypts fifth message
            let decryptedFifth = try! await receivingManager.ratchetDecrypt(fifthEncrypted)
            #expect(decryptedFifth == fifthPlaintext, "Decrypted fifth plaintext must match.")

            try await sendingManager.shutdown()
            try await receivingManager.shutdown()
        } catch {
            try await sendingManager.shutdown()
            try await receivingManager.shutdown()
        }
    }
    
    @Test
    func testRatchetEncryptDecrypt80Messages() async throws {
        let sendingManager = RatchetStateManager<SHA256>(executor: executor)
        await sendingManager.setDelegate(self)
        let receivingManager = RatchetStateManager<SHA256>(executor: executor)
        await receivingManager.setDelegate(self)

        // MARK: 1. Generate key material for both parties
        let senderLtpk = crypto.generateCurve25519PrivateKey()
        let senderOtpk = crypto.generateCurve25519PrivateKey()
        let senderSpk = crypto.generateCurve25519SigningPrivateKey()
        let senderKEM = try crypto.generateKyber1024PrivateSigningKey()
        let senderDBSK = SymmetricKey(size: .bits256)

        let recipientLtpk = crypto.generateCurve25519PrivateKey()
        let recipientOtpk = crypto.generateCurve25519PrivateKey()
        let recipientSpk = crypto.generateCurve25519SigningPrivateKey()
        let recipientKEM = try crypto.generateKyber1024PrivateSigningKey()
        let recipientDBSK = SymmetricKey(size: .bits256)

        senderIdentity = try makeSenderIdentity(
            senderLtpk,
            senderSpk,
            senderKEM,
            senderOtpk.publicKey,
            recipientDBSK
        )
        recipientIdentity = try makeReceiverIdentity(
            recipientLtpk,
            recipientSpk,
            recipientOtpk.publicKey,
            recipientKEM,
            senderDBSK
        )

        // MARK: 2. Select one-time keys for the initial handshake
        let aliceOneTimeKeyPair = try senderOneTimeKeys().randomElement()!
        let bobOneTimeKeyPair = try recipientOneTimeKeys().randomElement()!

        let aliceInitialOneTimePrivate = aliceOneTimeKeyPair.privateKey
        let aliceInitialOneTimePublic = aliceOneTimeKeyPair.publicKey
        let bobInitialOneTimePrivate = bobOneTimeKeyPair.privateKey
        let bobInitialOneTimePublic = bobOneTimeKeyPair.publicKey

        // MARK: 3. Alice → Bob: Initial handshake and first message
        await #expect(throws: Never.self, performing: {
            try await sendingManager.senderInitialization(
                sessionIdentity: self.recipientIdentity,
                sessionSymmetricKey: senderDBSK,
                remoteKeys: .init(
                    longTerm: .init(recipientLtpk.publicKey.rawRepresentation),
                    oneTime: bobInitialOneTimePublic,
                    kyber: .init(recipientKEM.publicKey.rawRepresentation)
                ),
                localKeys: .init(
                    longTerm: .init(senderLtpk.rawRepresentation),
                    oneTime: aliceInitialOneTimePrivate,
                    kyber: .init(senderKEM.encode())
                )
            )
        })

        let firstPlaintext = "Message 1 from Alice".data(using: .utf8)!
        let firstEncrypted = try await sendingManager.ratchetEncrypt(plainText: firstPlaintext)
        let aliceOneTimeKeyId = firstEncrypted.header.curveOneTimeKeyId


        // MARK: 3c. Bob sets up as recipient
        let aliceOneTimePrivateForBob = try await fetchPrivateOneTimeKey(aliceOneTimeKeyId)

        await #expect(throws: Never.self, performing: {
            try await receivingManager.recipientInitialization(
                sessionIdentity: self.senderIdentity,
                sessionSymmetricKey: recipientDBSK,
                remoteKeys: .init(
                    longTerm: .init(senderLtpk.publicKey.rawRepresentation),
                    oneTime: firstEncrypted.header.remotePublicOneTimeKey!,
                    kyber: .init(senderKEM.publicKey.rawRepresentation)
                ),
                localKeys: .init(
                    longTerm: .init(recipientLtpk.rawRepresentation),
                    oneTime: aliceOneTimePrivateForBob,
                    kyber: .init(recipientKEM.encode())
                )
            )
        })

        let firstDecrypted = try await receivingManager.ratchetDecrypt(firstEncrypted)
        #expect(firstDecrypted == firstPlaintext, "Decrypted first message must match Alice’s original.")

        // MARK: 4. Alice → Bob: Continue sending messages 2 through 80
        for i in 2...80 {
            let plaintext = "Message \(i) from Alice".data(using: .utf8)!
            let encrypted = try await sendingManager.ratchetEncrypt(plainText: plaintext)
            let decrypted = try await receivingManager.ratchetDecrypt(encrypted)
            #expect(decrypted == plaintext, "Decrypted message \(i) must match Alice’s original.")
        }

        // MARK: 5. Bob → Alice: Perform the reverse-direction handshake
        await #expect(throws: Never.self, performing: {
            try await receivingManager.senderInitialization(
                sessionIdentity: self.senderIdentity,
                sessionSymmetricKey: recipientDBSK,
                remoteKeys: .init(
                    longTerm: .init(senderLtpk.publicKey.rawRepresentation),
                    oneTime: aliceInitialOneTimePublic,
                    kyber: .init(senderKEM.publicKey.rawRepresentation)
                ),
                localKeys: .init(
                    longTerm: .init(recipientLtpk.rawRepresentation),
                    oneTime: bobInitialOneTimePrivate,
                    kyber: .init(recipientKEM.encode())
                )
            )
        })

        await #expect(throws: Never.self, performing: {
            try await sendingManager.recipientInitialization(
                sessionIdentity: self.recipientIdentity,
                sessionSymmetricKey: senderDBSK,
                remoteKeys: .init(
                    longTerm: .init(recipientLtpk.publicKey.rawRepresentation),
                    oneTime: bobInitialOneTimePublic,
                    kyber: .init(recipientKEM.publicKey.rawRepresentation)
                ),
                localKeys: .init(
                    longTerm: .init(senderLtpk.rawRepresentation),
                    oneTime: aliceInitialOneTimePrivate,
                    kyber: .init(senderKEM.encode())
                )
            )
        })

        let firstBackPlaintext = "Message 1 from Bob".data(using: .utf8)!
        let firstBackEncrypted = try await receivingManager.ratchetEncrypt(plainText: firstBackPlaintext)
        let firstBackDecrypted = try await sendingManager.ratchetDecrypt(firstBackEncrypted)
        #expect(firstBackDecrypted == firstBackPlaintext, "Decrypted first Bob→Alice message must match.")

        // MARK: 6. Bob → Alice: Continue sending messages 2 through 80
        for i in 2...80 {
            let plaintext = "Message \(i) from Bob".data(using: .utf8)!
            let encrypted = try await receivingManager.ratchetEncrypt(plainText: plaintext)
            let decrypted = try await sendingManager.ratchetDecrypt(encrypted)
            #expect(decrypted == plaintext, "Decrypted Bob→Alice message \(i) must match.")
        }

        // MARK: 7. Clean up both managers
        await #expect(throws: Never.self, performing: {
            try await sendingManager.shutdown()
            try await receivingManager.shutdown()
        })
    }

    
    @Test
    func testRatchetEncryptDecryptMessagesPerUserWitNewIntializations() async throws {
        let sendingManager = RatchetStateManager<SHA256>(executor: executor)
        await sendingManager.setDelegate(self)
        let receivingManager = RatchetStateManager<SHA256>(executor: executor)
        await receivingManager.setDelegate(self)

        let senderLtpk = crypto.generateCurve25519PrivateKey()
        let senderOtpk = crypto.generateCurve25519PrivateKey()
        let senderSpk = crypto.generateCurve25519SigningPrivateKey()
        let senderKEM = try crypto.generateKyber1024PrivateSigningKey()
        let senderDBSK = SymmetricKey(size: .bits256)

        let recipientLtpk = crypto.generateCurve25519PrivateKey()
        let recipientOtpk = crypto.generateCurve25519PrivateKey()
        let recipientSpk = crypto.generateCurve25519SigningPrivateKey()
        let recipientKEM = try crypto.generateKyber1024PrivateSigningKey()
        let recipientDBSK = SymmetricKey(size: .bits256)

        senderIdentity = try makeSenderIdentity(
            senderLtpk,
            senderSpk,
            senderKEM,
            senderOtpk.publicKey,
            recipientDBSK
        )
        recipientIdentity = try makeReceiverIdentity(
            recipientLtpk,
            recipientSpk,
            recipientOtpk.publicKey,
            recipientKEM,
            senderDBSK
        )

        let aliceOneTimeKeyPair = try senderOneTimeKeys().randomElement()!
        let bobOneTimeKeyPair = try recipientOneTimeKeys().randomElement()!

        let aliceInitialOneTimePrivate = aliceOneTimeKeyPair.privateKey
        let aliceInitialOneTimePublic = aliceOneTimeKeyPair.publicKey
        let bobInitialOneTimePrivate = bobOneTimeKeyPair.privateKey
        let bobInitialOneTimePublic = bobOneTimeKeyPair.publicKey

        // MARK: 4. Alice → Bob: Continue sending messages 2 through 80
            let plaintext = "Message from Alice".data(using: .utf8)!
            
            await #expect(throws: Never.self, performing: {
                try await sendingManager.senderInitialization(
                    sessionIdentity: self.recipientIdentity,
                    sessionSymmetricKey: senderDBSK,
                    remoteKeys: .init(
                        longTerm: .init(recipientLtpk.publicKey.rawRepresentation),
                        oneTime: bobInitialOneTimePublic,
                        kyber: .init(recipientKEM.publicKey.rawRepresentation)
                    ),
                    localKeys: .init(
                        longTerm: .init(senderLtpk.rawRepresentation),
                        oneTime: aliceInitialOneTimePrivate,
                        kyber: .init(senderKEM.encode())
                    )
                )
            })
            
            let encrypted = try await sendingManager.ratchetEncrypt(plainText: plaintext)
            let aliceOneTimeKeyId = encrypted.header.curveOneTimeKeyId
            let aliceOneTimePrivateForBob = try await fetchPrivateOneTimeKey(aliceOneTimeKeyId)
            
            // Initialize recipient before decrypting the message
            await #expect(throws: Never.self, performing: {
                try await receivingManager.recipientInitialization(
                    sessionIdentity: self.senderIdentity,
                    sessionSymmetricKey: recipientDBSK,
                    remoteKeys: .init(
                        longTerm: .init(senderLtpk.publicKey.rawRepresentation),
                        oneTime: encrypted.header.remotePublicOneTimeKey!,
                        kyber: .init(senderKEM.publicKey.rawRepresentation)
                    ),
                    localKeys: .init(
                        longTerm: .init(recipientLtpk.rawRepresentation),
                        oneTime: aliceOneTimePrivateForBob,
                        kyber: .init(recipientKEM.encode())
                    )
                )
            })
            let decrypted = try await receivingManager.ratchetDecrypt(encrypted)
            #expect(decrypted == plaintext, "Decrypted message must match Alice’s original.")
            
            await #expect(throws: Never.self, performing: {
                try await receivingManager.senderInitialization(
                    sessionIdentity: self.senderIdentity,
                    sessionSymmetricKey: recipientDBSK,
                    remoteKeys: .init(
                        longTerm: .init(senderLtpk.publicKey.rawRepresentation),
                        oneTime: aliceInitialOneTimePublic,
                        kyber: .init(senderKEM.publicKey.rawRepresentation)
                    ),
                    localKeys: .init(
                        longTerm: .init(recipientLtpk.rawRepresentation),
                        oneTime: bobInitialOneTimePrivate,
                        kyber: .init(recipientKEM.encode())
                    )
                )
            })
            
            let encrypted2 = try await sendingManager.ratchetEncrypt(plainText: plaintext)
            
            // Initialize recipient before decrypting the message
            await #expect(throws: Never.self, performing: {
                try await sendingManager.recipientInitialization(
                    sessionIdentity: self.recipientIdentity,
                    sessionSymmetricKey: senderDBSK,
                    remoteKeys: .init(
                        longTerm: .init(recipientLtpk.publicKey.rawRepresentation),
                        oneTime: encrypted.header.remotePublicOneTimeKey!,
                        kyber: .init(recipientKEM.publicKey.rawRepresentation)
                    ),
                    localKeys: .init(
                        longTerm: .init(senderLtpk.rawRepresentation),
                        oneTime: aliceInitialOneTimePrivate,
                        kyber: .init(senderKEM.encode())
                    )
                )
            })
            let decrypted2 = try await receivingManager.ratchetDecrypt(encrypted2)
            #expect(decrypted2 == plaintext, "Decrypted message must match Alice’s original.")
            
        await #expect(throws: Never.self, performing: {
            try await sendingManager.senderInitialization(
                sessionIdentity: self.recipientIdentity,
                sessionSymmetricKey: senderDBSK,
                remoteKeys: .init(
                    longTerm: .init(recipientLtpk.publicKey.rawRepresentation),
                    oneTime: bobInitialOneTimePublic,
                    kyber: .init(recipientKEM.publicKey.rawRepresentation)
                ),
                localKeys: .init(
                    longTerm: .init(senderLtpk.rawRepresentation),
                    oneTime: aliceInitialOneTimePrivate,
                    kyber: .init(senderKEM.encode())
                )
            )
        })
        
        let encrypted3 = try await sendingManager.ratchetEncrypt(plainText: plaintext)
        
        await #expect(throws: Never.self, performing: {
            try await sendingManager.senderInitialization(
                sessionIdentity: self.recipientIdentity,
                sessionSymmetricKey: senderDBSK,
                remoteKeys: .init(
                    longTerm: .init(recipientLtpk.publicKey.rawRepresentation),
                    oneTime: bobInitialOneTimePublic,
                    kyber: .init(recipientKEM.publicKey.rawRepresentation)
                ),
                localKeys: .init(
                    longTerm: .init(senderLtpk.rawRepresentation),
                    oneTime: aliceInitialOneTimePrivate,
                    kyber: .init(senderKEM.encode())
                )
            )
        })
        
        let encrypted4 = try await sendingManager.ratchetEncrypt(plainText: plaintext)
        
        // Initialize recipient before decrypting the message
        await #expect(throws: Never.self, performing: {
            try await receivingManager.recipientInitialization(
                sessionIdentity: self.senderIdentity,
                sessionSymmetricKey: recipientDBSK,
                remoteKeys: .init(
                    longTerm: .init(senderLtpk.publicKey.rawRepresentation),
                    oneTime: encrypted.header.remotePublicOneTimeKey!,
                    kyber: .init(senderKEM.publicKey.rawRepresentation)
                ),
                localKeys: .init(
                    longTerm: .init(recipientLtpk.rawRepresentation),
                    oneTime: aliceOneTimePrivateForBob,
                    kyber: .init(recipientKEM.encode())
                )
            )
        })
        let decrypted3 = try await receivingManager.ratchetDecrypt(encrypted3)
        #expect(decrypted3 == plaintext, "Decrypted message must match Alice’s original.")
        
        // Initialize recipient before decrypting the message
        await #expect(throws: Never.self, performing: {
            try await receivingManager.recipientInitialization(
                sessionIdentity: self.senderIdentity,
                sessionSymmetricKey: recipientDBSK,
                remoteKeys: .init(
                    longTerm: .init(senderLtpk.publicKey.rawRepresentation),
                    oneTime: encrypted.header.remotePublicOneTimeKey!,
                    kyber: .init(senderKEM.publicKey.rawRepresentation)
                ),
                localKeys: .init(
                    longTerm: .init(recipientLtpk.rawRepresentation),
                    oneTime: aliceOneTimePrivateForBob,
                    kyber: .init(recipientKEM.encode())
                )
            )
        })
        let decrypted4 = try await receivingManager.ratchetDecrypt(encrypted4)
        #expect(decrypted4 == plaintext, "Decrypted message must match Alice’s original.")
        
        await #expect(throws: Never.self, performing: {
            try await receivingManager.senderInitialization(
                sessionIdentity: self.senderIdentity,
                sessionSymmetricKey: recipientDBSK,
                remoteKeys: .init(
                    longTerm: .init(senderLtpk.publicKey.rawRepresentation),
                    oneTime: aliceInitialOneTimePublic,
                    kyber: .init(senderKEM.publicKey.rawRepresentation)
                ),
                localKeys: .init(
                    longTerm: .init(recipientLtpk.rawRepresentation),
                    oneTime: bobInitialOneTimePrivate,
                    kyber: .init(recipientKEM.encode())
                )
            )
        })
        
        let encrypted5 = try await sendingManager.ratchetEncrypt(plainText: plaintext)
        
        await #expect(throws: Never.self, performing: {
            try await sendingManager.recipientInitialization(
                sessionIdentity: self.recipientIdentity,
                sessionSymmetricKey: senderDBSK,
                remoteKeys: .init(
                    longTerm: .init(recipientLtpk.publicKey.rawRepresentation),
                    oneTime: encrypted.header.remotePublicOneTimeKey!,
                    kyber: .init(recipientKEM.publicKey.rawRepresentation)
                ),
                localKeys: .init(
                    longTerm: .init(senderLtpk.rawRepresentation),
                    oneTime: aliceInitialOneTimePrivate,
                    kyber: .init(senderKEM.encode())
                )
            )
        })
        let decrypted5 = try await receivingManager.ratchetDecrypt(encrypted5)
        #expect(decrypted5 == plaintext, "Decrypted message must match Alice’s original.")
        
        await #expect(throws: Never.self, performing: {
            try await receivingManager.senderInitialization(
                sessionIdentity: self.senderIdentity,
                sessionSymmetricKey: recipientDBSK,
                remoteKeys: .init(
                    longTerm: .init(senderLtpk.publicKey.rawRepresentation),
                    oneTime: aliceInitialOneTimePublic,
                    kyber: .init(senderKEM.publicKey.rawRepresentation)
                ),
                localKeys: .init(
                    longTerm: .init(recipientLtpk.rawRepresentation),
                    oneTime: bobInitialOneTimePrivate,
                    kyber: .init(recipientKEM.encode())
                )
            )
        })
        
        let encrypted6 = try await sendingManager.ratchetEncrypt(plainText: plaintext)
        
        await #expect(throws: Never.self, performing: {
            try await sendingManager.recipientInitialization(
                sessionIdentity: self.recipientIdentity,
                sessionSymmetricKey: senderDBSK,
                remoteKeys: .init(
                    longTerm: .init(recipientLtpk.publicKey.rawRepresentation),
                    oneTime: encrypted.header.remotePublicOneTimeKey!,
                    kyber: .init(recipientKEM.publicKey.rawRepresentation)
                ),
                localKeys: .init(
                    longTerm: .init(senderLtpk.rawRepresentation),
                    oneTime: aliceInitialOneTimePrivate,
                    kyber: .init(senderKEM.encode())
                )
            )
        })
        let decrypted6 = try await receivingManager.ratchetDecrypt(encrypted6)
        #expect(decrypted6 == plaintext, "Decrypted message must match Alice’s original.")

        // MARK: 7. Clean up both managers
        await #expect(throws: Never.self, performing: {
            try await sendingManager.shutdown()
            try await receivingManager.shutdown()
        })
    }
    
    
    @Test
    func testRatchetEncryptDecryptOutofOrderMessagesPerUserWitNewIntializations() async throws {
        let sendingManager = RatchetStateManager<SHA256>(executor: executor)
        await sendingManager.setDelegate(self)
        let receivingManager = RatchetStateManager<SHA256>(executor: executor)
        await receivingManager.setDelegate(self)

        let senderLtpk = crypto.generateCurve25519PrivateKey()
        let senderOtpk = crypto.generateCurve25519PrivateKey()
        let senderSpk = crypto.generateCurve25519SigningPrivateKey()
        let senderKEM = try crypto.generateKyber1024PrivateSigningKey()
        let senderDBSK = SymmetricKey(size: .bits256)

        let recipientLtpk = crypto.generateCurve25519PrivateKey()
        let recipientOtpk = crypto.generateCurve25519PrivateKey()
        let recipientSpk = crypto.generateCurve25519SigningPrivateKey()
        let recipientKEM = try crypto.generateKyber1024PrivateSigningKey()
        let recipientDBSK = SymmetricKey(size: .bits256)

        senderIdentity = try makeSenderIdentity(
            senderLtpk,
            senderSpk,
            senderKEM,
            senderOtpk.publicKey,
            recipientDBSK
        )
        recipientIdentity = try makeReceiverIdentity(
            recipientLtpk,
            recipientSpk,
            recipientOtpk.publicKey,
            recipientKEM,
            senderDBSK
        )

        let aliceOneTimeKeyPair = try senderOneTimeKeys().randomElement()!
        let bobOneTimeKeyPair = try recipientOneTimeKeys().randomElement()!

        let aliceInitialOneTimePrivate = aliceOneTimeKeyPair.privateKey
        let bobInitialOneTimePublic = bobOneTimeKeyPair.publicKey

        // MARK: 4. Alice → Bob: Continue sending messages 2 through 80
            let plaintext1 = "Message 1 from Alice".data(using: .utf8)!
            let plaintext2 = "Message 2 from Alice".data(using: .utf8)!
            let plaintext3 = "Message 3 from Alice".data(using: .utf8)!
            
            await #expect(throws: Never.self, performing: {
                try await sendingManager.senderInitialization(
                    sessionIdentity: self.recipientIdentity,
                    sessionSymmetricKey: senderDBSK,
                    remoteKeys: .init(
                        longTerm: .init(recipientLtpk.publicKey.rawRepresentation),
                        oneTime: bobInitialOneTimePublic,
                        kyber: .init(recipientKEM.publicKey.rawRepresentation)
                    ),
                    localKeys: .init(
                        longTerm: .init(senderLtpk.rawRepresentation),
                        oneTime: aliceInitialOneTimePrivate,
                        kyber: .init(senderKEM.encode())
                    )
                )
            })
            
            let encrypted1 = try await sendingManager.ratchetEncrypt(plainText: plaintext1)
        
        await #expect(throws: Never.self, performing: {
            try await sendingManager.senderInitialization(
                sessionIdentity: self.recipientIdentity,
                sessionSymmetricKey: senderDBSK,
                remoteKeys: .init(
                    longTerm: .init(recipientLtpk.publicKey.rawRepresentation),
                    oneTime: bobInitialOneTimePublic,
                    kyber: .init(recipientKEM.publicKey.rawRepresentation)
                ),
                localKeys: .init(
                    longTerm: .init(senderLtpk.rawRepresentation),
                    oneTime: aliceInitialOneTimePrivate,
                    kyber: .init(senderKEM.encode())
                )
            )
        })
        
        let encrypted2 = try await sendingManager.ratchetEncrypt(plainText: plaintext2)
        
        
        await #expect(throws: Never.self, performing: {
            try await sendingManager.senderInitialization(
                sessionIdentity: self.recipientIdentity,
                sessionSymmetricKey: senderDBSK,
                remoteKeys: .init(
                    longTerm: .init(recipientLtpk.publicKey.rawRepresentation),
                    oneTime: bobInitialOneTimePublic,
                    kyber: .init(recipientKEM.publicKey.rawRepresentation)
                ),
                localKeys: .init(
                    longTerm: .init(senderLtpk.rawRepresentation),
                    oneTime: aliceInitialOneTimePrivate,
                    kyber: .init(senderKEM.encode())
                )
            )
        })
        
        let encrypted3 = try await sendingManager.ratchetEncrypt(plainText: plaintext3)
        
        var stashedMessages = Set<RatchetMessage>()
           
        let aliceOneTimeKeyId3 = encrypted3.header.curveOneTimeKeyId
        let aliceOneTimePrivateForBob3 = try await fetchPrivateOneTimeKey(aliceOneTimeKeyId3)
            // Initialize recipient before decrypting the message
            await #expect(throws: Never.self, performing: {
                try await receivingManager.recipientInitialization(
                    sessionIdentity: self.senderIdentity,
                    sessionSymmetricKey: recipientDBSK,
                    remoteKeys: .init(
                        longTerm: .init(senderLtpk.publicKey.rawRepresentation),
                        oneTime: encrypted3.header.remotePublicOneTimeKey!,
                        kyber: .init(senderKEM.publicKey.rawRepresentation)
                    ),
                    localKeys: .init(
                        longTerm: .init(recipientLtpk.rawRepresentation),
                        oneTime: aliceOneTimePrivateForBob3,
                        kyber: .init(recipientKEM.encode())
                    )
                )
            })
        await #expect(throws: Never.self, performing: {
            do {
                let decrypted3 = try await receivingManager.ratchetDecrypt(encrypted3)
                #expect(decrypted3 == plaintext3, "Decrypted message must match Alice’s original.")
            } catch let error as RatchetError {
                if error == .initialMessageNotReceived {
                    stashedMessages.insert(encrypted3)
                }
            }
        })
        
        let aliceOneTimeKeyId1 = encrypted1.header.curveOneTimeKeyId
        let aliceOneTimePrivateForBob1 = try await fetchPrivateOneTimeKey(aliceOneTimeKeyId1)
            // Initialize recipient before decrypting the message
            await #expect(throws: Never.self, performing: {
                try await receivingManager.recipientInitialization(
                    sessionIdentity: self.senderIdentity,
                    sessionSymmetricKey: recipientDBSK,
                    remoteKeys: .init(
                        longTerm: .init(senderLtpk.publicKey.rawRepresentation),
                        oneTime: encrypted1.header.remotePublicOneTimeKey!,
                        kyber: .init(senderKEM.publicKey.rawRepresentation)
                    ),
                    localKeys: .init(
                        longTerm: .init(recipientLtpk.rawRepresentation),
                        oneTime: aliceOneTimePrivateForBob1,
                        kyber: .init(recipientKEM.encode())
                    )
                )
            })
        await #expect(throws: Never.self, performing: {
            do {
            let decrypted1 = try await receivingManager.ratchetDecrypt(encrypted1)
            #expect(decrypted1 == plaintext1, "Decrypted message must match Alice’s original.")
        } catch let error as RatchetError {
            if error == .initialMessageNotReceived {
                stashedMessages.insert(encrypted1)
            }
        }
        })
        
        let aliceOneTimeKeyId2 = encrypted2.header.curveOneTimeKeyId
        let aliceOneTimePrivateForBob2 = try await fetchPrivateOneTimeKey(aliceOneTimeKeyId2)
            // Initialize recipient before decrypting the message
            await #expect(throws: Never.self, performing: {
                try await receivingManager.recipientInitialization(
                    sessionIdentity: self.senderIdentity,
                    sessionSymmetricKey: recipientDBSK,
                    remoteKeys: .init(
                        longTerm: .init(senderLtpk.publicKey.rawRepresentation),
                        oneTime: encrypted2.header.remotePublicOneTimeKey!,
                        kyber: .init(senderKEM.publicKey.rawRepresentation)
                    ),
                    localKeys: .init(
                        longTerm: .init(recipientLtpk.rawRepresentation),
                        oneTime: aliceOneTimePrivateForBob2,
                        kyber: .init(recipientKEM.encode())
                    )
                )
            })
        await #expect(throws: Never.self, performing: {
            do {
            let decrypted2 = try await receivingManager.ratchetDecrypt(encrypted2)
            #expect(decrypted2 == plaintext2, "Decrypted message must match Alice’s original.")
        } catch let error as RatchetError {
            if error == .initialMessageNotReceived {
                stashedMessages.insert(encrypted2)
            }
        }
        })
        
        for stashedMessage in stashedMessages {
            do {
                try await receivingManager.recipientInitialization(
                    sessionIdentity: self.senderIdentity,
                    sessionSymmetricKey: recipientDBSK,
                    remoteKeys: .init(
                        longTerm: .init(senderLtpk.publicKey.rawRepresentation),
                        oneTime: encrypted1.header.remotePublicOneTimeKey!,
                        kyber: .init(senderKEM.publicKey.rawRepresentation)
                    ),
                    localKeys: .init(
                        longTerm: .init(recipientLtpk.rawRepresentation),
                        oneTime: aliceOneTimePrivateForBob1,
                        kyber: .init(recipientKEM.encode())
                    )
                )
                
                let message = try! await receivingManager.ratchetDecrypt(stashedMessage)
            } catch {
                continue
            }
        }
        
        
        // MARK: 7. Clean up both managers
        await #expect(throws: Never.self, performing: {
            try await sendingManager.shutdown()
            try await receivingManager.shutdown()
        })
    }





    // --- NEW: PERFORMANCE TEST ---
    @Test
    func testPerformanceThousandsOfMessages() async throws {
        let sendingManager = RatchetStateManager<SHA256>(executor: executor)
        await sendingManager.setDelegate(self)

        // Generate sender keys
        let senderltpk = crypto.generateCurve25519PrivateKey()
        let senderspk = crypto.generateCurve25519SigningPrivateKey()
        let senderKEM = try crypto.generateKyber1024PrivateSigningKey()
        let senderotpk = crypto.generateCurve25519PrivateKey()
        let senderDBSK = SymmetricKey(size: .bits256)
        
        let receivingManager = RatchetStateManager<SHA256>(executor: executor)
        await receivingManager.setDelegate(self)
        
        // Generate receiver keys
        let recipientltpk = crypto.generateCurve25519PrivateKey()
        let recipientspk = crypto.generateCurve25519SigningPrivateKey()
        let recipientKEM = try crypto.generateKyber1024PrivateSigningKey()
        let recipientotpk = crypto.generateCurve25519PrivateKey()
        let recipientDBSK = SymmetricKey(size: .bits256)

        // Create Sender's Identity
        senderIdentity = try makeSenderIdentity(senderltpk, senderspk, senderKEM, senderotpk.publicKey, senderDBSK)
        recipientIdentity = try makeReceiverIdentity(recipientltpk, recipientspk, recipientotpk.publicKey, recipientKEM, recipientDBSK)
        
        let localPrivateOneTimeKey = try senderOneTimeKeys().randomElement()
        let remotePublicOneTimeKey = try recipientOneTimeKeys().randomElement()!.publicKey
        

        // Initialize Sender
        try await sendingManager.senderInitialization(
            sessionIdentity: senderIdentity,
            sessionSymmetricKey: senderDBSK,
            remoteKeys: .init(longTerm: .init(recipientltpk.publicKey.rawRepresentation), oneTime: remotePublicOneTimeKey, kyber: .init(recipientKEM.publicKey.rawRepresentation)),
            localKeys: .init(longTerm: .init(senderltpk.rawRepresentation), oneTime: localPrivateOneTimeKey!.privateKey, kyber: .init(senderKEM.encode())))

        let payload = Data(repeating: 0x41, count: 128) // 128 bytes of "A"
        let messageCount = 10_000
        
        var messages: [RatchetMessage] = []

        let clock = ContinuousClock()
        let duration = try await clock.measure {
            for _ in 0..<messageCount {
                let encrypted = try await sendingManager.ratchetEncrypt(plainText: payload)
                messages.append(encrypted)
            }
        }

        let firstMessage = messages.first!
        let firstPrivateOTK = try await fetchPrivateOneTimeKey(firstMessage.header.curveOneTimeKeyId)
        
        _ = try await receivingManager.recipientInitialization(
            sessionIdentity: recipientIdentity,
            sessionSymmetricKey: recipientDBSK,
            remoteKeys: .init(
                longTerm: .init(senderltpk.publicKey.rawRepresentation),
                oneTime: firstMessage.header.remotePublicOneTimeKey!,
                kyber: .init(senderKEM.publicKey.rawRepresentation)),
            localKeys: .init(
                longTerm: .init(recipientltpk.rawRepresentation),
                oneTime: firstPrivateOTK,
                kyber: .init(recipientKEM.encode())))
        
        for message in messages {
            _ = try await receivingManager.ratchetDecrypt(message)
        }
        print("🔵 Encrypted/Decrypted \(messageCount) messages in \(duration.components.seconds) seconds")
        #expect(messages.count == messageCount)
        try await sendingManager.shutdown()
        try await receivingManager.shutdown()
    }

    
    var senderIdentity: SessionIdentity!
    var recipientIdentity: SessionIdentity!
    // --- NEW: STRESS TEST OUT OF ORDER ---
    @Test
    func testStressOutOfOrderMessages() async throws {
        let sendingManager = RatchetStateManager<SHA256>(executor: executor)
        await sendingManager.setDelegate(self)
        let receivingManager = RatchetStateManager<SHA256>(executor: executor)
        await receivingManager.setDelegate(self)

        // Generate keys
        let senderltpk = crypto.generateCurve25519PrivateKey()
        let senderspk = crypto.generateCurve25519SigningPrivateKey()
        let senderKEM = try crypto.generateKyber1024PrivateSigningKey()
        let senderotpk = crypto.generateCurve25519PrivateKey()
        let senderDBSK = SymmetricKey(size: .bits256)
        
        let recipientltpk = crypto.generateCurve25519PrivateKey()
        let recipientspk = crypto.generateCurve25519SigningPrivateKey()
        let recipientKEM = try crypto.generateKyber1024PrivateSigningKey()
        let recipientotpk = crypto.generateCurve25519PrivateKey()
        let recipientDBSK = SymmetricKey(size: .bits256)

        senderIdentity = try makeSenderIdentity(senderltpk, senderspk, senderKEM, senderotpk.publicKey, senderDBSK)
        recipientIdentity = try makeReceiverIdentity(recipientltpk, recipientspk, recipientotpk.publicKey, recipientKEM, recipientDBSK)

        let localPrivateOneTimeKey = try senderOneTimeKeys().randomElement()
        let remotePublicOneTimeKey = try recipientOneTimeKeys().randomElement()

        try await sendingManager.senderInitialization(
            sessionIdentity: senderIdentity,
            sessionSymmetricKey: senderDBSK,
            remoteKeys: .init(
                longTerm: .init(recipientltpk.publicKey.rawRepresentation),
                oneTime: remotePublicOneTimeKey!.publicKey,
                kyber: .init(recipientKEM.publicKey.rawRepresentation)),
            localKeys: .init(
                longTerm: .init(senderltpk.rawRepresentation),
                oneTime: localPrivateOneTimeKey!.privateKey,
                kyber: .init(senderKEM.encode())))

        var messages = try await (0...80).asyncMap { i in
            try await sendingManager.ratchetEncrypt(plainText: "Message \(i)".data(using: .utf8)!)
        }

        _ = try await receivingManager.recipientInitialization(
            sessionIdentity: recipientIdentity,
            sessionSymmetricKey: recipientDBSK,
            remoteKeys: .init(
                longTerm: .init(senderltpk.publicKey.rawRepresentation),
                oneTime: localPrivateOneTimeKey!.publicKey,
                kyber: .init(senderKEM.publicKey.rawRepresentation)),
            localKeys: .init(
                longTerm: .init(recipientltpk.rawRepresentation),
                oneTime: remotePublicOneTimeKey!.privateKey,
                kyber: .init(recipientKEM.encode())))
        
        let firstMessage = messages.removeFirst()
        _ = try await receivingManager.ratchetDecrypt(firstMessage)

        // Now decrypt the rest (shuffled!)
        let rest = messages.shuffled()
        
        for await message in rest.async {
            await #expect(throws: Never.self, performing: {
                _ = try await receivingManager.ratchetDecrypt(message)
            })
        }
        try await sendingManager.shutdown()
        try await receivingManager.shutdown()
    }
    
    @Test
    func outOfOrderHeaders() async throws {
        let sendingManager = RatchetStateManager<SHA256>(executor: executor)
        await sendingManager.setDelegate(self)
        let receivingManager = RatchetStateManager<SHA256>(executor: executor)
        await receivingManager.setDelegate(self)
        
        // Generate keys
        let senderltpk = crypto.generateCurve25519PrivateKey()
        let senderspk = crypto.generateCurve25519SigningPrivateKey()
        let senderKEM = try crypto.generateKyber1024PrivateSigningKey()
        let senderotpk = crypto.generateCurve25519PrivateKey()
        let senderDBSK = SymmetricKey(size: .bits256)
        
        let recipientltpk = crypto.generateCurve25519PrivateKey()
        let recipientspk = crypto.generateCurve25519SigningPrivateKey()
        let recipientKEM = try crypto.generateKyber1024PrivateSigningKey()
        let recipientotpk = crypto.generateCurve25519PrivateKey()
        let recipientDBSK = SymmetricKey(size: .bits256)
        
        senderIdentity = try makeSenderIdentity(senderltpk, senderspk, senderKEM, senderotpk.publicKey, senderDBSK)
        recipientIdentity = try makeReceiverIdentity(recipientltpk, recipientspk, recipientotpk.publicKey, recipientKEM, recipientDBSK)
        
        let localPrivateOneTimeKey = try senderOneTimeKeys().randomElement()
        let remotePublicOneTimeKey = try recipientOneTimeKeys().randomElement()
        
        try await sendingManager.senderInitialization(
            sessionIdentity: senderIdentity,
            sessionSymmetricKey: senderDBSK,
            remoteKeys: .init(
                longTerm: .init(recipientltpk.publicKey.rawRepresentation),
                oneTime: remotePublicOneTimeKey!.publicKey,
                kyber: .init(recipientKEM.publicKey.rawRepresentation)),
            localKeys: .init(
                longTerm: .init(senderltpk.rawRepresentation),
                oneTime: localPrivateOneTimeKey!.privateKey,
                kyber: .init(senderKEM.encode()))
        )

        _ = try await receivingManager.recipientInitialization(
            sessionIdentity: recipientIdentity,
            sessionSymmetricKey: recipientDBSK,
            remoteKeys: .init(
                longTerm: .init(senderltpk.publicKey.rawRepresentation),
                oneTime: localPrivateOneTimeKey!.publicKey,
                kyber: .init(senderKEM.publicKey.rawRepresentation)),
            localKeys: .init(
                longTerm: .init(recipientltpk.rawRepresentation),
                oneTime: remotePublicOneTimeKey!.privateKey,
                kyber: .init(recipientKEM.encode())))
      
        
        var messages = try await (1...80).asyncMap { i in
            try await sendingManager.ratchetEncrypt(plainText: "Message \(i)".data(using: .utf8)!)
        }
        
        let firstMessage = messages.removeFirst()
        _ = try await receivingManager.ratchetDecrypt(firstMessage)

        // Shuffle messages to simulate out-of-order delivery
        var shuffledMessages = messages.shuffled()
        
        var seenMessageNumbers: Set<Int> = []
        
        while !shuffledMessages.isEmpty {
            guard let randomIndex = shuffledMessages.indices.randomElement() else { continue }
            let message = shuffledMessages[randomIndex]
            
            do {
                let decryptedHeader = try await receivingManager.decryptHeader(message.header)

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
        try await sendingManager.shutdown()
        try await receivingManager.shutdown()
    }


    // --- NEW: SERIALIZATION / STATE SAVE-LOAD TEST ---
    @Test
    func testSerializationAndResumingRatchet() async throws {
        let sendingManager = RatchetStateManager<SHA256>(executor: executor)
        await sendingManager.setDelegate(self)
        let receivingManager = RatchetStateManager<SHA256>(executor: executor)
        await receivingManager.setDelegate(self)

        // Generate sender keys
        let senderltpk = crypto.generateCurve25519PrivateKey()
        let senderspk = crypto.generateCurve25519SigningPrivateKey()
        let senderKEM = try crypto.generateKyber1024PrivateSigningKey()
        let senderotpk = crypto.generateCurve25519PrivateKey()
        let senderDBSK = SymmetricKey(size: .bits256)
        
        // Generate receiver keys
        let recipientltpk = crypto.generateCurve25519PrivateKey()
        let recipientspk = crypto.generateCurve25519SigningPrivateKey()
        let recipientKEM = try crypto.generateKyber1024PrivateSigningKey()
        let recipientotpk = crypto.generateCurve25519PrivateKey()
        let recipientDBSK = SymmetricKey(size: .bits256)
        // Create Sender's Identity
        senderIdentity = try makeSenderIdentity(senderltpk, senderspk, senderKEM, senderotpk.publicKey, senderDBSK)
        
        // Create Receiver's Identity
        recipientIdentity = try makeReceiverIdentity(recipientltpk, recipientspk, recipientotpk.publicKey, recipientKEM, recipientDBSK)
        
        let localPrivateOneTimeKey = try senderOneTimeKeys().randomElement()
        let remotePublicOneTimeKey = try recipientOneTimeKeys().randomElement()!.publicKey

        // Initialize Sender
        try await sendingManager.senderInitialization(
            sessionIdentity: senderIdentity,
            sessionSymmetricKey: senderDBSK,
            remoteKeys: .init(longTerm: .init(recipientltpk.publicKey.rawRepresentation), oneTime: remotePublicOneTimeKey, kyber: .init(recipientKEM.publicKey.rawRepresentation)),
            localKeys: .init(longTerm: .init(senderltpk.rawRepresentation), oneTime: localPrivateOneTimeKey!.privateKey, kyber: .init(senderKEM.encode())))
        
        let plaintext = "Persist me!".data(using: .utf8)!
        let encrypted = try await sendingManager.ratchetEncrypt(plainText: plaintext)
        let localPrivateOneTimeKey1 = try await fetchPrivateOneTimeKey(encrypted.header.curveOneTimeKeyId)
        
        try await Task.sleep(until: .now + .seconds(10))

       try await receivingManager.recipientInitialization(
            sessionIdentity: recipientIdentity,
            sessionSymmetricKey: recipientDBSK,
            remoteKeys: .init(longTerm: .init(senderltpk.publicKey.rawRepresentation), oneTime: encrypted.header.remotePublicOneTimeKey!, kyber: .init(senderKEM.publicKey.rawRepresentation)),
            localKeys: .init(longTerm: .init(recipientltpk.rawRepresentation), oneTime: localPrivateOneTimeKey1, kyber: .init(recipientKEM.encode())))
        let decrypted = try await receivingManager.ratchetDecrypt(encrypted)
        #expect(decrypted == plaintext)
        try await sendingManager.shutdown()
        try await receivingManager.shutdown()
    }
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
