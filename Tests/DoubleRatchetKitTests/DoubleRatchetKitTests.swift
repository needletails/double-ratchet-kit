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
                    publicOneTimeKey: publicOTK.rawRepresentation,
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
                publicOneTimeKey: publicOTK.rawRepresentation,
                deviceName: "ReceiverDevice",
                isMasterDevice: true),
            symmetricKey: databaseSymmetricKey
        )
    }

    @Test
    func testRatchetEncryptDecrypt() async throws {
        let sendingManager = RatchetStateManager<SHA256>(executor: executor)
        await sendingManager.setDelegate(self)
        let receivingManager = RatchetStateManager<SHA256>(executor: executor)
        await receivingManager.setDelegate(self)

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
        
        let originalPlaintext = "Test message for ratchet encrypt/decrypt".data(using: .utf8)!
        
        // Sender encrypts a message
        let encrypted = try await sendingManager.ratchetEncrypt(plainText: originalPlaintext)
        let localPrivateOneTimeKey1 = try await fetchPrivateOneTimeKey(encrypted.header.oneTimeId)
        
        // Receiver decrypts it
        let decryptedPlaintext = try await receivingManager.recipientInitialization(
            sessionIdentity: recipientIdentity,
            sessionSymmetricKey: recipientDBSK,
            remoteKeys: .init(longTerm: .init(senderltpk.publicKey.rawRepresentation), oneTime: encrypted.header.remotePublicOneTimeKey!, kyber: .init(senderKEM.publicKey.rawRepresentation)),
            localKeys: .init(longTerm: .init(recipientltpk.rawRepresentation), oneTime: localPrivateOneTimeKey1, kyber: .init(recipientKEM.encode())),
            initialMessage: encrypted)
      
        #expect(decryptedPlaintext == originalPlaintext, "Decrypted plaintext must match the original plaintext.")
        // 🚀 NOW Send a Second Message to verify ratchet advancement!
        let secondPlaintext = "Second ratcheted message!".data(using: .utf8)!
        let secondEncrypted = try await sendingManager.ratchetEncrypt(plainText: secondPlaintext)
        let secondDecryptedPlaintext = try await receivingManager.ratchetDecrypt(secondEncrypted)
        #expect(secondDecryptedPlaintext == secondPlaintext, "Decrypted second plaintext must match.")
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
        let firstPrivateOTK = try await fetchPrivateOneTimeKey(firstMessage.header.oneTimeId)
        
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
                kyber: .init(recipientKEM.encode())),
            initialMessage: firstMessage
        )
        
        for message in messages.dropFirst() {
            _ = try await receivingManager.ratchetDecrypt(message)
        }
        print("🔵 Encrypted/Decrypted \(messageCount) messages in \(duration.components.seconds) seconds")
        #expect(messages.count == messageCount)
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
        let remotePublicOneTimeKey = try recipientOneTimeKeys().randomElement()!.publicKey

        try await sendingManager.senderInitialization(
            sessionIdentity: senderIdentity,
            sessionSymmetricKey: senderDBSK,
            remoteKeys: .init(
                longTerm: .init(recipientltpk.publicKey.rawRepresentation),
                oneTime: remotePublicOneTimeKey,
                kyber: .init(recipientKEM.publicKey.rawRepresentation)),
            localKeys: .init(
                longTerm: .init(senderltpk.rawRepresentation),
                oneTime: localPrivateOneTimeKey!.privateKey,
                kyber: .init(senderKEM.encode())))

        let messages = try await (0...80).asyncMap { i in
            try await sendingManager.ratchetEncrypt(plainText: "Message \(i)".data(using: .utf8)!)
        }

        // Use the FIRST message for initialization
        let firstMessage = messages.first!
        let firstPrivateOTK = try await fetchPrivateOneTimeKey(firstMessage.header.oneTimeId)

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
                kyber: .init(recipientKEM.encode())),
            initialMessage: firstMessage
        )

        // Now decrypt the rest (shuffled!)
        let rest = messages.dropFirst().shuffled()
        
        for await message in rest.async {
            await #expect(throws: Never.self, performing: {
                _ = try await receivingManager.ratchetDecrypt(message)
            })
        }
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
        let remotePublicOneTimeKey = try recipientOneTimeKeys().randomElement()!.publicKey
        
        try await sendingManager.senderInitialization(
            sessionIdentity: senderIdentity,
            sessionSymmetricKey: senderDBSK,
            remoteKeys: .init(
                longTerm: .init(recipientltpk.publicKey.rawRepresentation),
                oneTime: remotePublicOneTimeKey,
                kyber: .init(recipientKEM.publicKey.rawRepresentation)),
            localKeys: .init(
                longTerm: .init(senderltpk.rawRepresentation),
                oneTime: localPrivateOneTimeKey!.privateKey,
                kyber: .init(senderKEM.encode()))
        )
        
        let firstMessage = try await sendingManager.ratchetEncrypt(plainText: "Message One".data(using: .utf8)!)
        let firstPrivateOTK = try await fetchPrivateOneTimeKey(firstMessage.header.oneTimeId)
        
        
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
                kyber: .init(recipientKEM.encode())),
            initialMessage: firstMessage
        )
        
        let messages = try await (1...5).asyncMap { i in
            try await sendingManager.ratchetEncrypt(plainText: "Message \(i)".data(using: .utf8)!)
        }
        
        // Shuffle messages to simulate out-of-order delivery
        var shuffledMessages = messages.shuffled()
        
        var seenMessageNumbers: Set<Int> = []
        
        while !shuffledMessages.isEmpty {
            guard let randomIndex = shuffledMessages.indices.randomElement() else { continue }
            let message = shuffledMessages[randomIndex]
            
            do {
                let decryptedHeader = try await receivingManager.decryptHeader(message.header)

                if let number = decryptedHeader.decrypted?.messageNumber {
//                    print("✅ Decrypted Header: message number: \(number)")
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
        for expected in 1...5 {
            #expect(seenMessageNumbers.contains(expected), "Expected to see message number \(expected)")
        }
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
        let localPrivateOneTimeKey1 = try await fetchPrivateOneTimeKey(encrypted.header.oneTimeId)
        
        try await Task.sleep(until: .now + .seconds(10))

        let decrypted = try await receivingManager.recipientInitialization(
            sessionIdentity: recipientIdentity,
            sessionSymmetricKey: recipientDBSK,
            remoteKeys: .init(longTerm: .init(senderltpk.publicKey.rawRepresentation), oneTime: encrypted.header.remotePublicOneTimeKey!, kyber: .init(senderKEM.publicKey.rawRepresentation)),
            localKeys: .init(longTerm: .init(recipientltpk.rawRepresentation), oneTime: localPrivateOneTimeKey1, kyber: .init(recipientKEM.encode())),
            initialMessage: encrypted)

        #expect(decrypted == plaintext)
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
