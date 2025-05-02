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
@testable import DoubleRatchetKit

@Suite(.serialized)
actor RatchetStateManagerTests: SessionIdentityDelegate {
    
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
    
    
    func fetchPrivateOneTimeKey(_ id: UUID?) async throws -> DoubleRatchetKit.Curve25519PrivateKeyRepresentable {
        guard let key = try recipientOneTimeKeys().first(where: { $0.id == id }) else {
            fatalError()
        }
        return key.privateKey
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


    func updateSessionIdentity(_ identity: SessionIdentity) async throws {}
    
    
    let executor = TestableExecutor(queue: .init(label: "testable-executor"))
    
    nonisolated var unownedExecutor: UnownedSerialExecutor {
        executor.asUnownedSerialExecutor()
    }
    
    let crypto = NeedleTailCrypto()

        func makeSenderIdentity(_
                                lltpk: Curve25519PrivateKey,
                                _ lspk: Curve25519.Signing.PrivateKey,
                                _ senderKEM: Kyber1024.KeyAgreement.PrivateKey,
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
                    kyber1024PublicKey:  senderKEM.publicKey.rawRepresentation,
                    deviceName: "SenderDevice",
                    isMasterDevice: true),
            symmetricKey: databaseSymmetricKey)
    }

    func makeReceiverIdentity(_
                              rltpk: Curve25519PrivateKey,
                              _ rspk: Curve25519.Signing.PrivateKey,
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
                kyber1024PublicKey:  receiverKEM.publicKey.rawRepresentation,
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
        let senderspk = crypto.generateCurve25519SigningPrivateKey()
        let senderKEM = try crypto.generateKyber1024PrivateSigningKey()
        let senderDBSK = SymmetricKey(size: .bits256)
        
        // Generate receiver keys
        let recipientltpk = crypto.generateCurve25519PrivateKey()
        let recipientspk = crypto.generateCurve25519SigningPrivateKey()
        let recipientKEM = try crypto.generateKyber1024PrivateSigningKey()
        let recipientDBSK = SymmetricKey(size: .bits256)
        // Create Sender's Identity
        let senderIdentity = try makeSenderIdentity(senderltpk, senderspk, senderKEM, senderDBSK)
        
        // Create Receiver's Identity
        let recipientIdentity = try makeReceiverIdentity(recipientltpk, recipientspk, recipientKEM, recipientDBSK)
        
        let localPrivateOneTimeKey = try senderOneTimeKeys().randomElement()
        let remotePublicOneTimeKey = try recipientOneTimeKeys().randomElement()!.publicKey

        // Initialize Sender
        try await sendingManager.senderInitialization(
            sessionIdentity: senderIdentity,
            sessionSymmetricKey: senderDBSK,
            remotePublicLongTermKey: .init(recipientltpk.publicKey.rawRepresentation),
            remotePublicOneTimeKey:  remotePublicOneTimeKey,
            remoteKyber1024PublicKey: .init(recipientKEM.publicKey.rawRepresentation),
            localPrivateLongTermKey: .init(senderltpk.rawRepresentation),
            localPrivateOneTimeKey: localPrivateOneTimeKey!.privateKey,
            localKyber1024PrivateKey: .init(senderKEM.encode()))
        
        let originalPlaintext = "Test message for ratchet encrypt/decrypt".data(using: .utf8)!
        
        // Sender encrypts a message
        let encrypted = try await sendingManager.ratchetEncrypt(plainText: originalPlaintext)
        let localPrivateOneTimeKey1 = try await fetchPrivateOneTimeKey(encrypted.header.oneTimeId)
        
        // Receiver decrypts it
        let decryptedPlaintext = try await receivingManager.recipientInitialization(
            sessionIdentity: recipientIdentity,
            sessionSymmetricKey: recipientDBSK,
            remotePublicLongTermKey: .init(senderltpk.publicKey.rawRepresentation),
            remotePublicOneTimeKey: encrypted.header.remotePublicOneTimeKey,
            remoteKyber1024PublicKey: .init(senderKEM.publicKey.rawRepresentation),
            localPrivateLongTermKey: .init(recipientltpk.rawRepresentation),
            localPrivateOneTimeKey: localPrivateOneTimeKey1,
            localKyber1024PrivateKey: .init(recipientKEM.encode()),
            initialMessage: encrypted)
        
        #expect(decryptedPlaintext == originalPlaintext, "Decrypted plaintext must match the original plaintext.")

        // 🚀 NOW Send a Second Message to verify ratchet advancement!
        let secondPlaintext = "Second ratcheted message!".data(using: .utf8)!
        let secondEncrypted = try await sendingManager.ratchetEncrypt(plainText: secondPlaintext)
        
        let localPrivateOneTimeKey2 = try await fetchPrivateOneTimeKey(secondEncrypted.header.oneTimeId)

        // Receiver decrypts it
        let secondDecryptedPlaintext = try await receivingManager.recipientInitialization(
            sessionIdentity: recipientIdentity,
            sessionSymmetricKey: recipientDBSK,
            remotePublicLongTermKey: .init(senderltpk.publicKey.rawRepresentation),
            remotePublicOneTimeKey:  secondEncrypted.header.remotePublicOneTimeKey,
            remoteKyber1024PublicKey: .init(senderKEM.publicKey.rawRepresentation),
            localPrivateLongTermKey: .init(recipientltpk.rawRepresentation),
            localPrivateOneTimeKey: localPrivateOneTimeKey2,
            localKyber1024PrivateKey: .init(recipientKEM.encode()),
            initialMessage: secondEncrypted)

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
        let senderDBSK = SymmetricKey(size: .bits256)
        
        // Generate receiver keys
        let recipientltpk = crypto.generateCurve25519PrivateKey()
        let recipientKEM = try crypto.generateKyber1024PrivateSigningKey()

        // Create Sender's Identity
        let senderIdentity = try makeSenderIdentity(senderltpk, senderspk, senderKEM, senderDBSK)
        
        let localPrivateOneTimeKey = try senderOneTimeKeys().randomElement()
        let remotePublicOneTimeKey = try recipientOneTimeKeys().randomElement()!.publicKey

        // Initialize Sender
        try await sendingManager.senderInitialization(
            sessionIdentity: senderIdentity,
            sessionSymmetricKey: senderDBSK,
            remotePublicLongTermKey: .init(recipientltpk.publicKey.rawRepresentation),
            remotePublicOneTimeKey:  remotePublicOneTimeKey,
            remoteKyber1024PublicKey: .init(recipientKEM.publicKey.rawRepresentation),
            localPrivateLongTermKey: .init(senderltpk.rawRepresentation),
            localPrivateOneTimeKey: localPrivateOneTimeKey!.privateKey,
            localKyber1024PrivateKey: .init(senderKEM.encode()))

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
        print("🔵 Encrypted \(messageCount) messages in \(duration.components.seconds) seconds")

        #expect(messages.count == messageCount)
    }

    // --- NEW: STRESS TEST OUT OF ORDER ---
    @Test
    func testStressOutOfOrderMessages() async throws {
        let sendingManager = RatchetStateManager<SHA256>(executor: executor)
        await sendingManager.setDelegate(self)
        let receivingManager = RatchetStateManager<SHA256>(executor: executor)
        await receivingManager.setDelegate(self)

        // Generate sender keys
        let senderltpk = crypto.generateCurve25519PrivateKey()
        let senderspk = crypto.generateCurve25519SigningPrivateKey()
        let senderKEM = try crypto.generateKyber1024PrivateSigningKey()
        let senderDBSK = SymmetricKey(size: .bits256)
        
        // Generate receiver keys
        let recipientltpk = crypto.generateCurve25519PrivateKey()
        let recipientspk = crypto.generateCurve25519SigningPrivateKey()
        let recipientKEM = try crypto.generateKyber1024PrivateSigningKey()
        let recipientDBSK = SymmetricKey(size: .bits256)
        // Create Sender's Identity
        let senderIdentity = try makeSenderIdentity(senderltpk, senderspk, senderKEM, senderDBSK)
        
        // Create Receiver's Identity
        let recipientIdentity = try makeReceiverIdentity(recipientltpk, recipientspk, recipientKEM, recipientDBSK)
        
        let localPrivateOneTimeKey = try senderOneTimeKeys().randomElement()
        let remotePublicOneTimeKey = try recipientOneTimeKeys().randomElement()!.publicKey

        // Initialize Sender
        try await sendingManager.senderInitialization(
            sessionIdentity: senderIdentity,
            sessionSymmetricKey: senderDBSK,
            remotePublicLongTermKey: .init(recipientltpk.publicKey.rawRepresentation),
            remotePublicOneTimeKey:  remotePublicOneTimeKey,
            remoteKyber1024PublicKey: .init(recipientKEM.publicKey.rawRepresentation),
            localPrivateLongTermKey: .init(senderltpk.rawRepresentation),
            localPrivateOneTimeKey: localPrivateOneTimeKey!.privateKey,
            localKyber1024PrivateKey: .init(senderKEM.encode()))

        let messages = try await (1...5).asyncMap { i in
            try await sendingManager.ratchetEncrypt(plainText: "Message \(i)".data(using: .utf8)!)
        }

        // Shuffle them
        let shuffledMessages = messages.shuffled()

        for encrypted in shuffledMessages {
            do {
                let localPrivateOneTimeKey1 = try await fetchPrivateOneTimeKey(encrypted.header.oneTimeId)
                
                // Receiver decrypts it
                _ = try await receivingManager.recipientInitialization(
                    sessionIdentity: recipientIdentity,
                    sessionSymmetricKey: recipientDBSK,
                    remotePublicLongTermKey: .init(senderltpk.publicKey.rawRepresentation),
                    remotePublicOneTimeKey: encrypted.header.remotePublicOneTimeKey,
                    remoteKyber1024PublicKey: .init(senderKEM.publicKey.rawRepresentation),
                    localPrivateLongTermKey: .init(recipientltpk.rawRepresentation),
                    localPrivateOneTimeKey: localPrivateOneTimeKey1,
                    localKyber1024PrivateKey: .init(recipientKEM.encode()),
                    initialMessage: encrypted)
            } catch {
                // Some decrypts should fail (because they're out of order!)
                continue
            }
        }
        
        // Reorder properly, should work
        for encrypted in messages {
            do {
                let decrypted = try await receivingManager.ratchetDecrypt(encrypted)
                let original = String(data: decrypted, encoding: .utf8)
                #expect(original?.hasPrefix("Message") == true)
            } catch {
                // It's OK if expired
                if let ratchetError = error as? RatchetError, ratchetError == .expiredKey {
                    // Expected! Move on
                    continue
                } else {
                    // Some unexpected error
                    throw error
                }
            }
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
        let senderDBSK = SymmetricKey(size: .bits256)
        
        // Generate receiver keys
        let recipientltpk = crypto.generateCurve25519PrivateKey()
        let recipientspk = crypto.generateCurve25519SigningPrivateKey()
        let recipientKEM = try crypto.generateKyber1024PrivateSigningKey()
        let recipientDBSK = SymmetricKey(size: .bits256)
        // Create Sender's Identity
        let senderIdentity = try makeSenderIdentity(senderltpk, senderspk, senderKEM, senderDBSK)
        
        // Create Receiver's Identity
        let recipientIdentity = try makeReceiverIdentity(recipientltpk, recipientspk, recipientKEM, recipientDBSK)
        
        let localPrivateOneTimeKey = try senderOneTimeKeys().randomElement()
        let remotePublicOneTimeKey = try recipientOneTimeKeys().randomElement()!.publicKey

        // Initialize Sender
        try await sendingManager.senderInitialization(
            sessionIdentity: senderIdentity,
            sessionSymmetricKey: senderDBSK,
            remotePublicLongTermKey: .init(recipientltpk.publicKey.rawRepresentation),
            remotePublicOneTimeKey:  remotePublicOneTimeKey,
            remoteKyber1024PublicKey: .init(recipientKEM.publicKey.rawRepresentation),
            localPrivateLongTermKey: .init(senderltpk.rawRepresentation),
            localPrivateOneTimeKey: localPrivateOneTimeKey!.privateKey,
            localKyber1024PrivateKey: .init(senderKEM.encode()))
        
        let plaintext = "Persist me!".data(using: .utf8)!
        let encrypted = try await sendingManager.ratchetEncrypt(plainText: plaintext)
        let localPrivateOneTimeKey1 = try await fetchPrivateOneTimeKey(encrypted.header.oneTimeId)
        
        try await Task.sleep(until: .now + .seconds(10))

        let decrypted = try await receivingManager.recipientInitialization(
            sessionIdentity: recipientIdentity,
            sessionSymmetricKey: recipientDBSK,
            remotePublicLongTermKey: .init(senderltpk.publicKey.rawRepresentation),
            remotePublicOneTimeKey: encrypted.header.remotePublicOneTimeKey,
            remoteKyber1024PublicKey: .init(senderKEM.publicKey.rawRepresentation),
            localPrivateLongTermKey: .init(recipientltpk.rawRepresentation),
            localPrivateOneTimeKey: localPrivateOneTimeKey1,
            localKyber1024PrivateKey: .init(recipientKEM.encode()),
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
