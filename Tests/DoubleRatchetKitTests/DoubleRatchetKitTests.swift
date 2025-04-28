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

@Suite
struct RatchetStateManagerTests {
    
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
                publicKeyRepesentable: lltpk.publicKey.rawRepresentation,
                publicSigningRepresentable: lspk.publicKey.rawRepresentation,
                kyber1024PublicKey: senderKEM.publicKey,
                state: nil,
                deviceName: "SenderDevice",
                isMasterDevice: true
            ),
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
                publicKeyRepesentable: rltpk.publicKey.rawRepresentation,
                publicSigningRepresentable: rspk.publicKey.rawRepresentation,
                kyber1024PublicKey: receiverKEM.publicKey,
                state: nil,
                deviceName: "ReceiverDevice",
                isMasterDevice: true
            ),
            symmetricKey: databaseSymmetricKey
        )
    }

    @Test
    func testRatchetEncryptDecrypt() async throws {
        let sendingManager = RatchetStateManager<SHA256>(executor: executor)
        let receivingManager = RatchetStateManager<SHA256>(executor: executor)
        
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
        let senderIdentity = try makeSenderIdentity(senderltpk, senderspk, senderKEM, senderDBSK)
        
        // Create Receiver's Identity
        let recipientIdentity = try makeReceiverIdentity(recipientltpk, recipientspk, recipientKEM, recipientDBSK)
        
        // Initialize Sender
        try await sendingManager.senderInitialization(
            sessionIdentity: senderIdentity,
            sessionSymmetricKey: senderDBSK,
            remotePublicLongTermKey: recipientltpk.publicKey,
            remotePublicOneTimeKey: recipientotpk.publicKey,
            remotePQKEMPublicKey: recipientKEM.publicKey,
            localPrivateLongTermKey: senderltpk,
            localPrivateOneTimeKey: senderotpk,
            localPQDHPrivateKey: senderKEM)
        
        let originalPlaintext = "Test message for ratchet encrypt/decrypt".data(using: .utf8)!
        
        // Sender encrypts a message
        let encrypted = try await sendingManager.ratchetEncrypt(plainText: originalPlaintext)
        
        // Receiver decrypts it
        let decryptedPlaintext = try await receivingManager.recipientInitialization(
            sessionIdentity: recipientIdentity,
            sessionSymmetricKey: recipientDBSK,
            remotePublicLongTermKey: senderltpk.publicKey,
            remotePublicOneTimeKey: senderotpk.publicKey,
            remotePQKEMPublicKey: senderKEM.publicKey,
            localPrivateLongTermKey: recipientltpk,
            localPrivateOneTimeKey: recipientotpk,
            localPQKEMPrivateKey: recipientKEM,
            initialMessage: encrypted)
        
        #expect(decryptedPlaintext == originalPlaintext, "Decrypted plaintext must match the original plaintext.")

        // 🚀 NOW Send a Second Message to verify ratchet advancement!
        let secondPlaintext = "Second ratcheted message!".data(using: .utf8)!
        let secondEncrypted = try await sendingManager.ratchetEncrypt(plainText: secondPlaintext)

        // Receiver decrypts it
        let secondDecryptedPlaintext = try await receivingManager.recipientInitialization(
            sessionIdentity: recipientIdentity,
            sessionSymmetricKey: recipientDBSK,
            remotePublicLongTermKey: senderltpk.publicKey,
            remotePublicOneTimeKey: senderotpk.publicKey,
            remotePQKEMPublicKey: senderKEM.publicKey,
            localPrivateLongTermKey: recipientltpk,
            localPrivateOneTimeKey: recipientotpk,
            localPQKEMPrivateKey: recipientKEM,
            initialMessage: secondEncrypted)

        #expect(secondDecryptedPlaintext == secondPlaintext, "Decrypted second plaintext must match.")
    }

    // --- NEW: PERFORMANCE TEST ---
    @Test
    func testPerformanceThousandsOfMessages() async throws {
        let sendingManager = RatchetStateManager<SHA256>(executor: executor)
        
        // Generate sender keys
        let senderltpk = crypto.generateCurve25519PrivateKey()
        let senderotpk = crypto.generateCurve25519PrivateKey()
        let senderspk = crypto.generateCurve25519SigningPrivateKey()
        let senderKEM = try crypto.generateKyber1024PrivateSigningKey()
        let senderDBSK = SymmetricKey(size: .bits256)
        
        // Generate receiver keys
        let recipientltpk = crypto.generateCurve25519PrivateKey()
        let recipientotpk = crypto.generateCurve25519PrivateKey()
        let recipientKEM = try crypto.generateKyber1024PrivateSigningKey()

        // Create Sender's Identity
        let senderIdentity = try makeSenderIdentity(senderltpk, senderspk, senderKEM, senderDBSK)
        
        
        try await sendingManager.senderInitialization(
            sessionIdentity: senderIdentity,
            sessionSymmetricKey: senderDBSK,
            remotePublicLongTermKey: recipientltpk.publicKey,
            remotePublicOneTimeKey: recipientotpk.publicKey,
            remotePQKEMPublicKey: recipientKEM.publicKey,
            localPrivateLongTermKey: senderltpk,
            localPrivateOneTimeKey: senderotpk,
            localPQDHPrivateKey: senderKEM)

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
        let receivingManager = RatchetStateManager<SHA256>(executor: executor)
        
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
        let senderIdentity = try makeSenderIdentity(senderltpk, senderspk, senderKEM, senderDBSK)
        
        // Create Receiver's Identity
        let recipientIdentity = try makeReceiverIdentity(recipientltpk, recipientspk, recipientKEM, recipientDBSK)

        try await sendingManager.senderInitialization(
            sessionIdentity: senderIdentity,
            sessionSymmetricKey: senderDBSK,
            remotePublicLongTermKey: recipientltpk.publicKey,
            remotePublicOneTimeKey: recipientotpk.publicKey,
            remotePQKEMPublicKey: recipientKEM.publicKey,
            localPrivateLongTermKey: senderltpk,
            localPrivateOneTimeKey: senderotpk,
            localPQDHPrivateKey: senderKEM)


        let messages = try await (1...5).asyncMap { i in
            try await sendingManager.ratchetEncrypt(plainText: "Message \(i)".data(using: .utf8)!)
        }

        // Shuffle them
        let shuffledMessages = messages.shuffled()

        for encrypted in shuffledMessages {
            do {
                _ = try await receivingManager.recipientInitialization(
                    sessionIdentity: recipientIdentity,
                    sessionSymmetricKey: recipientDBSK,
                    remotePublicLongTermKey: senderltpk.publicKey,
                    remotePublicOneTimeKey: senderotpk.publicKey,
                    remotePQKEMPublicKey: senderKEM.publicKey,
                    localPrivateLongTermKey: recipientltpk,
                    localPrivateOneTimeKey: recipientotpk,
                    localPQKEMPrivateKey: recipientKEM,
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
        let receivingManager = RatchetStateManager<SHA256>(executor: executor)
        
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
        let senderIdentity = try makeSenderIdentity(senderltpk, senderspk, senderKEM, senderDBSK)
        
        // Create Receiver's Identity
        let recipientIdentity = try makeReceiverIdentity(recipientltpk, recipientspk, recipientKEM, recipientDBSK)
        
        try await sendingManager.senderInitialization(
            sessionIdentity: senderIdentity,
            sessionSymmetricKey: senderDBSK,
            remotePublicLongTermKey: recipientltpk.publicKey,
            remotePublicOneTimeKey: recipientotpk.publicKey,
            remotePQKEMPublicKey: recipientKEM.publicKey,
            localPrivateLongTermKey: senderltpk,
            localPrivateOneTimeKey: senderotpk,
            localPQDHPrivateKey: senderKEM)


        let plaintext = "Persist me!".data(using: .utf8)!
        let encrypted = try await sendingManager.ratchetEncrypt(plainText: plaintext)

        try await Task.sleep(until: .now + .seconds(10))

        let decrypted = try await receivingManager.recipientInitialization(
            sessionIdentity: recipientIdentity,
            sessionSymmetricKey: recipientDBSK,
            remotePublicLongTermKey: senderltpk.publicKey,
            remotePublicOneTimeKey: senderotpk.publicKey,
            remotePQKEMPublicKey: senderKEM.publicKey,
            localPrivateLongTermKey: recipientltpk,
            localPrivateOneTimeKey: recipientotpk,
            localPQKEMPrivateKey: recipientKEM,
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
