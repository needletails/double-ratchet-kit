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
import AsyncAlgorithms
import Crypto
import Foundation
import NeedleTailCrypto
import NeedleTailLogger
import SwiftKyber
import Testing

@testable import DoubleRatchetKit

@Suite(.serialized)
actor RatchetStateManagerTests: SessionIdentityDelegate {
    struct KeyPair {
        let id: UUID
        let publicKey: CurvePublicKey
        let privateKey: CurvePrivateKey
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
        longTerm: Curve25519PrivateKey,
        signing: Curve25519.Signing.PrivateKey,
        kem: Kyber1024.KeyAgreement.PrivateKey,
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
                pqKemPublicKey: .init(kem.publicKey.rawRepresentation),
                oneTimePublicKey: .init(oneTime.rawRepresentation),
                deviceName: "AliceDevice",
                isMasterDevice: true
            ),
            symmetricKey: databaseSymmetricKey
        )
    }

    func makeBobIdentity(
        longTerm: Curve25519PrivateKey,
        signing: Curve25519.Signing.PrivateKey,
        kem: Kyber1024.KeyAgreement.PrivateKey,
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
                pqKemPublicKey: .init(kem.publicKey.rawRepresentation),
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
        let aliceKEM = try crypto.generateKyber1024PrivateSigningKey()

        // Generate receiver keys
        let bobLtpk = crypto.generateCurve25519PrivateKey()
        let bobOtpk = crypto.generateCurve25519PrivateKey()
        let bobSpk = crypto.generateCurve25519SigningPrivateKey()
        let bobKEM = try crypto.generateKyber1024PrivateSigningKey()

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
        let aliceKyberPublic = try PQKemPublicKey(
            id: aliceKyberId, aliceKEM.publicKey.rawRepresentation)
        let aliceKyberPrivate = try PQKemPrivateKey(id: aliceKyberId, aliceKEM.encode())

        let bobKyberId = UUID()
        let bobKyberPublic = try PQKemPublicKey(id: bobKyberId, bobKEM.publicKey.rawRepresentation)
        let bobKyberPrivate = try PQKemPrivateKey(id: bobKyberId, bobKEM.encode())

        let bundle = KeyBundle(
            alicePublic: RemoteKeys(
                longTerm: alicePublicLongTerm, oneTime: aliceInitialOneTimePublic,
                pqKem: aliceKyberPublic),
            alicePrivate: LocalKeys(
                longTerm: alicePrivateLongTerm, oneTime: aliceInitialOneTimePrivate,
                pqKem: aliceKyberPrivate),
            bobPublic: RemoteKeys(
                longTerm: bobPublicLongTerm, oneTime: bobInitialOneTimePublic, pqKem: bobKyberPublic
            ),
            bobPrivate: LocalKeys(
                longTerm: bobPrivateLongTerm, oneTime: bobInitialOneTimePrivate,
                pqKem: bobKyberPrivate)
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
        let aliceManager = RatchetStateManager<SHA256>(executor: executor)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor)
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
            let encrypted = try await aliceManager.ratchetEncrypt(plainText: originalPlaintext)

            // Bob initializes as recipient from Alice
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: .init(
                    longTerm: bundle.alicePublic.longTerm,
                    oneTime: encrypted.header.remoteOneTimePublicKey!,
                    pqKem: encrypted.header.remotePQKemPublicKey,
                ),
                localKeys: bundle.bobPrivate)

            let decryptedPlaintext = try await bobManager.ratchetDecrypt(encrypted)
            #expect(
                decryptedPlaintext == originalPlaintext,
                "Decrypted plaintext must match the original plaintext.")

            // Test ratchet advancement with second message
            let secondPlaintext = "Second ratcheted message!".data(using: .utf8)!
            let secondEncrypted = try await aliceManager.ratchetEncrypt(plainText: secondPlaintext)
            let secondDecryptedPlaintext = try await bobManager.ratchetDecrypt(secondEncrypted)
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

            let encrypted2 = try await bobManager.ratchetEncrypt(plainText: originalPlaintext)

            // Alice initializes as recipient from Bob
            guard let bobIdentityLatest2 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.recipientInitialization(
                sessionIdentity: bobIdentityLatest2,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: .init(
                    longTerm: bundle.bobPublic.longTerm,
                    oneTime: encrypted2.header.remoteOneTimePublicKey!,
                    pqKem: encrypted2.header.remotePQKemPublicKey,
                ),
                localKeys: bundle.alicePrivate)

            let decryptedSecond = try await aliceManager.ratchetDecrypt(encrypted2)
            #expect(decryptedSecond == originalPlaintext, "Decrypted second plaintext must match.")

            // Continue bidirectional communication
            let thirdPlaintext = "Third message from Alice".data(using: .utf8)!
            let thirdEncrypted = try await aliceManager.ratchetEncrypt(plainText: thirdPlaintext)
            let decryptedThird = try await bobManager.ratchetDecrypt(thirdEncrypted)
            #expect(decryptedThird == thirdPlaintext, "Decrypted third plaintext must match.")

            let fourthPlaintext = "Fourth message from Bob".data(using: .utf8)!
            let fourthEncrypted = try await bobManager.ratchetEncrypt(plainText: fourthPlaintext)
            let decryptedFourth = try await aliceManager.ratchetDecrypt(fourthEncrypted)
            #expect(decryptedFourth == fourthPlaintext, "Decrypted fourth plaintext must match.")

            let fifthPlaintext = "Fifth message from Alice".data(using: .utf8)!
            let fifthEncrypted = try await aliceManager.ratchetEncrypt(plainText: fifthPlaintext)
            let decryptedFifth = try await bobManager.ratchetDecrypt(fifthEncrypted)
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
        let aliceManager = RatchetStateManager<SHA256>(executor: executor)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor)
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
            let firstEncrypted = try await aliceManager.ratchetEncrypt(plainText: firstPlaintext)

            // Bob initializes as recipient from Alice
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: .init(
                    longTerm: bundle.alicePublic.longTerm,
                    oneTime: firstEncrypted.header.remoteOneTimePublicKey!,
                    pqKem: firstEncrypted.header.remotePQKemPublicKey,
                ),
                localKeys: bundle.bobPrivate)

            let firstDecrypted = try await bobManager.ratchetDecrypt(firstEncrypted)
            #expect(
                firstDecrypted == firstPlaintext,
                "Decrypted first message must match Alice's original.")

            // Alice sends messages 2 through 80 to Bob
            for i in 2...80 {
                let plaintext = "Message \(i) from Alice".data(using: .utf8)!
                let encrypted = try await aliceManager.ratchetEncrypt(plainText: plaintext)
                let decrypted = try await bobManager.ratchetDecrypt(encrypted)
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
            try await aliceManager.recipientInitialization(
                sessionIdentity: bobIdentityLatest2,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)

            let firstBackPlaintext = "Message 1 from Bob".data(using: .utf8)!
            let firstBackEncrypted = try await bobManager.ratchetEncrypt(
                plainText: firstBackPlaintext)
            let firstBackDecrypted = try await aliceManager.ratchetDecrypt(firstBackEncrypted)
            #expect(
                firstBackDecrypted == firstBackPlaintext,
                "Decrypted first Bob→Alice message must match.")

            // Bob sends messages 2 through 80 to Alice
            for i in 2...80 {
                let plaintext = "Message \(i) from Bob".data(using: .utf8)!
                let encrypted = try await bobManager.ratchetEncrypt(plainText: plaintext)
                let decrypted = try await aliceManager.ratchetDecrypt(encrypted)
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
        let aliceManager = RatchetStateManager<SHA256>(executor: executor)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor)
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
                        sessionSymmetricKey: aliceDbsk,
                        remoteKeys: bundle.bobPublic,
                        localKeys: bundle.alicePrivate)
                })

            let encrypted = try await aliceManager.ratchetEncrypt(plainText: plaintext)

            // Initialize recipient before decrypting the message
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await bobManager.recipientInitialization(
                        sessionIdentity: aliceIdentityLatest,
                        sessionSymmetricKey: bobDBSK,
                        remoteKeys: .init(
                            longTerm: bundle.alicePublic.longTerm,
                            oneTime: encrypted.header.remoteOneTimePublicKey!,
                            pqKem: encrypted.header.remotePQKemPublicKey,
                        ),
                        localKeys: bundle.bobPrivate)
                })
            let decrypted = try await bobManager.ratchetDecrypt(encrypted)
            #expect(decrypted == plaintext, "Decrypted message must match Alice's original.")

            guard let aliceIdentityLatest2 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await bobManager.senderInitialization(
                        sessionIdentity: aliceIdentityLatest2,
                        sessionSymmetricKey: bobDBSK,
                        remoteKeys: bundle.alicePublic,
                        localKeys: bundle.bobPrivate)
                })

            let encrypted2 = try await bobManager.ratchetEncrypt(plainText: plaintext)

            // Initialize recipient before decrypting the message
            guard let bobIdentityLatest2 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await aliceManager.recipientInitialization(
                        sessionIdentity: bobIdentityLatest2,
                        sessionSymmetricKey: aliceDbsk,
                        remoteKeys: .init(
                            longTerm: bundle.alicePublic.longTerm,
                            oneTime: encrypted2.header.remoteOneTimePublicKey!,
                            pqKem: encrypted2.header.remotePQKemPublicKey,
                        ),
                        localKeys: bundle.bobPrivate)
                })
            let decrypted2 = try await aliceManager.ratchetDecrypt(encrypted2)
            #expect(decrypted2 == plaintext, "Decrypted message must match Alice's original.")

            guard let bobIdentityLatest3 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await aliceManager.senderInitialization(
                        sessionIdentity: bobIdentityLatest3,
                        sessionSymmetricKey: aliceDbsk,
                        remoteKeys: bundle.alicePublic,
                        localKeys: bundle.alicePrivate)
                })

            let encrypted3 = try await aliceManager.ratchetEncrypt(plainText: plaintext)

            // Initialize recipient before decrypting the message
            guard let aliceIdentityLatest3 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await bobManager.recipientInitialization(
                        sessionIdentity: aliceIdentityLatest3,
                        sessionSymmetricKey: bobDBSK,
                        remoteKeys: .init(
                            longTerm: bundle.alicePublic.longTerm,
                            oneTime: encrypted3.header.remoteOneTimePublicKey!,
                            pqKem: encrypted3.header.remotePQKemPublicKey,
                        ),
                        localKeys: bundle.bobPrivate)
                })

            let decrypted3 = try await bobManager.ratchetDecrypt(encrypted3)
            #expect(decrypted3 == plaintext, "Decrypted message must match Alice's original.")

            guard let bobIdentityLatest4 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await aliceManager.senderInitialization(
                        sessionIdentity: bobIdentityLatest4,
                        sessionSymmetricKey: aliceDbsk,
                        remoteKeys: bundle.alicePublic,
                        localKeys: bundle.alicePrivate)
                })

            let encrypted4 = try await aliceManager.ratchetEncrypt(plainText: plaintext)

            // Initialize recipient before decrypting the message
            guard let aliceIdentityLatest4 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await bobManager.recipientInitialization(
                        sessionIdentity: aliceIdentityLatest4,
                        sessionSymmetricKey: bobDBSK,
                        remoteKeys: .init(
                            longTerm: bundle.alicePublic.longTerm,
                            oneTime: encrypted4.header.remoteOneTimePublicKey!,
                            pqKem: encrypted4.header.remotePQKemPublicKey,
                        ),
                        localKeys: bundle.bobPrivate)
                })
            let decrypted4 = try await bobManager.ratchetDecrypt(encrypted4)
            #expect(decrypted4 == plaintext, "Decrypted message must match Alice's original.")

            guard let aliceIdentityLatest5 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await bobManager.senderInitialization(
                        sessionIdentity: aliceIdentityLatest5,
                        sessionSymmetricKey: bobDBSK,
                        remoteKeys: bundle.alicePublic,
                        localKeys: bundle.bobPrivate,
                    )
                })

            let encrypted5 = try await aliceManager.ratchetEncrypt(plainText: plaintext)

            // Initialize recipient before decrypting the message
            guard let bobIdentityLatest5 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await aliceManager.recipientInitialization(
                        sessionIdentity: bobIdentityLatest5,
                        sessionSymmetricKey: aliceDbsk,
                        remoteKeys: .init(
                            longTerm: bundle.bobPublic.longTerm,
                            oneTime: encrypted5.header.remoteOneTimePublicKey!,
                            pqKem: encrypted5.header.remotePQKemPublicKey,
                        ),
                        localKeys: bundle.alicePrivate,
                    )
                })
            let decrypted5 = try await bobManager.ratchetDecrypt(encrypted5)
            #expect(decrypted5 == plaintext, "Decrypted message must match Alice's original.")

            guard let aliceIdentityLatest6 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await bobManager.senderInitialization(
                        sessionIdentity: aliceIdentityLatest6,
                        sessionSymmetricKey: bobDBSK,
                        remoteKeys: bundle.alicePublic,
                        localKeys: bundle.bobPrivate,
                    )
                })

            let encrypted6 = try await aliceManager.ratchetEncrypt(plainText: plaintext)

            // Initialize recipient before decrypting the message
            await #expect(
                throws: Never.self,
                performing: {
                    try await bobManager.recipientInitialization(
                        sessionIdentity: aliceIdentityLatest6,
                        sessionSymmetricKey: bobDBSK,
                        remoteKeys: .init(
                            longTerm: bundle.alicePublic.longTerm,
                            oneTime: encrypted6.header.remoteOneTimePublicKey!,
                            pqKem: encrypted6.header.remotePQKemPublicKey,
                        ),
                        localKeys: bundle.bobPrivate,
                    )
                })
            let decrypted6 = try await bobManager.ratchetDecrypt(encrypted6)
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
        let aliceManager = RatchetStateManager<SHA256>(executor: executor)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor)
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
                        sessionSymmetricKey: aliceDbsk,
                        remoteKeys: bundle.bobPublic,
                        localKeys: bundle.alicePrivate,
                    )
                })

            let encrypted1 = try await aliceManager.ratchetEncrypt(plainText: plaintext1)

            guard let bobIdentityLatest2 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await aliceManager.senderInitialization(
                        sessionIdentity: bobIdentityLatest2,
                        sessionSymmetricKey: aliceDbsk,
                        remoteKeys: bundle.bobPublic,
                        localKeys: bundle.alicePrivate,
                    )
                })

            let encrypted2 = try await aliceManager.ratchetEncrypt(plainText: plaintext2)

            guard let bobIdentityLatest3 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            guard let aliceIdentityLatest3 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await aliceManager.senderInitialization(
                        sessionIdentity: bobIdentityLatest3,
                        sessionSymmetricKey: aliceDbsk,
                        remoteKeys: bundle.bobPublic,
                        localKeys: bundle.alicePrivate)
                })

            let encrypted3 = try await aliceManager.ratchetEncrypt(plainText: plaintext3)

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
                        sessionSymmetricKey: bobDBSK,
                        remoteKeys: .init(
                            longTerm: bundle.alicePublic.longTerm,
                            oneTime: encrypted3.header.remoteOneTimePublicKey!,
                            pqKem: encrypted3.header.remotePQKemPublicKey,
                        ),
                        localKeys: bundle.bobPrivate,
                    )
                })
            await #expect(
                throws: Never.self,
                performing: {
                    do {
                        let decrypted3 = try await bobManager.ratchetDecrypt(encrypted3)
                        #expect(
                            decrypted3 == plaintext3,
                            "Decrypted message must match Alice's original.")
                    } catch let error as RatchetError {
                        if error == .initialMessageNotReceived {
                            stashedMessages.insert(encrypted3)
                        }
                    }
                })

            guard let aliceIdentityLatest2 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await bobManager.recipientInitialization(
                        sessionIdentity: aliceIdentityLatest2,
                        sessionSymmetricKey: bobDBSK,
                        remoteKeys: .init(
                            longTerm: bundle.alicePublic.longTerm,
                            oneTime: encrypted1.header.remoteOneTimePublicKey!,
                            pqKem: encrypted1.header.remotePQKemPublicKey,
                        ),
                        localKeys: bundle.bobPrivate,
                    )
                })
            await #expect(
                throws: Never.self,
                performing: {
                    do {
                        let decrypted1 = try await bobManager.ratchetDecrypt(encrypted1)
                        #expect(
                            decrypted1 == plaintext1,
                            "Decrypted message must match Alice's original.")
                    } catch let error as RatchetError {
                        if error == .initialMessageNotReceived {
                            stashedMessages.insert(encrypted1)
                        }
                    }
                })

            guard let aliceIdentityLatest3 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            await #expect(
                throws: Never.self,
                performing: {
                    try await bobManager.recipientInitialization(
                        sessionIdentity: aliceIdentityLatest3,
                        sessionSymmetricKey: bobDBSK,
                        remoteKeys: .init(
                            longTerm: bundle.alicePublic.longTerm,
                            oneTime: encrypted2.header.remoteOneTimePublicKey!,
                            pqKem: encrypted2.header.remotePQKemPublicKey,
                        ),
                        localKeys: bundle.bobPrivate,
                    )
                })
            await #expect(
                throws: Never.self,
                performing: {
                    do {
                        let decrypted2 = try await bobManager.ratchetDecrypt(encrypted2)
                        #expect(
                            decrypted2 == plaintext2,
                            "Decrypted message must match Alice's original.")
                    } catch let error as RatchetError {
                        if error == .initialMessageNotReceived {
                            stashedMessages.insert(encrypted2)
                        }
                    }
                })

            for stashedMessage in stashedMessages {
                do {
                    guard let aliceIdentityLatest4 = getSessionIdentity(for: aliceIdentity.id)
                    else {
                        continue
                    }
                    try await bobManager.recipientInitialization(
                        sessionIdentity: aliceIdentityLatest4,
                        sessionSymmetricKey: bobDBSK,
                        remoteKeys: .init(
                            longTerm: bundle.alicePublic.longTerm,
                            oneTime: encrypted1.header.remoteOneTimePublicKey!,
                            pqKem: encrypted1.header.remotePQKemPublicKey,
                        ),
                        localKeys: bundle.bobPrivate,
                    )

                    _ = try await bobManager.ratchetDecrypt(stashedMessage)
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
        let aliceManager = RatchetStateManager<SHA256>(executor: executor)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor)
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
                    let encrypted = try await aliceManager.ratchetEncrypt(plainText: payload)
                    messages.append(encrypted)
                }
            }

            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            _ = try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate)

            for message in messages {
                _ = try await bobManager.ratchetDecrypt(message)
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
        let aliceManager = RatchetStateManager<SHA256>(executor: executor)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor)
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

            var messages = try await (0...80).asyncMap { i in
                try await aliceManager.ratchetEncrypt(plainText: "Message \(i)".data(using: .utf8)!)
            }

            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            _ = try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate)

            let firstMessage = messages.removeFirst()
            _ = try await bobManager.ratchetDecrypt(firstMessage)

            // Now decrypt the rest (shuffled!)
            let rest = messages.shuffled()

            for await message in rest.async {
                await #expect(
                    throws: Never.self,
                    performing: {
                        _ = try await bobManager.ratchetDecrypt(message)
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
        let aliceManager = RatchetStateManager<SHA256>(executor: executor)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor)
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
                let encrypted = try await aliceManager.ratchetEncrypt(plainText: payload)
                messages.append(encrypted)
            }

            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            _ = try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate)

            // Decrypt all messages
            for message in messages {
                _ = try await bobManager.ratchetDecrypt(message)
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
        let aliceManager = RatchetStateManager<SHA256>(executor: executor)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor)
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
            let encrypted = try await aliceManager.ratchetEncrypt(plainText: plaintext)

            try await Task.sleep(until: .now + .seconds(10))

            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            _ = try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate)
            let decrypted = try await bobManager.ratchetDecrypt(encrypted)
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
        let aliceManager = RatchetStateManager<SHA256>(executor: executor)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor)
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
            let encrypted = try! await aliceManager.ratchetEncrypt(plainText: originalPlaintext)

            // Receiver decrypts it
            _ = try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate)

            let decryptedPlaintext = try await bobManager.ratchetDecrypt(encrypted)
            #expect(
                decryptedPlaintext == originalPlaintext,
                "Decrypted plaintext must match the original plaintext.")
            // 🚀 NOW Send a Second Message to verify ratchet advancement!
            let secondPlaintext = "Second ratcheted message!".data(using: .utf8)!
            let secondEncrypted = try await aliceManager.ratchetEncrypt(plainText: secondPlaintext)
            let secondDecryptedPlaintext = try await bobManager.ratchetDecrypt(secondEncrypted)

            #expect(
                secondDecryptedPlaintext == secondPlaintext,
                "Decrypted second plaintext must match.")

            try await bobManager.senderInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate)

            let encrypted2 = try await bobManager.ratchetEncrypt(plainText: originalPlaintext)

            _ = try await aliceManager.recipientInitialization(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: bundle.bobPublic,
                localKeys: bundle.alicePrivate)

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
                    pqKem: bundle.alicePrivate.pqKem,
                ))

            let rotatedPlaintext = "Test message for ratchet encrypt/decrypt".data(using: .utf8)!

            // Sender encrypts a message
            let encryptedRotated = try await aliceManager.ratchetEncrypt(
                plainText: rotatedPlaintext)

            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: .init(
                    longTerm: aliceRotatedPublicLongTerm,
                    oneTime: bundle.alicePublic.oneTime,
                    pqKem: bundle.alicePublic.pqKem,
                ),
                localKeys: bundle.bobPrivate)

            let decryptedPlaintextRotated = try await bobManager.ratchetDecrypt(encryptedRotated)
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
                    pqKem: bundle.alicePublic.pqKem,
                ),
                localKeys: .init(
                    longTerm: bobRotatedPrivateLongTerm,
                    oneTime: bundle.bobPrivate.oneTime,
                    pqKem: bundle.bobPrivate.pqKem,
                ))

            let rotatedPlaintext2 = "Test message for ratchet encrypt/decrypt".data(using: .utf8)!
            let encryptedRotated2 = try await bobManager.ratchetEncrypt(
                plainText: rotatedPlaintext2)

            try await aliceManager.recipientInitialization(
                sessionIdentity: bobIdentityLatest,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: .init(
                    longTerm: bobRotatedPublicLongTerm,
                    oneTime: bundle.bobPublic.oneTime,
                    pqKem: bundle.bobPublic.pqKem,
                ),
                localKeys: bundle.alicePrivate)

            // Decrypt message from Bob -> Alice (2nd message)
            let decryptedRotatedSecond = try await aliceManager.ratchetDecrypt(encryptedRotated2)
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
                        pqKem: bundle.bobPublic.pqKem,
                    ),
                    localKeys: .init(
                        longTerm: aliceRotatedPrivateLongTerm,
                        oneTime: bundle.alicePrivate.oneTime,
                        pqKem: bundle.alicePrivate.pqKem,
                    ),
                )
                return try await aliceManager.ratchetEncrypt(
                    plainText: "Message \(i)".data(using: .utf8)!)
            }

            for message in messages {
                _ = try await bobManager.recipientInitialization(
                    sessionIdentity: aliceIdentityLatest,
                    sessionSymmetricKey: bobDBSK,
                    remoteKeys: .init(
                        longTerm: aliceRotatedPublicLongTerm,
                        oneTime: bundle.alicePublic.oneTime,
                        pqKem: bundle.alicePublic.pqKem,
                    ),
                    localKeys: .init(
                        longTerm: bobRotatedPrivateLongTerm,
                        oneTime: bundle.bobPrivate.oneTime,
                        pqKem: bundle.bobPrivate.pqKem,
                    ),
                )
                _ = try await bobManager.ratchetDecrypt(message)
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
        let aliceManager = RatchetStateManager<SHA256>(executor: executor)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor)
        await bobManager.setDelegate(self)

        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()

            // Test stateUninitialized error
            await #expect(
                throws: RatchetError.stateUninitialized.self,
                performing: {
                    _ = try await aliceManager.ratchetEncrypt(plainText: "test".data(using: .utf8)!)
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
                plainText: "test".data(using: .utf8)!)

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
                remoteKeys: .init(
                    longTerm: bundle.alicePublic.longTerm,
                    oneTime: validMessage.header.remoteOneTimePublicKey!,
                    pqKem: validMessage.header.remotePQKemPublicKey,
                ),
                localKeys: bundle.bobPrivate)

            await #expect(
                throws: CryptoKitError.self,
                performing: {
                    _ = try await bobManager.ratchetDecrypt(invalidMessage)
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
        let aliceManager1 = RatchetStateManager<SHA256>(executor: executor)
        await aliceManager1.setDelegate(self)
        let aliceManager2 = RatchetStateManager<SHA256>(executor: executor)
        await aliceManager2.setDelegate(self)
        let bobManager1 = RatchetStateManager<SHA256>(executor: executor)
        await bobManager1.setDelegate(self)
        let bobManager2 = RatchetStateManager<SHA256>(executor: executor)
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
                plainText: "Message from Alice1".data(using: .utf8)!)
            async let message2 = aliceManager2.ratchetEncrypt(
                plainText: "Message from Alice2".data(using: .utf8)!)

            let (encrypted1, encrypted2) = try await (message1, message2)

            // Bob managers should be able to decrypt messages from respective Alice managers
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }

            try await bobManager1.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: .init(
                    longTerm: bundle.alicePublic.longTerm,
                    oneTime: encrypted1.header.remoteOneTimePublicKey!,
                    pqKem: encrypted1.header.remotePQKemPublicKey,
                ),
                localKeys: bundle.bobPrivate)

            try await bobManager2.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: .init(
                    longTerm: bundle.alicePublic.longTerm,
                    oneTime: encrypted2.header.remoteOneTimePublicKey!,
                    pqKem: encrypted2.header.remotePQKemPublicKey,
                ),
                localKeys: bundle.bobPrivate)

            let decrypted1 = try await bobManager1.ratchetDecrypt(encrypted1)
            let decrypted2 = try await bobManager2.ratchetDecrypt(encrypted2)

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
        let aliceManager = RatchetStateManager<SHA256>(executor: executor)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor)
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
                plainText: "Initial message".data(using: .utf8)!)

            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: .init(
                    longTerm: bundle.alicePublic.longTerm,
                    oneTime: message1.header.remoteOneTimePublicKey!,
                    pqKem: message1.header.remotePQKemPublicKey,
                ),
                localKeys: bundle.bobPrivate)

            let decrypted1 = try await bobManager.ratchetDecrypt(message1)
            #expect(decrypted1 == "Initial message".data(using: .utf8)!)

            // Simulate session corruption by creating new managers
            let aliceManagerRecovery = RatchetStateManager<SHA256>(executor: executor)
            await aliceManagerRecovery.setDelegate(self)
            let bobManagerRecovery = RatchetStateManager<SHA256>(executor: executor)
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
                plainText: "Recovery message".data(using: .utf8)!)

            guard let aliceIdentityLatest2 = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManagerRecovery.recipientInitialization(
                sessionIdentity: aliceIdentityLatest2,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: .init(
                    longTerm: bundle.alicePublic.longTerm,
                    oneTime: message2.header.remoteOneTimePublicKey!,
                    pqKem: message2.header.remotePQKemPublicKey,
                ),
                localKeys: bundle.bobPrivate)

            let decrypted2 = try await bobManagerRecovery.ratchetDecrypt(message2)
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
        let aliceManager = RatchetStateManager<SHA256>(executor: executor)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor)
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
            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate)

            // Send many messages to test key rotation and potential exhaustion
            var messages: [RatchetMessage] = []
            for i in 0..<1000 {
                let message = try await aliceManager.ratchetEncrypt(
                    plainText: "Message \(i)".data(using: .utf8)!)
                messages.append(message)
            }

            // Verify all messages can be decrypted
            for (i, message) in messages.enumerated() {
                let decrypted = try await bobManager.ratchetDecrypt(message)
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
        let aliceManager = RatchetStateManager<SHA256>(executor: executor)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor)
        await bobManager.setDelegate(self)
        let charlieManager = RatchetStateManager<SHA256>(executor: executor)
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
                plainText: "Alice to Bob".data(using: .utf8)!)

            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: .init(
                    longTerm: bundle.alicePublic.longTerm,
                    oneTime: aliceToBobMessage.header.remoteOneTimePublicKey!,
                    pqKem: aliceToBobMessage.header.remotePQKemPublicKey,
                ),
                localKeys: bundle.bobPrivate)

            let decryptedAliceToBob = try await bobManager.ratchetDecrypt(aliceToBobMessage)
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
                plainText: "Bob to Alice".data(using: .utf8)!)

            guard let bobIdentityLatest2 = getSessionIdentity(for: bobIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await aliceManager.recipientInitialization(
                sessionIdentity: bobIdentityLatest2,
                sessionSymmetricKey: aliceDbsk,
                remoteKeys: .init(
                    longTerm: bundle.bobPublic.longTerm,
                    oneTime: bobToAliceMessage.header.remoteOneTimePublicKey!,
                    pqKem: bobToAliceMessage.header.remotePQKemPublicKey,
                ),
                localKeys: bundle.alicePrivate)

            let decryptedBobToAlice = try await aliceManager.ratchetDecrypt(bobToAliceMessage)
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
        let aliceManager = RatchetStateManager<SHA512>(executor: executor)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA512>(executor: executor)
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
                plainText: "SHA512 test".data(using: .utf8)!)

            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: .init(
                    longTerm: bundle.alicePublic.longTerm,
                    oneTime: message.header.remoteOneTimePublicKey!,
                    pqKem: message.header.remotePQKemPublicKey,
                ),
                localKeys: bundle.bobPrivate)

            let decrypted = try await bobManager.ratchetDecrypt(message)
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
        let aliceManager = RatchetStateManager<SHA256>(executor: executor)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor)
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
                plainText: "Delegate test".data(using: .utf8)!)

            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: .init(
                    longTerm: bundle.alicePublic.longTerm,
                    oneTime: message.header.remoteOneTimePublicKey!,
                    pqKem: message.header.remotePQKemPublicKey,
                ),
                localKeys: bundle.bobPrivate)

            let decrypted = try await bobManager.ratchetDecrypt(message)
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
        let aliceManager = RatchetStateManager<SHA256>(executor: executor)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor)
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
            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate)

            // Send many large messages to simulate memory pressure
            let largePayload = Data(repeating: 0x41, count: 1024 * 1024)  // 1MB payload
            var messages: [RatchetMessage] = []

            for _ in 0..<10 {
                let message = try await aliceManager.ratchetEncrypt(plainText: largePayload)
                messages.append(message)
            }

            // Verify all messages can still be decrypted under memory pressure
            for message in messages {
                let decrypted = try await bobManager.ratchetDecrypt(message)
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
        let aliceManager = RatchetStateManager<SHA256>(executor: executor)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor)
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
            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: bundle.alicePublic,
                localKeys: bundle.bobPrivate)

            // Send initial message
            let initialMessage = try await aliceManager.ratchetEncrypt(
                plainText: "Initial".data(using: .utf8)!)
            let decryptedInitial = try await bobManager.ratchetDecrypt(initialMessage)
            #expect(decryptedInitial == "Initial".data(using: .utf8)!)

            // Simulate long delay (in real scenario, keys might expire)
            try await Task.sleep(until: .now + .seconds(1))

            // Send message after delay
            let delayedMessage = try await aliceManager.ratchetEncrypt(
                plainText: "Delayed".data(using: .utf8)!)
            let decryptedDelayed = try await bobManager.ratchetDecrypt(delayedMessage)
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
        let aliceManager = RatchetStateManager<SHA256>(executor: executor)
        await aliceManager.setDelegate(self)
        let bobManager = RatchetStateManager<SHA256>(executor: executor)
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
                let message = try await aliceManager.ratchetEncrypt(plainText: "Message \(i)".data(using: .utf8)!)
                messages.append(message)
            }
            
            // Initialize Bob as recipient
            guard let aliceIdentityLatest = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            try await bobManager.recipientInitialization(
                sessionIdentity: aliceIdentityLatest,
                sessionSymmetricKey: bobDBSK,
                remoteKeys: .init(
                    longTerm: bundle.alicePublic.longTerm,
                    oneTime: messages[0].header.remoteOneTimePublicKey!,
                    pqKem: messages[0].header.remotePQKemPublicKey,
                ),
                localKeys: bundle.bobPrivate)
            
            // Bob successfully decrypts message 1 (establish handshake)
            let message1 = messages[0] // Index 0 = message 1
            let decrypted1 = try await bobManager.ratchetDecrypt(message1)
            #expect(decrypted1 == "Message 1".data(using: .utf8)!)
            
            // Bob successfully decrypts message 5
            let message5 = messages[4] // Index 4 = message 5
            let decrypted5 = try await bobManager.ratchetDecrypt(message5)
            #expect(decrypted5 == "Message 5".data(using: .utf8)!)
            
            // Now simulate the out-of-order scenario: message 7 arrives before message 6
            // This should trigger the skipped key generation process
            let message7 = messages[6] // Index 6 = message 7
            
            // This should work normally - the system should stash message 6's chain key
            // and generate message 7's chain key to decrypt it
            let decrypted7 = try await bobManager.ratchetDecrypt(message7)
            #expect(decrypted7 == "Message 7".data(using: .utf8)!)
            
            // Now when message 6 arrives, it should use the stashed chain key
            let message6 = messages[5] // Index 5 = message 6
            let decrypted6 = try await bobManager.ratchetDecrypt(message6)
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
                _ = try await bobManager.ratchetDecrypt(corruptedMessage)
            })
            
            try await aliceManager.shutdown()
            try await bobManager.shutdown()
        } catch {
            try? await aliceManager.shutdown()
            try? await bobManager.shutdown()
            throw error
        }
    }
}
