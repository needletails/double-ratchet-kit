//
//  OTKRetirementTests.swift
//  double-ratchet-kit
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
import BinaryCodable
import Testing
@testable import DoubleRatchetKit

extension MessageRatchetTests {
    /// Two 4.1 peers converge on OTK retirement: after both handshake
    /// directions finish and each side has seen the other's advertisement,
    /// headers stop embedding the bootstrap OTK public half and stop citing
    /// the peer's OTK id — without diverging the chains.
    @Test
    func testOneTimeKeyRetirementConvergence() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)

        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()

            func aliceSend(_ text: String) async throws -> RatchetMessage {
                guard let identity = getSessionIdentity(for: bobIdentity.id) else {
                    throw TestErrors.identityNotFound
                }
                try await aliceManager.initiateSession(
                    sessionIdentity: identity,
                    sessionSymmetricKey: aliceDbsk,
                    remoteKeys: bundle.bobPublic,
                    localKeys: bundle.alicePrivate)
                return try await aliceManager.encrypt(plainText: Data(text.utf8), sessionId: identity.id)
            }

            func bobReceive(_ message: RatchetMessage) async throws -> Data {
                guard let identity = getSessionIdentity(for: aliceIdentity.id) else {
                    throw TestErrors.identityNotFound
                }
                try await bobManager.respondToSession(
                    sessionIdentity: identity,
                    sessionSymmetricKey: bobDBSK,
                    header: message.header,
                    localKeys: bundle.bobPrivate)
                return try await bobManager.decrypt(message, sessionId: identity.id)
            }

            func bobSend(_ text: String) async throws -> RatchetMessage {
                guard let identity = getSessionIdentity(for: aliceIdentity.id) else {
                    throw TestErrors.identityNotFound
                }
                try await bobManager.initiateSession(
                    sessionIdentity: identity,
                    sessionSymmetricKey: bobDBSK,
                    remoteKeys: bundle.alicePublic,
                    localKeys: bundle.bobPrivate)
                return try await bobManager.encrypt(plainText: Data(text.utf8), sessionId: identity.id)
            }

            func aliceReceive(_ message: RatchetMessage) async throws -> Data {
                guard let identity = getSessionIdentity(for: bobIdentity.id) else {
                    throw TestErrors.identityNotFound
                }
                try await aliceManager.respondToSession(
                    sessionIdentity: identity,
                    sessionSymmetricKey: aliceDbsk,
                    header: message.header,
                    localKeys: bundle.alicePrivate)
                return try await aliceManager.decrypt(message, sessionId: identity.id)
            }

            // Bootstrap frame: embeds Alice's OTK and cites Bob's OTK id.
            let a1 = try await aliceSend("A1")
            #expect(a1.header.remoteOneTimePublicKey != nil)
            #expect(a1.header.oneTimeKeyId != nil)
            #expect(try await bobReceive(a1) == Data("A1".utf8))

            // Bob's first reply: his sending handshake is still open at the
            // retirement gate, so he still embeds his OTK and cites Alice's.
            let b1 = try await bobSend("B1")
            #expect(b1.header.remoteOneTimePublicKey != nil)
            #expect(b1.header.oneTimeKeyId != nil)
            #expect(try await aliceReceive(b1) == Data("B1".utf8))

            // Alice has now finished both handshakes and seen Bob's
            // advertisement: she retires her OTK (embed nil) but still cites
            // Bob's OTK id, since he has not retired yet.
            let a2 = try await aliceSend("A2")
            #expect(a2.header.remoteOneTimePublicKey == nil)
            #expect(a2.header.oneTimeKeyId != nil)
            #expect(try await bobReceive(a2) == Data("A2".utf8))

            // Bob adopted Alice's retirement and retires his own key: nothing
            // embedded, nothing cited.
            let b2 = try await bobSend("B2")
            #expect(b2.header.remoteOneTimePublicKey == nil)
            #expect(b2.header.oneTimeKeyId == nil)
            #expect(try await aliceReceive(b2) == Data("B2".utf8))

            // Fully converged: no OTK material in either direction, and the
            // lane keeps working across further host re-initializations.
            let a3 = try await aliceSend("A3")
            #expect(a3.header.remoteOneTimePublicKey == nil)
            #expect(a3.header.oneTimeKeyId == nil)
            #expect(try await bobReceive(a3) == Data("A3".utf8))

            let b3 = try await bobSend("B3")
            #expect(b3.header.remoteOneTimePublicKey == nil)
            #expect(b3.header.oneTimeKeyId == nil)
            #expect(try await aliceReceive(b3) == Data("B3".utf8))

            for round in 0 ..< 5 {
                let a = try await aliceSend("A-extra-\(round)")
                #expect(a.header.remoteOneTimePublicKey == nil)
                #expect(try await bobReceive(a) == Data("A-extra-\(round)".utf8))
                let b = try await bobSend("B-extra-\(round)")
                #expect(b.header.remoteOneTimePublicKey == nil)
                #expect(try await aliceReceive(b) == Data("B-extra-\(round)".utf8))
            }

            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    /// The retirement advertisement is an additive optional: a header without
    /// it (what a 4.0 sender emits — the nil optional is omitted from the
    /// encoding) decodes as nil, and a 4.1 header round-trips the flag.
    @Test
    func testMessageHeaderRetirementFlagWireCompatibility() async throws {
        // 4.0-shaped frame: flag absent from the encoding.
        let legacy = MessageHeader(
            previousChainLength: 3,
            messageNumber: 7,
            ratchetPublicKey: Data(repeating: 1, count: 32),
            ratchetKEMPublicKey: Data(repeating: 2, count: 64),
            ratchetKEMCiphertext: nil,
            supportsOneTimeKeyRetirement: nil)
        let legacyData = try BinaryEncoder().encode(legacy)
        let decodedLegacy = try BinaryDecoder().decode(MessageHeader.self, from: legacyData)
        #expect(decodedLegacy.supportsOneTimeKeyRetirement == nil)
        #expect(decodedLegacy.previousChainLength == 3)
        #expect(decodedLegacy.messageNumber == 7)

        // 4.1 frame round-trips the advertisement.
        let modern = MessageHeader(
            previousChainLength: 1,
            messageNumber: 2,
            ratchetPublicKey: Data(repeating: 3, count: 32),
            ratchetKEMPublicKey: Data(repeating: 4, count: 64),
            ratchetKEMCiphertext: nil,
            supportsOneTimeKeyRetirement: true)
        let modernData = try BinaryEncoder().encode(modern)
        let decodedModern = try BinaryDecoder().decode(MessageHeader.self, from: modernData)
        #expect(decodedModern.supportsOneTimeKeyRetirement == true)
        // The nil-flag encoding must stay smaller: proof the key is omitted,
        // which is exactly what keeps 4.0 decoders compatible.
        #expect(legacyData.count < modernData.count)
    }
}
