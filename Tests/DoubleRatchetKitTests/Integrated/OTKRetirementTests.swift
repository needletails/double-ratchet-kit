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

/// One lane as its two hosts drive it: each side re-initializes the session before every send
/// and every receive.
private struct HostedLane: Sendable {
    let tests: MessageRatchetTests
    let aliceManager: MessageRatchet
    let bobManager: MessageRatchet
    let aliceIdentity: SessionIdentity
    let bobIdentity: SessionIdentity
    let bundle: MessageRatchetTests.KeyBundle

    func aliceSend(_ text: String, localKeys: LocalKeys? = nil) async throws -> RatchetMessage {
        guard let identity = await tests.getSessionIdentity(for: bobIdentity.id) else {
            throw MessageRatchetTests.TestErrors.identityNotFound
        }
        try await aliceManager.initiateSession(
            sessionIdentity: identity,
            sessionSymmetricKey: tests.aliceDbsk,
            remoteKeys: bundle.bobPublic,
            localKeys: localKeys ?? bundle.alicePrivate)
        return try await aliceManager.encrypt(plainText: Data(text.utf8), sessionId: identity.id)
    }

    func bobReceive(_ message: RatchetMessage) async throws -> Data {
        guard let identity = await tests.getSessionIdentity(for: aliceIdentity.id) else {
            throw MessageRatchetTests.TestErrors.identityNotFound
        }
        try await bobManager.respondToSession(
            sessionIdentity: identity,
            sessionSymmetricKey: tests.bobDBSK,
            header: message.header,
            localKeys: bundle.bobPrivate)
        return try await bobManager.decrypt(message, sessionId: identity.id)
    }

    func bobSend(_ text: String) async throws -> RatchetMessage {
        guard let identity = await tests.getSessionIdentity(for: aliceIdentity.id) else {
            throw MessageRatchetTests.TestErrors.identityNotFound
        }
        try await bobManager.initiateSession(
            sessionIdentity: identity,
            sessionSymmetricKey: tests.bobDBSK,
            remoteKeys: bundle.alicePublic,
            localKeys: bundle.bobPrivate)
        return try await bobManager.encrypt(plainText: Data(text.utf8), sessionId: identity.id)
    }

    func aliceReceive(_ message: RatchetMessage, localKeys: LocalKeys? = nil) async throws -> Data {
        guard let identity = await tests.getSessionIdentity(for: bobIdentity.id) else {
            throw MessageRatchetTests.TestErrors.identityNotFound
        }
        try await aliceManager.respondToSession(
            sessionIdentity: identity,
            sessionSymmetricKey: tests.aliceDbsk,
            header: message.header,
            localKeys: localKeys ?? bundle.alicePrivate)
        return try await aliceManager.decrypt(message, sessionId: identity.id)
    }
}

extension MessageRatchetTests {
    private func withHostedLane(_ body: (HostedLane) async throws -> Void) async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)

        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            try await body(HostedLane(
                tests: self,
                aliceManager: aliceManager,
                bobManager: bobManager,
                aliceIdentity: aliceIdentity,
                bobIdentity: bobIdentity,
                bundle: bundle))
            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    /// Two 4.1 peers converge on OTK retirement: after both handshake
    /// directions finish and each side has seen the other's advertisement,
    /// headers stop embedding the bootstrap OTK public half and stop citing
    /// the peer's OTK id — without diverging the chains.
    @Test
    func testOneTimeKeyRetirementConvergence() async throws {
        try await withHostedLane { lane in
            // Bootstrap frame: embeds Alice's OTK and cites Bob's OTK id.
            let a1 = try await lane.aliceSend("A1")
            #expect(a1.header.remoteOneTimePublicKey != nil)
            #expect(a1.header.oneTimeKeyId != nil)
            #expect(try await lane.bobReceive(a1) == Data("A1".utf8))

            // Bob's first reply: his sending handshake is still open at the
            // retirement gate, so he still embeds his OTK and cites Alice's.
            let b1 = try await lane.bobSend("B1")
            #expect(b1.header.remoteOneTimePublicKey != nil)
            #expect(b1.header.oneTimeKeyId != nil)
            #expect(try await lane.aliceReceive(b1) == Data("B1".utf8))

            // Alice has now finished both handshakes and seen Bob's
            // advertisement: she retires her OTK (embed nil) but still cites
            // Bob's OTK id, since he has not retired yet.
            let a2 = try await lane.aliceSend("A2")
            #expect(a2.header.remoteOneTimePublicKey == nil)
            #expect(a2.header.oneTimeKeyId != nil)
            #expect(try await lane.bobReceive(a2) == Data("A2".utf8))

            // Bob adopted Alice's retirement and retires his own key: nothing
            // embedded, nothing cited.
            let b2 = try await lane.bobSend("B2")
            #expect(b2.header.remoteOneTimePublicKey == nil)
            #expect(b2.header.oneTimeKeyId == nil)
            #expect(try await lane.aliceReceive(b2) == Data("B2".utf8))

            // Fully converged: no OTK material in either direction, and the
            // lane keeps working across further host re-initializations.
            let a3 = try await lane.aliceSend("A3")
            #expect(a3.header.remoteOneTimePublicKey == nil)
            #expect(a3.header.oneTimeKeyId == nil)
            #expect(try await lane.bobReceive(a3) == Data("A3".utf8))

            let b3 = try await lane.bobSend("B3")
            #expect(b3.header.remoteOneTimePublicKey == nil)
            #expect(b3.header.oneTimeKeyId == nil)
            #expect(try await lane.aliceReceive(b3) == Data("B3".utf8))

            for round in 0 ..< 5 {
                let a = try await lane.aliceSend("A-extra-\(round)")
                #expect(a.header.remoteOneTimePublicKey == nil)
                #expect(try await lane.bobReceive(a) == Data("A-extra-\(round)".utf8))
                let b = try await lane.bobSend("B-extra-\(round)")
                #expect(b.header.remoteOneTimePublicKey == nil)
                #expect(try await lane.aliceReceive(b) == Data("B-extra-\(round)".utf8))
            }
        }
    }

    /// F3, Alice's first frame after Bob's reply, retires her one-time key and overtakes F2,
    /// which still embeds it. F2 reads as a key change but opens from the old chain's stash.
    /// Committing that epoch left Bob on a root Alice never saw, so his next frame failed on
    /// her with `maxSkippedHeadersExceeded`.
    @Test
    func testFrameOvertakenByOneTimeKeyRetirementKeepsTheLane() async throws {
        try await withHostedLane { lane in
            #expect(try await lane.bobReceive(lane.aliceSend("F1")) == Data("F1".utf8))
            let f2 = try await lane.aliceSend("F2")
            #expect(try await lane.aliceReceive(lane.bobSend("R1")) == Data("R1".utf8))
            let f3 = try await lane.aliceSend("F3")
            #expect(f2.header.remoteOneTimePublicKey != nil)
            #expect(f3.header.remoteOneTimePublicKey == nil)

            #expect(try await lane.bobReceive(f3) == Data("F3".utf8))
            #expect(try await lane.bobReceive(f2) == Data("F2".utf8))

            #expect(try await lane.aliceReceive(lane.bobSend("R2")) == Data("R2".utf8))
            #expect(try await lane.bobReceive(lane.aliceSend("F4")) == Data("F4".utf8))
        }
    }

    /// A genuine epoch overtakes the frame before it. That frame's old keys read as a second
    /// key change and it opens from the epoch's stash of the old chain, but the epoch Bob
    /// already holds is the one that stands.
    @Test
    func testFrameOvertakenByAnEpochKeepsTheEpoch() async throws {
        try await withHostedLane { lane in
            #expect(try await lane.bobReceive(lane.aliceSend("A1")) == Data("A1".utf8))
            let late = try await lane.aliceSend("late")
            let rotated = crypto.generateCurve25519PrivateKey()
            let rotatedKeys = try LocalKeys(
                longTerm: X25519PrivateKey(id: UUID(), rotated.rawRepresentation),
                oneTime: lane.bundle.alicePrivate.oneTime,
                mlKEM: lane.bundle.alicePrivate.mlKEM)
            let epoch = try await lane.aliceSend("epoch", localKeys: rotatedKeys)

            #expect(try await lane.bobReceive(epoch) == Data("epoch".utf8))
            #expect(try await lane.bobReceive(late) == Data("late".utf8))

            let reply = try await lane.bobSend("reply")
            #expect(try await lane.aliceReceive(reply, localKeys: rotatedKeys) == Data("reply".utf8))
            let next = try await lane.aliceSend("next", localKeys: rotatedKeys)
            #expect(try await lane.bobReceive(next) == Data("next".utf8))
        }
    }

    /// A turn leaves index 1 stashed on both chains. F2 consuming its own entry took Y1's too,
    /// because the removal ignored the chain, so Y1 failed.
    @Test
    func testFrameOnTheOldChainLeavesTheNewChainsKey() async throws {
        try await withHostedLane { lane in
            #expect(try await lane.bobReceive(lane.aliceSend("F1")) == Data("F1".utf8))
            let f2 = try await lane.aliceSend("F2")
            #expect(try await lane.aliceReceive(lane.bobSend("R1")) == Data("R1".utf8))
            let y0 = try await lane.aliceSend("Y0")
            let y1 = try await lane.aliceSend("Y1")
            let y2 = try await lane.aliceSend("Y2")

            #expect(try await lane.bobReceive(y0) == Data("Y0".utf8))
            #expect(try await lane.bobReceive(y2) == Data("Y2".utf8))
            #expect(try await lane.bobReceive(f2) == Data("F2".utf8))
            #expect(try await lane.bobReceive(y1) == Data("Y1".utf8))
        }
    }

    /// F2 opens from the old chain's stash after Y0 moved the row on. Marking its index on Y
    /// stopped Y2's gap stashing index 1, so Y1 failed.
    @Test
    func testFrameOnTheOldChainDoesNotHideTheNewChainsKey() async throws {
        try await withHostedLane { lane in
            #expect(try await lane.bobReceive(lane.aliceSend("F1")) == Data("F1".utf8))
            let f2 = try await lane.aliceSend("F2")
            #expect(try await lane.aliceReceive(lane.bobSend("R1")) == Data("R1".utf8))
            let y0 = try await lane.aliceSend("Y0")
            let y1 = try await lane.aliceSend("Y1")
            let y2 = try await lane.aliceSend("Y2")

            #expect(try await lane.bobReceive(y0) == Data("Y0".utf8))
            #expect(try await lane.bobReceive(f2) == Data("F2".utf8))
            #expect(try await lane.bobReceive(y2) == Data("Y2".utf8))
            #expect(try await lane.bobReceive(y1) == Data("Y1".utf8))
        }
    }

    /// The same mark across a rotation: the frame from before the epoch hid E1's key.
    @Test
    func testFrameFromBeforeAnEpochDoesNotHideTheEpochsKey() async throws {
        try await withHostedLane { lane in
            #expect(try await lane.bobReceive(lane.aliceSend("A1")) == Data("A1".utf8))
            let late = try await lane.aliceSend("late")
            let rotated = crypto.generateCurve25519PrivateKey()
            let rotatedKeys = try LocalKeys(
                longTerm: X25519PrivateKey(id: UUID(), rotated.rawRepresentation),
                oneTime: lane.bundle.alicePrivate.oneTime,
                mlKEM: lane.bundle.alicePrivate.mlKEM)
            let e0 = try await lane.aliceSend("E0", localKeys: rotatedKeys)
            let e1 = try await lane.aliceSend("E1", localKeys: rotatedKeys)
            let e2 = try await lane.aliceSend("E2", localKeys: rotatedKeys)

            #expect(try await lane.bobReceive(e0) == Data("E0".utf8))
            #expect(try await lane.bobReceive(late) == Data("late".utf8))
            #expect(try await lane.bobReceive(e2) == Data("E2".utf8))
            #expect(try await lane.bobReceive(e1) == Data("E1".utf8))
        }
    }

    /// The late frame opens its header from the epoch's scan, which adds every key before it
    /// to the stash and trims the front. The row kept that working stash, so E1 to E4 lost
    /// their header keys and failed with `maxSkippedHeadersExceeded`.
    @Test
    func testFrameAcrossAnEpochKeepsTheRowsHeaderStash() async throws {
        try await withHostedLane { lane in
            for index in 0 ..< 94 {
                let frame = try await lane.aliceSend("old \(index)")
                #expect(try await lane.bobReceive(frame) == Data("old \(index)".utf8))
            }
            let late = try await lane.aliceSend("late")
            let rotated = crypto.generateCurve25519PrivateKey()
            let rotatedKeys = try LocalKeys(
                longTerm: X25519PrivateKey(id: UUID(), rotated.rawRepresentation),
                oneTime: lane.bundle.alicePrivate.oneTime,
                mlKEM: lane.bundle.alicePrivate.mlKEM)
            var epoch: [RatchetMessage] = []
            for index in 0 ... 11 {
                try await epoch.append(lane.aliceSend("E\(index)", localKeys: rotatedKeys))
            }

            #expect(try await lane.bobReceive(epoch[0]) == Data("E0".utf8))
            #expect(try await lane.bobReceive(epoch[11]) == Data("E11".utf8))
            #expect(try await lane.bobReceive(late) == Data("late".utf8))
            for index in 1 ... 10 {
                #expect(try await lane.bobReceive(epoch[index]) == Data("E\(index)".utf8))
            }
        }
    }

    /// A lane with no one-time key takes one in a genuine epoch, then a frame from before it
    /// arrives with none. That reads as the peer retiring the key, but the frame opens from the
    /// stash, so it is older than the row and the key stands. Adopting the nil left E1 reading
    /// as a key change and Bob's reply failed on Alice.
    @Test
    func testFrameOvertakenByANewOneTimeKeyKeepsTheKey() async throws {
        try await withHostedLane { lane in
            let alice = lane.bundle.alicePrivate
            let noOneTimeKey = LocalKeys(longTerm: alice.longTerm, oneTime: nil, mlKEM: alice.mlKEM)
            let n0 = try await lane.aliceSend("N0", localKeys: noOneTimeKey)
            let n1 = try await lane.aliceSend("N1", localKeys: noOneTimeKey)
            let n2 = try await lane.aliceSend("N2", localKeys: noOneTimeKey)
            let e0 = try await lane.aliceSend("E0", localKeys: alice)
            let e1 = try await lane.aliceSend("E1", localKeys: alice)
            #expect(n1.header.remoteOneTimePublicKey == nil)
            #expect(e0.header.remoteOneTimePublicKey != nil)

            #expect(try await lane.bobReceive(n0) == Data("N0".utf8))
            #expect(try await lane.bobReceive(n2) == Data("N2".utf8))
            #expect(try await lane.bobReceive(e0) == Data("E0".utf8))
            #expect(try await lane.bobReceive(n1) == Data("N1".utf8))
            #expect(try await lane.bobReceive(e1) == Data("E1".utf8))

            #expect(try await lane.aliceReceive(lane.bobSend("R")) == Data("R".utf8))
            #expect(try await lane.bobReceive(lane.aliceSend("A")) == Data("A".utf8))
        }
    }

    /// A sender epoch keeps its ratchet key, so the epoch's tail of the old chain shares the new
    /// chain's tag. E2's gap found the tail entry at index 1 and stashed nothing, so E1 failed.
    @Test
    func testEpochFramesOutOfOrderKeepTheirKeys() async throws {
        try await withHostedLane { lane in
            #expect(try await lane.bobReceive(lane.aliceSend("A0")) == Data("A0".utf8))
            let rotated = crypto.generateCurve25519PrivateKey()
            let rotatedKeys = try LocalKeys(
                longTerm: X25519PrivateKey(id: UUID(), rotated.rawRepresentation),
                oneTime: lane.bundle.alicePrivate.oneTime,
                mlKEM: lane.bundle.alicePrivate.mlKEM)
            let e0 = try await lane.aliceSend("E0", localKeys: rotatedKeys)
            let e1 = try await lane.aliceSend("E1", localKeys: rotatedKeys)
            let e2 = try await lane.aliceSend("E2", localKeys: rotatedKeys)

            #expect(try await lane.bobReceive(e0) == Data("E0".utf8))
            #expect(try await lane.bobReceive(e2) == Data("E2".utf8))
            #expect(try await lane.bobReceive(e1) == Data("E1".utf8))
        }
    }

    /// The same collision when a turn stashes the epoch chain's tail: E1 is left behind.
    @Test
    func testEpochFrameLeftBehindByATurnKeepsItsKey() async throws {
        try await withHostedLane { lane in
            #expect(try await lane.bobReceive(lane.aliceSend("A0")) == Data("A0".utf8))
            let rotated = crypto.generateCurve25519PrivateKey()
            let rotatedKeys = try LocalKeys(
                longTerm: X25519PrivateKey(id: UUID(), rotated.rawRepresentation),
                oneTime: lane.bundle.alicePrivate.oneTime,
                mlKEM: lane.bundle.alicePrivate.mlKEM)
            let e0 = try await lane.aliceSend("E0", localKeys: rotatedKeys)
            let e1 = try await lane.aliceSend("E1", localKeys: rotatedKeys)

            #expect(try await lane.bobReceive(e0) == Data("E0".utf8))
            #expect(try await lane.aliceReceive(lane.bobSend("R"), localKeys: rotatedKeys) == Data("R".utf8))
            #expect(try await lane.bobReceive(lane.aliceSend("Z0", localKeys: rotatedKeys)) == Data("Z0".utf8))
            #expect(try await lane.bobReceive(e1) == Data("E1".utf8))
        }
    }

    /// The same collision when a second epoch stashes the first one's tail: E1 is left behind.
    @Test
    func testEpochFrameLeftBehindByAnEpochKeepsItsKey() async throws {
        try await withHostedLane { lane in
            #expect(try await lane.bobReceive(lane.aliceSend("A0")) == Data("A0".utf8))
            let first = crypto.generateCurve25519PrivateKey()
            let firstKeys = try LocalKeys(
                longTerm: X25519PrivateKey(id: UUID(), first.rawRepresentation),
                oneTime: lane.bundle.alicePrivate.oneTime,
                mlKEM: lane.bundle.alicePrivate.mlKEM)
            let second = crypto.generateCurve25519PrivateKey()
            let secondKeys = try LocalKeys(
                longTerm: X25519PrivateKey(id: UUID(), second.rawRepresentation),
                oneTime: lane.bundle.alicePrivate.oneTime,
                mlKEM: lane.bundle.alicePrivate.mlKEM)
            let e0 = try await lane.aliceSend("E0", localKeys: firstKeys)
            let e1 = try await lane.aliceSend("E1", localKeys: firstKeys)
            let g0 = try await lane.aliceSend("G0", localKeys: secondKeys)

            #expect(try await lane.bobReceive(e0) == Data("E0".utf8))
            #expect(try await lane.bobReceive(g0) == Data("G0".utf8))
            #expect(try await lane.bobReceive(e1) == Data("E1".utf8))
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
