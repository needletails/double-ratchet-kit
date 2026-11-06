//
//  RotationInFlightTests.swift
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

/// One lane as its two hosts drive it, with the keys each host supplies on every call, so a
/// test can rotate either side and hand the peer the public half its directory would.
private struct KeyedLane: Sendable {
    let tests: MessageRatchetTests
    let aliceManager: MessageRatchet
    let bobManager: MessageRatchet
    let aliceIdentity: SessionIdentity
    let bobIdentity: SessionIdentity
    let bundle: MessageRatchetTests.KeyBundle

    func aliceSend(_ text: String, localKeys: LocalKeys? = nil, remoteKeys: RemoteKeys? = nil) async throws -> RatchetMessage {
        guard let identity = await tests.getSessionIdentity(for: bobIdentity.id) else {
            throw MessageRatchetTests.TestErrors.identityNotFound
        }
        try await aliceManager.initiateSession(
            sessionIdentity: identity,
            sessionSymmetricKey: tests.aliceDbsk,
            remoteKeys: remoteKeys ?? bundle.bobPublic,
            localKeys: localKeys ?? bundle.alicePrivate)
        return try await aliceManager.encrypt(plainText: Data(text.utf8), sessionId: identity.id)
    }

    func bobReceive(_ message: RatchetMessage, localKeys: LocalKeys? = nil) async throws -> Data {
        guard let identity = await tests.getSessionIdentity(for: aliceIdentity.id) else {
            throw MessageRatchetTests.TestErrors.identityNotFound
        }
        try await bobManager.respondToSession(
            sessionIdentity: identity,
            sessionSymmetricKey: tests.bobDBSK,
            header: message.header,
            localKeys: localKeys ?? bundle.bobPrivate)
        return try await bobManager.decrypt(message, sessionId: identity.id)
    }

    func bobSend(_ text: String, localKeys: LocalKeys? = nil, remoteKeys: RemoteKeys? = nil) async throws -> RatchetMessage {
        guard let identity = await tests.getSessionIdentity(for: aliceIdentity.id) else {
            throw MessageRatchetTests.TestErrors.identityNotFound
        }
        try await bobManager.initiateSession(
            sessionIdentity: identity,
            sessionSymmetricKey: tests.bobDBSK,
            remoteKeys: remoteKeys ?? bundle.alicePublic,
            localKeys: localKeys ?? bundle.bobPrivate)
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
    private func withKeyedLane(_ body: (KeyedLane) async throws -> Void) async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)

        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            try await body(KeyedLane(
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

    /// Runs one delivery and names it if it fails.
    private func step(_ name: String, expecting text: String, _ body: () async throws -> Data) async throws {
        do {
            let plaintext = try await body()
            #expect(plaintext == Data(text.utf8), Comment(rawValue: name))
        } catch {
            Issue.record("\(name): \(error)")
            throw error
        }
    }

    /// A rotated long-term key and the public half the peer's directory would hand out.
    private func rotatedLongTerm(from keys: LocalKeys, publicBundle: RemoteKeys) throws -> (LocalKeys, RemoteKeys) {
        let longTerm = crypto.generateCurve25519PrivateKey()
        let id = UUID()
        let local = try LocalKeys(
            longTerm: X25519PrivateKey(id: id, longTerm.rawRepresentation),
            oneTime: keys.oneTime,
            mlKEM: keys.mlKEM)
        let remote = try RemoteKeys(
            longTerm: X25519PublicKey(id: id, longTerm.publicKey.rawRepresentation),
            oneTime: publicBundle.oneTime,
            mlKEM: publicBundle.mlKEM)
        return (local, remote)
    }

    /// Both handshakes finished in both directions, so each side has retired its one-time key.
    private func establish(_ lane: KeyedLane) async throws {
        try await step("A1", expecting: "A1") { try await lane.bobReceive(lane.aliceSend("A1")) }
        try await step("B1", expecting: "B1") { try await lane.aliceReceive(lane.bobSend("B1")) }
        try await step("A2", expecting: "A2") { try await lane.bobReceive(lane.aliceSend("A2")) }
        try await step("B2", expecting: "B2") { try await lane.aliceReceive(lane.bobSend("B2")) }
    }

    /// Bob's rotation epoch E0 overtakes his chain frame B3. B3's header key is on the old header
    /// chain, which the epoch dropped; re-deriving that chain from B3's bootstrap ciphertext no
    /// longer works once Alice's one-time key is retired, so B3 failed with
    /// `maxSkippedHeadersExceeded`. Every epoch now stashes the old header chain's next keys.
    @Test
    func testStaleFrameOvertakenByThePeersRotationOpens() async throws {
        try await withKeyedLane { lane in
            try await establish(lane)
            let stale = try await lane.bobSend("B3")

            let (bobRotated, bobCurrent) = try rotatedLongTerm(from: lane.bundle.bobPrivate, publicBundle: lane.bundle.bobPublic)
            let epoch = try await lane.bobSend("E0", localKeys: bobRotated)
            try await step("E0, Bob's rotation epoch", expecting: "E0") { try await lane.aliceReceive(epoch) }

            try await step("B3, overtaken by E0", expecting: "B3") { try await lane.aliceReceive(stale) }
            try await step("A3", expecting: "A3") {
                try await lane.bobReceive(lane.aliceSend("A3", remoteKeys: bobCurrent), localKeys: bobRotated)
            }
            try await step("B4", expecting: "B4") {
                try await lane.aliceReceive(lane.bobSend("B4", localKeys: bobRotated))
            }
        }
    }

    /// The same with Alice rotated as well, so the stale frame is the first inbound her rotated
    /// row sees and it reads as a key change: the 4.2.0 notes' first known issue.
    @Test
    func testStaleFrameOvertakenByThePeersRotationOpensOnOurRotatedRow() async throws {
        try await withKeyedLane { lane in
            try await establish(lane)
            let stale = try await lane.bobSend("B3")

            let (bobRotated, bobCurrent) = try rotatedLongTerm(from: lane.bundle.bobPrivate, publicBundle: lane.bundle.bobPublic)
            let epoch = try await lane.bobSend("E0", localKeys: bobRotated)
            try await step("E0, Bob's rotation epoch", expecting: "E0") { try await lane.aliceReceive(epoch) }

            let (aliceRotated, aliceCurrent) = try rotatedLongTerm(from: lane.bundle.alicePrivate, publicBundle: lane.bundle.alicePublic)
            try await step("B3, first inbound to Alice's rotated row", expecting: "B3") {
                try await lane.aliceReceive(stale, localKeys: aliceRotated)
            }
            try await step("A3, Alice's rotation epoch", expecting: "A3") {
                try await lane.bobReceive(lane.aliceSend("A3", localKeys: aliceRotated, remoteKeys: bobCurrent), localKeys: bobRotated)
            }
            try await step("B4", expecting: "B4") {
                try await lane.aliceReceive(lane.bobSend("B4", localKeys: bobRotated, remoteKeys: aliceCurrent), localKeys: aliceRotated)
            }
            try await step("A4", expecting: "A4") {
                try await lane.bobReceive(lane.aliceSend("A4", localKeys: aliceRotated, remoteKeys: bobCurrent), localKeys: bobRotated)
            }
        }
    }

    /// Our own rotation epoch with a peer frame in flight: the peer sent it before seeing the
    /// epoch, on the header chain the epoch left. It opens from the stash like a frame the
    /// peer's own epoch overtook.
    @Test
    func testStaleFrameAcrossOurOwnRotationOpens() async throws {
        try await withKeyedLane { lane in
            try await establish(lane)
            let stale = try await lane.bobSend("B3")

            let (aliceRotated, aliceCurrent) = try rotatedLongTerm(from: lane.bundle.alicePrivate, publicBundle: lane.bundle.alicePublic)
            try await step("E0, Alice's rotation epoch", expecting: "E0") {
                try await lane.bobReceive(lane.aliceSend("E0", localKeys: aliceRotated))
            }
            try await step("B3, sent before Bob saw E0", expecting: "B3") {
                try await lane.aliceReceive(stale, localKeys: aliceRotated)
            }
            try await step("B4, Bob's first frame after E0", expecting: "B4") {
                try await lane.aliceReceive(lane.bobSend("B4", remoteKeys: aliceCurrent), localKeys: aliceRotated)
            }
            try await step("A3", expecting: "A3") {
                try await lane.bobReceive(lane.aliceSend("A3", localKeys: aliceRotated))
            }
        }
    }

    /// Bob's B2 was a turn, so Alice's A3 opens a new chain; her rotation epoch E0 follows it and
    /// overtakes it. The sender stepped first and ran the epoch on the stepped root; the receiver
    /// ran the epoch first and failed E0's payload until A3 had landed. It now mirrors the
    /// sender's order.
    @Test
    func testEpochOvertakingOurOwnTurnFrameOpens() async throws {
        try await withKeyedLane { lane in
            try await establish(lane)
            let turn = try await lane.aliceSend("A3")

            let (aliceRotated, aliceCurrent) = try rotatedLongTerm(from: lane.bundle.alicePrivate, publicBundle: lane.bundle.alicePublic)
            let epoch = try await lane.aliceSend("E0", localKeys: aliceRotated)
            try await step("E0, the epoch, ahead of the turn frame", expecting: "E0") { try await lane.bobReceive(epoch) }
            try await step("A3, the turn frame, late", expecting: "A3") { try await lane.bobReceive(turn) }
            try await step("E1", expecting: "E1") {
                try await lane.bobReceive(lane.aliceSend("E1", localKeys: aliceRotated))
            }
            try await step("B3", expecting: "B3") {
                try await lane.aliceReceive(lane.bobSend("B3", remoteKeys: aliceCurrent), localKeys: aliceRotated)
            }
            try await step("A4", expecting: "A4") {
                try await lane.bobReceive(lane.aliceSend("A4", localKeys: aliceRotated))
            }
        }
    }

    /// The same, with a frame of the chain before the turn still in flight too. The retried
    /// order must stash that chain's tail as the first order did, or the frame is lost.
    @Test
    func testEpochOvertakingOurOwnTurnFrameKeepsTheEarlierChainsTail() async throws {
        try await withKeyedLane { lane in
            try await step("A1", expecting: "A1") { try await lane.bobReceive(lane.aliceSend("A1")) }
            try await step("B1", expecting: "B1") { try await lane.aliceReceive(lane.bobSend("B1")) }
            try await step("A2", expecting: "A2") { try await lane.bobReceive(lane.aliceSend("A2")) }
            let onOldChain = try await lane.aliceSend("A2'")
            try await step("B2", expecting: "B2") { try await lane.aliceReceive(lane.bobSend("B2")) }
            let turn = try await lane.aliceSend("A3")

            let (aliceRotated, aliceCurrent) = try rotatedLongTerm(from: lane.bundle.alicePrivate, publicBundle: lane.bundle.alicePublic)
            let epoch = try await lane.aliceSend("E0", localKeys: aliceRotated)
            try await step("E0, the epoch, ahead of both", expecting: "E0") { try await lane.bobReceive(epoch) }
            try await step("A2', from the chain before the turn", expecting: "A2'") { try await lane.bobReceive(onOldChain) }
            try await step("A3, the turn frame", expecting: "A3") { try await lane.bobReceive(turn) }
            try await step("B3", expecting: "B3") {
                try await lane.aliceReceive(lane.bobSend("B3", remoteKeys: aliceCurrent), localKeys: aliceRotated)
            }
            try await step("A4", expecting: "A4") {
                try await lane.bobReceive(lane.aliceSend("A4", localKeys: aliceRotated))
            }
        }
    }

    /// The same, with the epoch's second frame landing before its first. The scan that opens
    /// E1 passes E0's header key; the retried order must keep it.
    @Test
    func testEpochOvertakingOurOwnTurnFrameKeepsTheScannedHeaderKeys() async throws {
        try await withKeyedLane { lane in
            try await establish(lane)
            let turn = try await lane.aliceSend("A3")

            let (aliceRotated, aliceCurrent) = try rotatedLongTerm(from: lane.bundle.alicePrivate, publicBundle: lane.bundle.alicePublic)
            let first = try await lane.aliceSend("E0", localKeys: aliceRotated)
            let second = try await lane.aliceSend("E1", localKeys: aliceRotated)
            try await step("E1, the epoch's second frame, first", expecting: "E1") { try await lane.bobReceive(second) }
            try await step("E0, the epoch's first frame", expecting: "E0") { try await lane.bobReceive(first) }
            try await step("A3, the turn frame", expecting: "A3") { try await lane.bobReceive(turn) }
            try await step("B3", expecting: "B3") {
                try await lane.aliceReceive(lane.bobSend("B3", remoteKeys: aliceCurrent), localKeys: aliceRotated)
            }
            try await step("A4", expecting: "A4") {
                try await lane.bobReceive(lane.aliceSend("A4", localKeys: aliceRotated))
            }
        }
    }

    /// Bob's retirement frame B2 (no one-time key) overtakes his first reply B1 on Alice's row,
    /// whose receiving handshake is still unfinished. The nil read as a key change and the
    /// speculative epoch failed the frame; it is a retirement, adopted once the bootstrap PQXDH,
    /// which needs the held key, has opened the frame.
    @Test
    func testRetirementFrameOvertakingTheFirstReplyOpens() async throws {
        try await withKeyedLane { lane in
            try await step("A1", expecting: "A1") { try await lane.bobReceive(lane.aliceSend("A1")) }
            let reply = try await lane.bobSend("B1")
            let retirement = try await lane.bobSend("B2")
            #expect(reply.header.remoteOneTimePublicKey != nil)
            #expect(retirement.header.remoteOneTimePublicKey == nil)

            try await step("B2, the retirement frame, first", expecting: "B2") { try await lane.aliceReceive(retirement) }
            try await step("B1, the first reply, late", expecting: "B1") { try await lane.aliceReceive(reply) }
            let a2 = try await lane.aliceSend("A2")
            #expect(a2.header.oneTimeKeyId == nil, "Alice adopted Bob's retirement and stops citing his key")
            try await step("A2", expecting: "A2") { try await lane.bobReceive(a2) }
            try await step("B3", expecting: "B3") { try await lane.aliceReceive(lane.bobSend("B3")) }
        }
    }

    /// Rotation before the initiator has heard anything: the 4.2.0 notes' second known issue. The
    /// receive load wrote the host's rotated key into the row because its handshake was unfinished,
    /// so the header PQXDH for Bob's first reply ran with a key he never saw and failed with
    /// `maxSkippedHeadersExceeded`. The row now keeps the keys it sent with until a frame changes
    /// a remote key; the rotation reaches Bob through Alice's next send.
    @Test
    func testRotationBeforeTheInitiatorHasHeardAnythingOpensTheFirstReply() async throws {
        try await withKeyedLane { lane in
            try await step("A1", expecting: "A1") { try await lane.bobReceive(lane.aliceSend("A1")) }
            let (aliceRotated, aliceCurrent) = try rotatedLongTerm(from: lane.bundle.alicePrivate, publicBundle: lane.bundle.alicePublic)

            let reply = try await lane.bobSend("B1")
            try await step("B1, Bob's first reply", expecting: "B1") {
                try await lane.aliceReceive(reply, localKeys: aliceRotated)
            }
            try await step("A2, Alice's rotation epoch", expecting: "A2") {
                try await lane.bobReceive(lane.aliceSend("A2", localKeys: aliceRotated))
            }
            try await step("B2", expecting: "B2") {
                try await lane.aliceReceive(lane.bobSend("B2", remoteKeys: aliceCurrent), localKeys: aliceRotated)
            }
        }
    }

    /// The rotation reaches Bob as Alice's epoch before he replies. This always worked and pins the
    /// path hosts take when they send a refresh frame after rotating.
    @Test
    func testRotationBeforeTheInitiatorHasHeardAnythingAfterHerOwnEpoch() async throws {
        try await withKeyedLane { lane in
            try await step("A1", expecting: "A1") { try await lane.bobReceive(lane.aliceSend("A1")) }
            let (aliceRotated, aliceCurrent) = try rotatedLongTerm(from: lane.bundle.alicePrivate, publicBundle: lane.bundle.alicePublic)

            try await step("A2, Alice's rotation epoch", expecting: "A2") { try await lane.bobReceive(lane.aliceSend("A2", localKeys: aliceRotated)) }
            try await step("B1", expecting: "B1") {
                try await lane.aliceReceive(lane.bobSend("B1", remoteKeys: aliceCurrent), localKeys: aliceRotated)
            }
            try await step("A3", expecting: "A3") { try await lane.bobReceive(lane.aliceSend("A3", localKeys: aliceRotated)) }
        }
    }
}
