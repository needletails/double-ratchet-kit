//
//  StashBoundsTests.swift
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

/// One lane as its two hosts drive it, with the keys each host supplies on every call, and a
/// view of the row's stashes.
private struct StashLane: Sendable {
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

    /// Alice's row for Bob.
    func aliceRow() async -> RatchetState? {
        guard let identity = await tests.getSessionIdentity(for: bobIdentity.id) else { return nil }
        return await identity.props(symmetricKey: tests.aliceDbsk)?.state
    }

    /// Bob's row for Alice.
    func bobRow() async -> RatchetState? {
        guard let identity = await tests.getSessionIdentity(for: aliceIdentity.id) else { return nil }
        return await identity.props(symmetricKey: tests.bobDBSK)?.state
    }
}

extension MessageRatchetTests {
    private func withStashLane(_ body: (StashLane) async throws -> Void) async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)

        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            try await body(StashLane(
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
    private func stashStep(_ name: String, expecting text: String, _ body: () async throws -> Data) async throws {
        do {
            let plaintext = try await body()
            #expect(plaintext == Data(text.utf8), Comment(rawValue: name))
        } catch {
            Issue.record("\(name): \(error)")
            throw error
        }
    }

    /// A rotated long-term key and the public half the peer's directory would hand out.
    private func stashRotatedLongTerm(from keys: LocalKeys, publicBundle: RemoteKeys) throws -> (LocalKeys, RemoteKeys) {
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
    private func stashEstablish(_ lane: StashLane) async throws {
        try await stashStep("A1", expecting: "A1") { try await lane.bobReceive(lane.aliceSend("A1")) }
        try await stashStep("B1", expecting: "B1") { try await lane.aliceReceive(lane.bobSend("B1")) }
        try await stashStep("A2", expecting: "A2") { try await lane.bobReceive(lane.aliceSend("A2")) }
        try await stashStep("B2", expecting: "B2") { try await lane.aliceReceive(lane.bobSend("B2")) }
    }

    /// A gap of 68 frames on Bob's row, then Alice's rotation epoch overtakes two more. The row
    /// then holds exactly `maxSkippedMessageKeys` header keys: 68 for the gap, 32 for the epoch's
    /// tail. Each stale frame reads as a key change (its header carries Alice's old long-term
    /// key); its header has to open from the row's stash before any epoch is speculated, or the
    /// speculation's own 32-key stash evicts the gap's oldest keys and they are lost.
    @Test
    func testGapAndPeerEpochKeepEveryStashedFrame() async throws {
        try await withStashLane { lane in
            try await stashEstablish(lane)

            var gap: [RatchetMessage] = []
            for index in 0 ..< 68 {
                try await gap.append(lane.aliceSend("F\(index)"))
            }
            try await stashStep("F68 opens the gap", expecting: "F68") { try await lane.bobReceive(lane.aliceSend("F68")) }
            let overtaken = [try await lane.aliceSend("T0"), try await lane.aliceSend("T1")]

            let (aliceRotated, aliceCurrent) = try stashRotatedLongTerm(from: lane.bundle.alicePrivate, publicBundle: lane.bundle.alicePublic)
            try await stashStep("E0, Alice's rotation epoch", expecting: "E0") {
                try await lane.bobReceive(lane.aliceSend("E0", localKeys: aliceRotated))
            }
            let row = await lane.bobRow()
            #expect(row?.skippedHeaderMessages.count == 100, "68 gap keys plus the epoch's 32-key tail")
            #expect(row?.skippedMessageKeys.count == 100)

            try await stashStep("T0, overtaken by E0", expecting: "T0") { try await lane.bobReceive(overtaken[0]) }
            try await stashStep("T1, overtaken by E0", expecting: "T1") { try await lane.bobReceive(overtaken[1]) }
            for (index, frame) in gap.enumerated() {
                try await stashStep("F\(index) from the gap", expecting: "F\(index)") { try await lane.bobReceive(frame) }
            }
            #expect(await lane.bobRow()?.skippedHeaderMessages.count == 30, "the tail keys no frame used remain")

            try await stashStep("B3", expecting: "B3") {
                try await lane.aliceReceive(lane.bobSend("B3", remoteKeys: aliceCurrent), localKeys: aliceRotated)
            }
            try await stashStep("A3", expecting: "A3") {
                try await lane.bobReceive(lane.aliceSend("A3", localKeys: aliceRotated))
            }
        }
    }

    /// The newest stale frame lands first. Opening it must take only its own key out of the
    /// row's stash; the rollback used to intersect the row's stash with a working copy the
    /// speculative epoch had trimmed, which dropped the oldest frame's key as well.
    @Test
    func testNewestStaleFrameFirstKeepsTheOldestFramesKey() async throws {
        try await withStashLane { lane in
            try await stashEstablish(lane)

            var gap: [RatchetMessage] = []
            for index in 0 ..< 37 {
                try await gap.append(lane.aliceSend("F\(index)"))
            }
            try await stashStep("F37 opens the gap", expecting: "F37") { try await lane.bobReceive(lane.aliceSend("F37")) }

            let (aliceRotated, _) = try stashRotatedLongTerm(from: lane.bundle.alicePrivate, publicBundle: lane.bundle.alicePublic)
            try await stashStep("E0, Alice's rotation epoch", expecting: "E0") {
                try await lane.bobReceive(lane.aliceSend("E0", localKeys: aliceRotated))
            }
            #expect(await lane.bobRow()?.skippedHeaderMessages.count == 69)

            try await stashStep("F36, newest of the gap", expecting: "F36") { try await lane.bobReceive(gap[36]) }
            #expect(await lane.bobRow()?.skippedHeaderMessages.count == 68, "only F36's key leaves the stash")
            try await stashStep("F0, oldest of the gap", expecting: "F0") { try await lane.bobReceive(gap[0]) }
        }
    }

    /// A frame overtaken by three peer rotations. Its keys sit in the first epoch's tail, the
    /// oldest 32 of the 96 the row holds; speculating an epoch for it would have pushed 28 of
    /// them out before the lookup.
    @Test
    func testFrameOvertakenByThreePeerEpochsOpens() async throws {
        try await withStashLane { lane in
            try await stashEstablish(lane)
            var bobKeys = lane.bundle.bobPrivate
            var bobCurrent = lane.bundle.bobPublic

            let overtaken = try await lane.bobSend("F")
            for round in 0 ..< 3 {
                (bobKeys, bobCurrent) = try stashRotatedLongTerm(from: bobKeys, publicBundle: bobCurrent)
                try await stashStep("E\(round), Bob's rotation epoch", expecting: "E\(round)") {
                    try await lane.aliceReceive(lane.bobSend("E\(round)", localKeys: bobKeys))
                }
                try await stashStep("A after E\(round)", expecting: "A\(round)") {
                    try await lane.bobReceive(lane.aliceSend("A\(round)", remoteKeys: bobCurrent), localKeys: bobKeys)
                }
            }
            let row = await lane.aliceRow()
            #expect(row?.skippedHeaderMessages.count == 96)
            #expect(row?.skippedMessageKeys.count == 96)

            try await stashStep("F, overtaken by three epochs", expecting: "F") { try await lane.aliceReceive(overtaken) }
            try await stashStep("B next", expecting: "Bn") {
                try await lane.aliceReceive(lane.bobSend("Bn", localKeys: bobKeys))
            }
        }
    }

    /// Four rotations with nothing in flight each left a 32-key tail that no frame would ever
    /// claim, filling the stash, so the fifth rotation's tail was not stashed at all and the one
    /// frame it overtook was lost. The tail is now stashed whole and the oldest keys make room.
    @Test
    func testRepeatedPeerRotationsKeepTheEpochTail() async throws {
        try await withStashLane { lane in
            try await stashEstablish(lane)
            var bobKeys = lane.bundle.bobPrivate
            var bobCurrent = lane.bundle.bobPublic

            for round in 0 ..< 4 {
                (bobKeys, bobCurrent) = try stashRotatedLongTerm(from: bobKeys, publicBundle: bobCurrent)
                try await stashStep("E\(round), Bob's rotation epoch", expecting: "E\(round)") {
                    try await lane.aliceReceive(lane.bobSend("E\(round)", localKeys: bobKeys))
                }
                try await stashStep("A after E\(round)", expecting: "A\(round)") {
                    try await lane.bobReceive(lane.aliceSend("A\(round)", remoteKeys: bobCurrent), localKeys: bobKeys)
                }
                try await stashStep("B after E\(round)", expecting: "B\(round)") {
                    try await lane.aliceReceive(lane.bobSend("B\(round)", localKeys: bobKeys))
                }
            }
            #expect(await lane.aliceRow()?.skippedMessageKeys.count == 100, "four unclaimed tails fill the stash")

            let overtaken = try await lane.bobSend("F", localKeys: bobKeys)
            (bobKeys, bobCurrent) = try stashRotatedLongTerm(from: bobKeys, publicBundle: bobCurrent)
            try await stashStep("E4, Bob's fifth rotation", expecting: "E4") {
                try await lane.aliceReceive(lane.bobSend("E4", localKeys: bobKeys))
            }
            let afterFifth = await lane.aliceRow()
            #expect(afterFifth?.skippedMessageKeys.count == 100)
            #expect(afterFifth?.skippedHeaderMessages.count == 100, "five 32-key header tails trimmed to the cap")
            try await stashStep("F, overtaken by E4", expecting: "F") { try await lane.aliceReceive(overtaken) }
            try await stashStep("A5", expecting: "A5") {
                try await lane.bobReceive(lane.aliceSend("A5", remoteKeys: bobCurrent), localKeys: bobKeys)
            }
        }
    }

    /// Ninety keys of a gap that never closed used to leave room for ten of the twelve frames
    /// a rotation overtook. The documented 32-frame window has to hold whatever the stash
    /// already carries.
    @Test
    func testUnclaimedGapKeysDoNotShrinkTheEpochTail() async throws {
        try await withStashLane { lane in
            try await stashEstablish(lane)

            for _ in 0 ..< 90 { _ = try await lane.bobSend("lost") }
            try await stashStep("B91 opens a gap of 90", expecting: "B91") { try await lane.aliceReceive(lane.bobSend("B91")) }
            #expect(await lane.aliceRow()?.skippedMessageKeys.count == 90)

            var inFlight: [RatchetMessage] = []
            for index in 0 ..< 12 {
                try await inFlight.append(lane.bobSend("I\(index)"))
            }
            let (bobRotated, bobCurrent) = try stashRotatedLongTerm(from: lane.bundle.bobPrivate, publicBundle: lane.bundle.bobPublic)
            try await stashStep("E0, Bob's rotation epoch", expecting: "E0") {
                try await lane.aliceReceive(lane.bobSend("E0", localKeys: bobRotated))
            }
            #expect(await lane.aliceRow()?.skippedMessageKeys.count == 100, "the oldest gap keys made room for the tail")

            for (index, frame) in inFlight.enumerated() {
                try await stashStep("I\(index), overtaken by E0", expecting: "I\(index)") { try await lane.aliceReceive(frame) }
            }
            try await stashStep("A3", expecting: "A3") {
                try await lane.bobReceive(lane.aliceSend("A3", remoteKeys: bobCurrent), localKeys: bobRotated)
            }
        }
    }

    /// Gaps that never close used to grow the message-key stash without bound (and with it the
    /// persisted row). It is now capped like the header stash, and the lane keeps delivering.
    @Test
    func testMessageKeyStashStaysBounded() async throws {
        try await withStashLane { lane in
            try await stashEstablish(lane)
            for round in 0 ..< 3 {
                for _ in 0 ..< 60 { _ = try await lane.bobSend("lost") }
                try await stashStep("gap \(round) closes", expecting: "G\(round)") { try await lane.aliceReceive(lane.bobSend("G\(round)")) }
                let count = await lane.aliceRow()?.skippedMessageKeys.count ?? -1
                #expect(count <= testableRatchetConfiguration.maxSkippedMessageKeys, "stash holds \(count) after gap \(round)")
            }
            try await stashStep("A3", expecting: "A3") { try await lane.bobReceive(lane.aliceSend("A3")) }
            try await stashStep("B next", expecting: "Bn") { try await lane.aliceReceive(lane.bobSend("Bn")) }
        }
    }
}
