//
//  OTKHostEpochReinjectionTests.swift
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
import NeedleTailCrypto
import Testing
@testable import DoubleRatchetKit

extension MessageRatchetTests {
    private func rotatedMLKEM() throws -> MLKEMPrivateKey {
        let kem = try crypto.generateMLKem1024PrivateKey()
        return try MLKEMPrivateKey(id: UUID(), kem.encode())
    }

    /// A lane whose state never held the peer's one-time key (the peer embedded
    /// none) must not start citing the host-cached peer OTK on a host-driven
    /// epoch re-key. The peer has no state copy for that id and, with strict
    /// enforcement, fails fast with `missingOneTimeKey` on every later frame.
    @Test
    func testHostEpochDoesNotIntroduceRemoteOneTimeKeyTheLaneNeverHeld() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        await aliceManager.setEnforceOTKConsistency(true)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        await bobManager.setEnforceOTKConsistency(true)

        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            guard let aliceLane = getSessionIdentity(for: bobIdentity.id),
                  let bobLane = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            // Blank-lane bootstrap: Alice found no published OTK for Bob and has
            // none of her own in play, so her header embeds and cites nothing and
            // Bob's lane is created with `remoteOneTimePublicKey == nil`.
            let aliceNoOTK = LocalKeys(longTerm: bundle.alicePrivate.longTerm, oneTime: nil, mlKEM: bundle.alicePrivate.mlKEM)
            let bobWithoutOTK = RemoteKeys(longTerm: bundle.bobPublic.longTerm, oneTime: nil, mlKEM: bundle.bobPublic.mlKEM)
            let bobNoOTK = LocalKeys(longTerm: bundle.bobPrivate.longTerm, oneTime: nil, mlKEM: bundle.bobPrivate.mlKEM)

            try await aliceManager.initiateSession(sessionIdentity: aliceLane, sessionSymmetricKey: aliceDbsk, remoteKeys: bobWithoutOTK, localKeys: aliceNoOTK)
            let a1 = try await aliceManager.encrypt(plainText: Data("A1".utf8), sessionId: aliceLane.id)
            #expect(a1.header.remoteOneTimePublicKey == nil)
            #expect(a1.header.oneTimeKeyId == nil)
            try await bobManager.respondToSession(sessionIdentity: bobLane, sessionSymmetricKey: bobDBSK, header: a1.header, localKeys: bobNoOTK)
            #expect(try await bobManager.decrypt(a1, sessionId: bobLane.id) == Data("A1".utf8))

            // Bob's host rotates ML-KEM and, like every host, re-supplies the
            // peer OTK it has cached for Alice plus its own pool key.
            let bobRotated = LocalKeys(longTerm: bundle.bobPrivate.longTerm, oneTime: bundle.bobPrivate.oneTime, mlKEM: try rotatedMLKEM())
            try await bobManager.initiateSession(sessionIdentity: bobLane, sessionSymmetricKey: bobDBSK, remoteKeys: bundle.alicePublic, localKeys: bobRotated)
            let b1 = try await bobManager.encrypt(plainText: Data("B1".utf8), sessionId: bobLane.id)
            #expect(b1.header.oneTimeKeyId == nil, "host epoch re-injected a peer OTK the lane never held")

            try await aliceManager.respondToSession(sessionIdentity: aliceLane, sessionSymmetricKey: aliceDbsk, header: b1.header, localKeys: aliceNoOTK)
            #expect(try await aliceManager.decrypt(b1, sessionId: aliceLane.id) == Data("B1".utf8))

            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    /// A chain frame on an established lane that still cites a one-time key id
    /// the receiver no longer holds must decrypt: the private half only feeds
    /// PQXDH, so strict enforcement fails fast only for handshakes and epochs.
    @Test
    func testStrictChainFrameDecryptsWithoutCitedOneTimeKey() async throws {
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        await aliceManager.setEnforceOTKConsistency(true)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        await bobManager.setEnforceOTKConsistency(true)

        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            guard let aliceLane = getSessionIdentity(for: bobIdentity.id),
                  let bobLane = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }
            let bobNoOTK = LocalKeys(longTerm: bundle.bobPrivate.longTerm, oneTime: nil, mlKEM: bundle.bobPrivate.mlKEM)

            try await aliceManager.initiateSession(sessionIdentity: aliceLane, sessionSymmetricKey: aliceDbsk, remoteKeys: bundle.bobPublic, localKeys: bundle.alicePrivate)
            let a1 = try await aliceManager.encrypt(plainText: Data("A1".utf8), sessionId: aliceLane.id)
            try await bobManager.respondToSession(sessionIdentity: bobLane, sessionSymmetricKey: bobDBSK, header: a1.header, localKeys: bundle.bobPrivate)
            #expect(try await bobManager.decrypt(a1, sessionId: bobLane.id) == Data("A1".utf8))

            // Bob's host no longer holds the key (pool replaced) and supplies none;
            // Alice's chain frames keep citing it until she retires.
            let a2 = try await aliceManager.encrypt(plainText: Data("A2".utf8), sessionId: aliceLane.id)
            #expect(a2.header.oneTimeKeyId == bundle.bobPrivate.oneTime?.id)
            try await bobManager.respondToSession(sessionIdentity: bobLane, sessionSymmetricKey: bobDBSK, header: a2.header, localKeys: bobNoOTK)
            #expect(try await bobManager.decrypt(a2, sessionId: bobLane.id) == Data("A2".utf8))

            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }

    /// An epoch header that stops embedding the peer's one-time key retires it
    /// for the lane, exactly like the chain-frame adoption path does. A later
    /// host-driven epoch must not resurrect the cached key and cite it.
    @Test
    func testEpochHeaderDroppingOneTimeKeyRetiresItForHostEpochs() async throws {
        // Alice is a non-enforcing host: she may re-key without a local OTK
        // while still holding Bob's, which strict senders refuse to do.
        let aliceManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await aliceManager.setDelegate(self)
        let bobManager = MessageRatchet(executor: executor, ratchetConfiguration: testableRatchetConfiguration)
        await bobManager.setDelegate(self)
        await bobManager.setEnforceOTKConsistency(true)

        do {
            let (aliceIdentity, bobIdentity, bundle) = try await createKeys()
            guard let aliceLane = getSessionIdentity(for: bobIdentity.id),
                  let bobLane = getSessionIdentity(for: aliceIdentity.id) else {
                throw TestErrors.identityNotFound
            }

            // Normal bootstrap: Alice embeds her OTK, Bob's lane holds it.
            try await aliceManager.initiateSession(sessionIdentity: aliceLane, sessionSymmetricKey: aliceDbsk, remoteKeys: bundle.bobPublic, localKeys: bundle.alicePrivate)
            let a1 = try await aliceManager.encrypt(plainText: Data("A1".utf8), sessionId: aliceLane.id)
            #expect(a1.header.remoteOneTimePublicKey != nil)
            try await bobManager.respondToSession(sessionIdentity: bobLane, sessionSymmetricKey: bobDBSK, header: a1.header, localKeys: bundle.bobPrivate)
            #expect(try await bobManager.decrypt(a1, sessionId: bobLane.id) == Data("A1".utf8))

            // Alice's host rotates ML-KEM with no local OTK left: the epoch
            // header carries a new ML-KEM key and no OTK.
            let aliceRotatedNoOTK = LocalKeys(longTerm: bundle.alicePrivate.longTerm, oneTime: nil, mlKEM: try rotatedMLKEM())
            try await aliceManager.initiateSession(sessionIdentity: aliceLane, sessionSymmetricKey: aliceDbsk, remoteKeys: bundle.bobPublic, localKeys: aliceRotatedNoOTK)
            let a2 = try await aliceManager.encrypt(plainText: Data("A2".utf8), sessionId: aliceLane.id)
            #expect(a2.header.remoteOneTimePublicKey == nil)
            try await bobManager.respondToSession(sessionIdentity: bobLane, sessionSymmetricKey: bobDBSK, header: a2.header, localKeys: bundle.bobPrivate)
            #expect(try await bobManager.decrypt(a2, sessionId: bobLane.id) == Data("A2".utf8))

            // Bob answers in-chain; the host re-supplies the cached peer OTK but
            // the lane must not cite the key Alice dropped.
            try await bobManager.initiateSession(sessionIdentity: bobLane, sessionSymmetricKey: bobDBSK, remoteKeys: bundle.alicePublic, localKeys: bundle.bobPrivate)
            let b1 = try await bobManager.encrypt(plainText: Data("B1".utf8), sessionId: bobLane.id)
            #expect(b1.header.oneTimeKeyId == nil, "chain frame re-cited a peer OTK dropped by an epoch header")
            try await aliceManager.respondToSession(sessionIdentity: aliceLane, sessionSymmetricKey: aliceDbsk, header: b1.header, localKeys: aliceRotatedNoOTK)
            #expect(try await aliceManager.decrypt(b1, sessionId: aliceLane.id) == Data("B1".utf8))

            // Bob's host-driven epoch re-supplies the cached peer OTK again (with
            // Alice's current published ML-KEM); Bob must keep the lane OTK-less
            // instead of resurrecting it.
            let bobRotated = LocalKeys(longTerm: bundle.bobPrivate.longTerm, oneTime: bundle.bobPrivate.oneTime, mlKEM: try rotatedMLKEM())
            let aliceCurrent = try RemoteKeys(
                longTerm: bundle.alicePublic.longTerm,
                oneTime: bundle.alicePublic.oneTime,
                mlKEM: MLKEMPublicKey(id: aliceRotatedNoOTK.mlKEM.id, aliceRotatedNoOTK.mlKEM.rawRepresentation.decodeMLKem1024().publicKey.rawRepresentation))
            try await bobManager.initiateSession(sessionIdentity: bobLane, sessionSymmetricKey: bobDBSK, remoteKeys: aliceCurrent, localKeys: bobRotated)
            let b2 = try await bobManager.encrypt(plainText: Data("B2".utf8), sessionId: bobLane.id)
            #expect(b2.header.oneTimeKeyId == nil, "host epoch re-cited a peer OTK dropped by an epoch header")
            try await aliceManager.respondToSession(sessionIdentity: aliceLane, sessionSymmetricKey: aliceDbsk, header: b2.header, localKeys: aliceRotatedNoOTK)
            #expect(try await aliceManager.decrypt(b2, sessionId: aliceLane.id) == Data("B2".utf8))

            try await aliceManager.flushAndClose()
            try await bobManager.flushAndClose()
        } catch {
            try? await aliceManager.flushAndClose()
            try? await bobManager.flushAndClose()
            throw error
        }
    }
}
