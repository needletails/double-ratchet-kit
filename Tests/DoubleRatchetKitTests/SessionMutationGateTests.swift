import Foundation
import Testing
@testable import DoubleRatchetKit

@Suite("Session mutation gate", .serialized)
struct SessionMutationGateTests {
    @Test
    func sameSessionMutationsSerializeAndDifferentSessionsOverlap() async throws {
        let gate = SessionMutationGate()
        let probe = LeaseProbe()
        let firstSession = UUID()
        let secondSession = UUID()

        let first = Task {
            try await gate.withLease(for: firstSession) {
                await probe.enter()
                await probe.waitForRelease()
            }
        }
        await probe.waitForEntries(1)

        let queuedSameSession = Task {
            try await gate.withLease(for: firstSession) {
                await probe.enter()
            }
        }
        let concurrentOtherSession = Task {
            try await gate.withLease(for: secondSession) {
                await probe.enter()
                await probe.waitForRelease()
            }
        }

        await probe.waitForEntries(2)
        #expect(await probe.maximumConcurrentLeases == 2)

        await probe.releaseAll()
        try await first.value
        try await queuedSameSession.value
        try await concurrentOtherSession.value
        #expect(await probe.maximumConcurrentLeases == 2)
    }

    @Test
    func queuedMutationCancelsWithoutReceivingLease() async throws {
        let gate = SessionMutationGate()
        let probe = LeaseProbe()
        let sessionID = UUID()

        let active = Task {
            try await gate.withLease(for: sessionID) {
                await probe.enter()
                await probe.waitForRelease()
            }
        }
        await probe.waitForEntries(1)

        let queued = Task {
            try await gate.withLease(for: sessionID) {
                await probe.enter()
            }
        }
        queued.cancel()
        await probe.releaseAll()

        try await active.value
        await #expect(throws: CancellationError.self) {
            try await queued.value
        }
        #expect(await probe.entryCount == 1)
    }

    @Test
    func shutdownWaitsForLeaseAndRejectsNewMutations() async throws {
        let gate = SessionMutationGate()
        let probe = LeaseProbe()
        let sessionID = UUID()

        let active = Task {
            try await gate.withLease(for: sessionID) {
                await probe.enter()
                await probe.waitForRelease()
            }
        }
        await probe.waitForEntries(1)

        let shutdown = Task {
            await gate.closeAndWaitForLeases()
        }
        await Task.yield()
        do {
            try await gate.withLease(for: sessionID) {}
            Issue.record("Expected CancellationError")
        } catch {
            if error is CancellationError {
                // Expected.
            } else {
                Issue.record("Expected CancellationError, got \(error)")
            }
        }

        await probe.releaseAll()
        try await active.value
        await shutdown.value
    }
}

private actor LeaseProbe {
    private var activeLeases = 0
    private(set) var maximumConcurrentLeases = 0
    private(set) var entryCount = 0
    private var entryWaiters: [(Int, CheckedContinuation<Void, Never>)] = []
    private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

    func enter() {
        activeLeases += 1
        entryCount += 1
        maximumConcurrentLeases = max(maximumConcurrentLeases, activeLeases)
        resumeEntryWaiters()
    }

    func waitForEntries(_ count: Int) async {
        guard entryCount < count else { return }
        await withCheckedContinuation { continuation in
            entryWaiters.append((count, continuation))
        }
    }

    func waitForRelease() async {
        await withCheckedContinuation { continuation in
            releaseWaiters.append(continuation)
        }
        activeLeases -= 1
    }

    func releaseAll() {
        let continuations = releaseWaiters
        releaseWaiters.removeAll()
        for continuation in continuations {
            continuation.resume()
        }
    }

    private func resumeEntryWaiters() {
        let ready = entryWaiters.filter { $0.0 <= entryCount }
        entryWaiters.removeAll { $0.0 <= entryCount }
        for (_, continuation) in ready {
            continuation.resume()
        }
    }
}
