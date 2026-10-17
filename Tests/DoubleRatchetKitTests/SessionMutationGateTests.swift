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

    @Test(.timeLimit(.minutes(1)))
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
        // Cancel only once the acquirer is suspended in the waiter queue, so the cancellation
        // handler (not the up-front `Task.checkCancellation()`) is what rejects it.
        while await gate.queuedWaiterCount(for: sessionID) == 0 {
            await Task.yield()
        }
        queued.cancel()

        // The active lease is still held, so only the cancellation handler can dequeue the
        // waiter. Bound the wait: `queued.value` cannot be interrupted, so a regression would
        // otherwise hang instead of failing.
        let deadline = ContinuousClock.now + .seconds(5)
        while await gate.queuedWaiterCount(for: sessionID) > 0, ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(1))
        }
        try #require(await gate.queuedWaiterCount(for: sessionID) == 0)
        await #expect(throws: CancellationError.self) {
            try await queued.value
        }

        await probe.releaseAll()
        try await active.value
        #expect(await probe.entryCount == 1)

        // The cancelled waiter must not have leaked the lease.
        try await gate.withLease(for: sessionID) {
            await probe.enter()
        }
        #expect(await probe.entryCount == 2)
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
