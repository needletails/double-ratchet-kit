//
//  SessionMutationGate.swift
//  double-ratchet-kit
//

import Foundation

/// Serializes state-changing work per session while allowing unrelated sessions to proceed.
///
/// The gate is deliberately separate from the managers' actors: manager actors are reentrant
/// across `await` points, whereas a ratchet mutation must retain exclusive ownership from its
/// first state read through its durable commit.
actor SessionMutationGate {
    private struct Waiter {
        let id: UUID
        let continuation: CheckedContinuation<Void, Error>
    }

    private var closed = false
    private var activeSessions = Set<UUID>()
    private var waiters: [UUID: [Waiter]] = [:]
    private var shutdownWaiters: [CheckedContinuation<Void, Never>] = []

    func withLease<T: Sendable>(
        for sessionId: UUID,
        operation: @Sendable () async throws -> T
    ) async throws -> T {
        try await acquire(sessionId)
        do {
            try Task.checkCancellation()
            let result = try await operation()
            release(sessionId)
            return result
        } catch {
            release(sessionId)
            throw error
        }
    }

    private func acquire(_ sessionId: UUID) async throws {
        try Task.checkCancellation()
        guard !closed else {
            throw CancellationError()
        }
        guard activeSessions.contains(sessionId) else {
            activeSessions.insert(sessionId)
            return
        }

        let waiterID = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                guard !closed else {
                    continuation.resume(throwing: CancellationError())
                    return
                }
                waiters[sessionId, default: []].append(
                    Waiter(id: waiterID, continuation: continuation)
                )
            }
        } onCancel: {
            // The handler runs synchronously on the cancelling thread, outside actor isolation,
            // so removing the waiter has to hop back onto the actor. This is safe:
            // - No data race: only Sendable values are captured, and the queue is touched only
            //   inside `cancelWaiter`, on the actor.
            // - No lost cancellation: if the task is already cancelled, this handler runs before
            //   the operation, but the hop cannot run until `acquire` suspends, and by then the
            //   waiter is queued.
            // - No double resume: `release`, `closeAndWaitForLeases` and `cancelWaiter` each
            //   remove a waiter before resuming it, so whichever runs first wins. If `release`
            //   wins, `withLease` sees the cancellation in `Task.checkCancellation()` and passes
            //   the lease on.
            // - Bounded cost: the handler fires at most once per waiter, so it spawns at most one
            //   task per queued acquire.
            Task {
                await self.cancelWaiter(waiterID, for: sessionId)
            }
        }
    }

    private func cancelWaiter(_ waiterID: UUID, for sessionId: UUID) {
        guard var queue = waiters[sessionId],
              let index = queue.firstIndex(where: { $0.id == waiterID }) else {
            return
        }
        let waiter = queue.remove(at: index)
        if queue.isEmpty {
            waiters.removeValue(forKey: sessionId)
        } else {
            waiters[sessionId] = queue
        }
        waiter.continuation.resume(throwing: CancellationError())
    }

    /// Number of acquirers suspended behind the active lease for `sessionId`. Used by tests.
    func queuedWaiterCount(for sessionId: UUID) -> Int {
        waiters[sessionId]?.count ?? 0
    }

    private func release(_ sessionId: UUID) {
        if var queue = waiters[sessionId], !queue.isEmpty {
            let next = queue.removeFirst()
            if queue.isEmpty {
                waiters.removeValue(forKey: sessionId)
            } else {
                waiters[sessionId] = queue
            }
            next.continuation.resume()
        } else {
            activeSessions.remove(sessionId)
        }
        resumeShutdownWaitersIfDrained()
    }

    func closeAndWaitForLeases() async {
        guard !closed else {
            if activeSessions.isEmpty { return }
            await waitForLeasesToDrain()
            return
        }

        closed = true
        let pending = waiters.values.flatMap { $0 }
        waiters.removeAll()
        for waiter in pending {
            waiter.continuation.resume(throwing: CancellationError())
        }
        await waitForLeasesToDrain()
    }

    private func waitForLeasesToDrain() async {
        guard !activeSessions.isEmpty else { return }
        await withCheckedContinuation { continuation in
            shutdownWaiters.append(continuation)
        }
    }

    private func resumeShutdownWaitersIfDrained() {
        guard activeSessions.isEmpty else { return }
        let continuations = shutdownWaiters
        shutdownWaiters.removeAll()
        for continuation in continuations {
            continuation.resume()
        }
    }
}
