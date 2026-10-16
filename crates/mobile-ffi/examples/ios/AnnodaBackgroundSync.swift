import BackgroundTasks
import Dispatch
import Foundation
import UserNotifications
import annoda_mobile_ffi

enum HostSyncDeferReason {
    case authorizationUnavailable
    case budgetExhausted
    case syncFailed
    case cleanupFailed
    case schedulingUnavailable
}

enum HostSyncCompletion {
    case finished
    case deferred(HostSyncDeferReason)
}

/// The app supplies saved credential/issuer/peer configuration and silent authorization.
protocol AnnodaBackgroundInputs: Sendable {
    func accountDirectory() async -> String
    func backgroundPassphrase() async -> String?
    func syncRequest() async throws -> FfiSyncRequest
    func recordDeferred(_ reason: HostSyncDeferReason) async
}

enum AnnodaBackgroundScheduler {
    static let identifier = "org.annoda.sync.refresh"

    static func register(inputs: AnnodaBackgroundInputs) throws {
        BGTaskScheduler.shared.register(forTaskWithIdentifier: identifier, using: nil) { task in
            guard let refresh = task as? BGAppRefreshTask else {
                task.setTaskCompleted(success: false)
                return
            }
            AnnodaBackgroundSync(inputs: inputs).handle(refresh)
        }
        try scheduleNext()
    }

    static func scheduleNext() throws {
        let request = BGAppRefreshTaskRequest(identifier: identifier)
        request.earliestBeginDate = Date(timeIntervalSinceNow: 15 * 60)
        // This is an earliest start hint; iOS controls launch timing and execution duration.
        try BGTaskScheduler.shared.submit(request)
    }
}

final class AnnodaSessionControl: @unchecked Sendable {
    private let lock = NSLock()
    private var session: SyncSession?
    private var expired = false

    func install(_ session: SyncSession) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        self.session = session
        return !expired
    }

    func expire() {
        lock.lock()
        expired = true
        let session = self.session
        lock.unlock()
        session?.cancel()
    }
}

final class AnnodaBackgroundSync {
    private let inputs: AnnodaBackgroundInputs

    init(inputs: AnnodaBackgroundInputs) {
        self.inputs = inputs
    }

    func handle(_ task: BGAppRefreshTask) {
        let control = AnnodaSessionControl()
        let work = Task.detached(priority: .background) { [inputs] in
            let completion = await run(inputs: inputs, control: control)
            if case .deferred(let reason) = completion {
                await inputs.recordDeferred(reason)
            }
            do {
                try AnnodaBackgroundScheduler.scheduleNext()
            } catch {
                await inputs.recordDeferred(.schedulingUnavailable)
            }
            if case .finished = completion {
                task.setTaskCompleted(success: true)
            } else {
                task.setTaskCompleted(success: false)
            }
        }
        task.expirationHandler = {
            control.expire()
            work.cancel()
        }
    }
}

private func run(
    inputs: AnnodaBackgroundInputs,
    control: AnnodaSessionControl
) async -> HostSyncCompletion {
    let startedAt = DispatchTime.now().uptimeNanoseconds
    guard let passphrase = await inputs.backgroundPassphrase() else {
        return .deferred(.authorizationUnavailable)
    }
    let directory = await inputs.accountDirectory()
    var account: AccountHandle?
    var session: SyncSession?
    var completion: HostSyncCompletion = .deferred(.syncFailed)
    do {
        // The portable vault's KDF is synchronous, so it runs away from the UI actor.
        account = try await Task.detached(priority: .background) {
            try openAccount(directory: directory, passphrase: passphrase)
        }.value
        if !Task.isCancelled, let account {
            var request = try await inputs.syncRequest()
            let elapsedNs = DispatchTime.now().uptimeNanoseconds &- startedAt
            let elapsedMs = elapsedNs / 1_000_000
            // The host grants at most 20 seconds of Rust execution, less auth/KDF setup time.
            let remainingMs = elapsedMs >= 20_000 ? 0 : 20_000 - elapsedMs
            request.budget.maxDurationMs = min(request.budget.maxDurationMs, UInt64(remainingMs))
            if request.budget.maxDurationMs == 0 {
                completion = .deferred(.budgetExhausted)
            } else {
                session = try account.startSyncSession(request: request)
                if let session, control.install(session) {
                    var report: FfiSyncReport?
                    while !Task.isCancelled {
                        report = try session.waitResult(timeoutMs: 250)
                        if report != nil { break }
                        try await Task.sleep(for: .milliseconds(50))
                    }
                    if Task.isCancelled { session.cancel() }
                    while try !session.isFinished() {
                        _ = try session.waitResult(timeoutMs: 250)
                    }
                    if let report, report.status == .complete || report.status == .partial {
                        try await deliverPending(account)
                        completion = .finished
                    } else if report?.status == .budgetExhausted || report?.status == .deferred {
                        completion = .deferred(.budgetExhausted)
                    }
                } else {
                    session?.cancel()
                }
            }
        }
    } catch {
        session?.cancel()
    }
    session?.cancel()
    if let session {
        while (try? session.isFinished()) == false {
            _ = try? session.waitResult(timeoutMs: 250)
        }
    }
    do {
        try account?.lock()
    } catch {
        return .deferred(.cleanupFailed)
    }
    return completion
}

private func deliverPending(_ account: AccountHandle) async throws {
    let center = UNUserNotificationCenter.current()
    let settings = await center.notificationSettings()
    guard settings.authorizationStatus == .authorized
        || settings.authorizationStatus == .provisional
        || settings.authorizationStatus == .ephemeral else { return }
    for event in try account.pendingNotifications(limit: 64) {
        let stableId = event.eventId.map { String(format: "%02x", $0) }.joined()
        let content = UNMutableNotificationContent()
        content.title = event.kind == .newMatch ? "New match" : "New like"
        content.body = "Open the app to view it."
        let request = UNNotificationRequest(
            identifier: stableId,
            content: content,
            trigger: nil
        )
        try await center.add(request)
        // The stable event id is acknowledged only after the OS accepted its notification request.
        _ = try account.acknowledgeNotification(eventId: event.eventId)
    }
}
