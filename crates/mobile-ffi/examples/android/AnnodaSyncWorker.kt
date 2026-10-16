package example.annoda

import android.app.Notification
import android.app.NotificationManager
import android.content.Context
import android.content.pm.PackageManager
import android.Manifest
import android.os.Build
import android.os.SystemClock
import androidx.core.content.ContextCompat
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import uniffi.annoda_mobile_ffi.*
import java.util.concurrent.TimeUnit

/** Host-owned inputs come from its credential and peer configuration stores. */
interface AnnodaSyncInputs {
    suspend fun accountDirectory(accountId: String): String
    suspend fun backgroundPassphrase(accountId: String): String?
    suspend fun request(accountId: String): FfiSyncRequest
    fun notification(event: FfiNotificationEvent): Notification
    fun recordDeferred(reason: HostSyncDeferReason)
}

enum class HostSyncDeferReason { AUTHORIZATION_UNAVAILABLE, SCHEDULING_UNAVAILABLE }

data class AnnodaWorkConstraints(
    val requireBatteryNotLow: Boolean = true,
    val requireCharging: Boolean = false,
)

/** Install this factory in WorkManager's Configuration; application inputs stay host-owned. */
class AnnodaSyncWorkerFactory(private val inputs: AnnodaSyncInputs) : androidx.work.WorkerFactory() {
    override fun createWorker(
        appContext: Context,
        workerClassName: String,
        params: WorkerParameters,
    ): androidx.work.ListenableWorker? =
        if (workerClassName == AnnodaSyncWorker::class.java.name) {
            AnnodaSyncWorker(appContext, params, inputs)
        } else null
}

object AnnodaSyncScheduling {
    private const val UNIQUE_WORK = "annoda-finite-sync"

    fun schedule(
        context: Context,
        accountId: String,
        hostConstraints: AnnodaWorkConstraints = AnnodaWorkConstraints(),
    ) {
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .setRequiresBatteryNotLow(hostConstraints.requireBatteryNotLow)
            .setRequiresCharging(hostConstraints.requireCharging)
            .build()
        // Fifteen minutes is WorkManager's periodic-work minimum interval, not a launch guarantee.
        val request = PeriodicWorkRequestBuilder<AnnodaSyncWorker>(15, TimeUnit.MINUTES)
            .setConstraints(constraints)
            .setInputData(androidx.work.Data.Builder().putString("account_id", accountId).build())
            .build()
        WorkManager.getInstance(context).enqueueUniquePeriodicWork(
            UNIQUE_WORK,
            ExistingPeriodicWorkPolicy.KEEP,
            request,
        )
    }
}

class AnnodaSyncWorker(
    appContext: Context,
    params: WorkerParameters,
    private val inputs: AnnodaSyncInputs,
) : CoroutineWorker(appContext, params) {
    override suspend fun doWork(): Result {
        val startedAt = SystemClock.elapsedRealtime()
        val accountId = inputData.getString("account_id") ?: return Result.failure()
        // Background auth must be silently available; this worker never prompts or creates an account.
        val passphrase = inputs.backgroundPassphrase(accountId)
        if (passphrase == null) {
            inputs.recordDeferred(HostSyncDeferReason.AUTHORIZATION_UNAVAILABLE)
            return Result.success()
        }
        val directory = inputs.accountDirectory(accountId)
        var account: AccountHandle? = null
        var session: SyncSession? = null
        try {
            account = withContext(Dispatchers.IO) { openAccount(directory, passphrase) }
            if (!currentCoroutineContext().isActive) return Result.retry()
            var request = inputs.request(accountId)
            // The host grants at most 20 seconds of Rust execution, less auth/KDF setup time.
            val remainingMs = (20_000L - (SystemClock.elapsedRealtime() - startedAt))
                .coerceAtLeast(0)
            request.budget.maxDurationMs = minOf(request.budget.maxDurationMs, remainingMs.toULong())
            if (request.budget.maxDurationMs == 0uL) return Result.retry()
            session = withContext(Dispatchers.IO) { account.startSyncSession(request) }
            while (currentCoroutineContext().isActive) {
                val report = withContext(Dispatchers.IO) { session.waitResult(250uL) }
                if (report != null) {
                    publishPending(account)
                    return if (report.status == FfiSyncStatus.CANCELLED) Result.retry() else Result.success()
                }
                if (isStopped) break
                delay(50)
            }
            return Result.retry()
        } finally {
            withContext(NonCancellable + Dispatchers.IO) {
                session?.cancel()
                while (session?.isFinished() == false) session.waitResult(250uL)
                account?.lock()
            }
        }
    }

    private fun publishPending(account: AccountHandle) {
        val manager = applicationContext.getSystemService(NotificationManager::class.java)
        if (!manager.areNotificationsEnabled()) return
        if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(
                applicationContext,
                Manifest.permission.POST_NOTIFICATIONS,
            ) != PackageManager.PERMISSION_GRANTED
        ) return
        for (event in account.pendingNotifications(64u)) {
            val stableTag = event.eventId.joinToString("") { "%02x".format(it) }
            manager.notify(stableTag, 0, inputs.notification(event))
            // Acknowledge only after Android accepted the notification; retries retain the same event id.
            account.acknowledgeNotification(event.eventId)
        }
    }
}
