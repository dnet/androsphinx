package org.hsbp.androsphinx

import android.app.*
import android.content.*
import android.content.Context
import androidx.core.app.NotificationCompat
import android.os.*
import androidx.annotation.RequiresApi
import androidx.preference.PreferenceManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.parcelize.Parcelize
import kotlin.coroutines.CoroutineContext

private const val CHANNEL_ID = "AndrosphinxChannel"
private const val CHANNEL_NAME = "Clipboard cleaner"
private const val CHANNEL_DESCRIPTION = "Removes passwords copied to the clipboard after a timer elapses."
private const val NOTIFICATION_ID = 42

const val SERVICE_COMMAND = "org.hsbp.androsphinx.ClipboardCleanerService.SERVICE_COMMAND"

class NotificationHelper(private val context: Context) {
    private val notificationManager by lazy {
        context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
    }

    private val contentIntent by lazy {
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) (PendingIntent.FLAG_MUTABLE
                or PendingIntent.FLAG_UPDATE_CURRENT) else PendingIntent.FLAG_UPDATE_CURRENT
        PendingIntent.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java),
            flags
        )
    }

    private val notificationBuilder: NotificationCompat.Builder by lazy {
        NotificationCompat.Builder(context, CHANNEL_ID)
            .setContentTitle(context.getString(R.string.clipboard_cleaner_notification_title))
            .setSound(null)
            .setContentIntent(contentIntent)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
    }

    @RequiresApi(Build.VERSION_CODES.O)
    private fun createChannel() =
        NotificationChannel(
            CHANNEL_ID,
            CHANNEL_NAME,
            NotificationManager.IMPORTANCE_DEFAULT
        ).apply {
            description = CHANNEL_DESCRIPTION
            setSound(null, null)
        }

    fun getNotification(): Notification {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            notificationManager.createNotificationChannel(createChannel())
        }
        return notificationBuilder.build()
    }

    fun updateNotification(notificationText: String, timeoutSeconds: Int, elapsedTime: Long) {
        notificationBuilder.setContentText(notificationText)
        notificationBuilder.setProgress(timeoutSeconds, elapsedTime.toInt(), false)
        notificationManager.notify(NOTIFICATION_ID, notificationBuilder.build())
        Thread.sleep(10) // TODO without this, it kind of never shows on Pixel 5 / Android 12
    }
}

@Parcelize
enum class TimerState : Parcelable {
    INITIALIZED,
    START,
    STOP
}

class ClipboardCleanerService : Service(), CoroutineScope {
    var serviceState: TimerState = TimerState.INITIALIZED

    private val helper by lazy { NotificationHelper(this) }

    private var currentTime: Long = 0
    private var deadlineTimestamp: Long = 0
        set(value) {
            currentTime = System.currentTimeMillis()
            field = value
        }

    private val handler = Handler(Looper.getMainLooper())
    private var runnable: Runnable = object : Runnable {
        override fun run() {
            currentTime = System.currentTimeMillis()
            broadcastUpdate()
            if (currentTime < deadlineTimestamp) {
                handler.postDelayed(this, 1000)
            } else {
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                if (Build.VERSION.SDK_INT >= 28) {
                    clipboard.clearPrimaryClip()
                } else {
                    clipboard.setPrimaryClip(ClipData.newPlainText("password", ""))
                }
                endTimerService()
            }
        }
    }

    private fun broadcastUpdate() {
        if (serviceState == TimerState.START) {
            val elapsedTime = (deadlineTimestamp - currentTime) / 1000
            helper.updateNotification(
                getString(R.string.clipboard_cleaner_notification, elapsedTime), timeoutSeconds, elapsedTime
            )
        }
    }

    private val job = Job()
    override val coroutineContext: CoroutineContext
        get() = Dispatchers.IO + job


    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)
        intent?.extras?.run {
            when (getSerializable(SERVICE_COMMAND) as TimerState) {
                TimerState.START -> startTimer()
                else -> return START_NOT_STICKY
            }
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        handler.removeCallbacks(runnable)
        job.cancel()
    }

    private var timeoutSeconds: Int = 0

    private fun startTimer() {
        timeoutSeconds = PreferenceManager.getDefaultSharedPreferences(this).getInt("clipboard_cleaner_timeout_seconds", 10)
        if (timeoutSeconds == 0) {
            stopService()
            return
        }

        serviceState = TimerState.START

        deadlineTimestamp = System.currentTimeMillis() + timeoutSeconds * 1000

        startForeground(NOTIFICATION_ID, helper.getNotification())
        broadcastUpdate()

        startCoroutineTimer()
    }

    private fun endTimerService() {
        serviceState = TimerState.STOP
        handler.removeCallbacks(runnable)
        broadcastUpdate()
        stopService()
    }

    private fun stopService() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            stopForeground(true)
        } else {
            stopSelf()
        }
    }

    private fun startCoroutineTimer() {
        launch(coroutineContext) {
            handler.post(runnable)
        }
    }
}