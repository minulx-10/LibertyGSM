package com.libertygsm.app

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import tunnel.Protector
import tunnel.Session
import tunnel.Tunnel

/**
 * Thin VpnService shell. It establishes the TUN interface and hands the file
 * descriptor to the shared Go core ([Tunnel]); all packet handling — DNS over
 * DoH, TLS ClientHello fragmentation, QUIC drop — happens in Go. The only thing
 * the Kotlin side provides is [Protector.protect], which excludes the core's
 * upstream sockets from the VPN so they don't loop back into the tunnel.
 */
class LibertyVpnService : VpnService() {

    private var session: Session? = null

    // gomobile interface: Go calls protect(fd) before connecting an upstream
    // socket; VpnService.protect keeps that socket off the VPN.
    private val protector = Protector { fd -> protect(fd.toInt()) }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopTunnel()
            return START_NOT_STICKY
        }
        startTunnel(intent?.getStringExtra(EXTRA_MODE) ?: "Standard")
        return START_STICKY
    }

    private fun startTunnel(mode: String) {
        if (session != null) return

        val pfd: ParcelFileDescriptor = Builder()
            .setSession("LibertyGSM")
            .setMtu(1500)
            .addAddress("10.111.0.1", 32)
            .addRoute("0.0.0.0", 0)        // capture all IPv4
            .addAddress("fd00:1111::1", 128)
            .addRoute("::", 0)             // capture all IPv6
            .addDnsServer("10.111.0.2")    // sink DNS into the tunnel
            .setBlocking(true)
            .establish() ?: run {
            stopSelf()
            return
        }

        startInForeground()
        try {
            // Go takes ownership of the fd and closes it on Session.stop().
            // Empty whitelist: fragment everything (the school-network default).
            session = Tunnel.connect(pfd.detachFd().toLong(), mode, "", protector)
        } catch (e: Exception) {
            stopTunnel()
        }
    }

    private fun stopTunnel() {
        try {
            session?.stop()
        } catch (_: Exception) {
        }
        session = null
        stopForegroundCompat()
        stopSelf()
    }

    fun updateMode(mode: String) = session?.updateMode(mode)

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopTunnel()
        super.onRevoke()
    }

    private fun startInForeground() {
        val mgr = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            mgr.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "LibertyGSM", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("LibertyGSM")
            .setContentText("우회 작동 중 — 모든 앱이 보호됩니다")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(open)
            .setOngoing(true)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIF_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, notification)
        }
    }

    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }

    companion object {
        const val ACTION_STOP = "com.libertygsm.app.STOP"
        const val EXTRA_MODE = "mode"
        private const val CHANNEL_ID = "libertygsm"
        private const val NOTIF_ID = 1
    }
}
