package com.libertygsm.app

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.libertygsm.app.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private var running = false

    // VpnService.prepare consent dialog. On approval, start the service.
    private val consent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) launchService(selectedMode())
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.toggle.setOnClickListener { if (running) stop() else start() }
        binding.version.text = "v" + appVersionName()
        render()
    }

    override fun onResume() {
        super.onResume()
        // The service may have kept running (or been revoked) while we were away.
        running = LibertyVpnService.isRunning
        render()
    }

    @Suppress("DEPRECATION")
    private fun appVersionName(): String =
        try {
            packageManager.getPackageInfo(packageName, 0).versionName ?: "?"
        } catch (_: Exception) {
            "?"
        }

    private fun selectedMode(): String = when (binding.modeSpinner.selectedItemPosition) {
        1 -> "Advanced"
        2 -> "Extreme"
        else -> "Standard"
    }

    private fun start() {
        val prep = VpnService.prepare(this)
        if (prep != null) consent.launch(prep) else launchService(selectedMode())
    }

    private fun launchService(mode: String) {
        val i = Intent(this, LibertyVpnService::class.java).putExtra(LibertyVpnService.EXTRA_MODE, mode)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(i) else startService(i)
        running = true
        render()
    }

    private fun stop() {
        startService(Intent(this, LibertyVpnService::class.java).setAction(LibertyVpnService.ACTION_STOP))
        running = false
        render()
    }

    private fun render() {
        binding.status.text = if (running) "우회 작동 중 — 모든 앱 보호" else "꺼짐"
        binding.toggle.text = if (running) "STOP" else "START"
        binding.modeSpinner.isEnabled = !running
    }
}
