package org.matrix.teesim

import android.os.Build
import android.os.IBinder
import android.os.ServiceManager
import java.io.File

/**
 * Finds the keystore daemon and drives the packaged `inject` binary to load the right interceptor
 * into it: `inject <pid> <lib.so> entry`. On Android 12+ the target is keystore2 with
 * libteesim_keymint.so; on 10/11 it is keystore with libteesim_keystore.so.
 *
 * **Event-driven, not polled.** The previous design scanned `/proc/<pid>/cmdline` every 2 s looking for
 * the keystore pid. This one blocks on [ServiceManager.waitForService] until the keystore binder
 * appears, registers a binder [IBinder.DeathRecipient] on it, injects once, and then parks on a
 * monitor until the recipient fires — i.e. until the keystore process dies. On death it clears the
 * stale pid and loops back to `waitForService` for the respawn. There is no `/proc` scanning loop and
 * no sleep-based polling while a keystore is live and injected; the only `findPid` call is the single
 * one made after a service (re)appears, to turn the binder handle into a pid for the inject binary.
 *
 * The only sleeps left are: a 2 s back-off on the no-service / inject-failed branch (a fault-retry,
 * not a watch poll), and the existing ~12 s `confirmAsync` hello wait (unchanged).
 */

class Injector(private val moduleDir: File) {

    private val api = Build.VERSION.SDK_INT
    private val procName = if (api >= 31) "keystore2" else "keystore"
    private val libName = if (api >= 31) "libteesim_keymint.so" else "libteesim_keystore.so"

    private val abi: String =
        Build.SUPPORTED_ABIS?.firstOrNull() ?: DeviceProps.prop("ro.product.cpu.abi", "arm64-v8a")

    private val injectBin = File(moduleDir, "$abi/inject")
    private val libFile = File(moduleDir, "$abi/$libName")

    @Volatile private var running = false
    @Volatile private var lastPid = -1

    // The keystore service name ServiceManager resolves for this Android generation.
    private val serviceName: String =
        if (api >= 31) "android.system.keystore2.IKeystoreService/default"
        else "android.security.keystore"

    // Wakes the loop when the live keystore service dies so it can re-enter waitForService for the
    // respawn. Parked on only after a successful inject; a successful inject never polls.
    private val deathLock = Object()

    private val deathRecipient = object : IBinder.DeathRecipient {
        override fun binderDied() {
            // Fires on a binder thread when the keystore process hosting the service exits. Wake the
            // loop so it drops the stale pid and blocks on waitForService again for the respawn.
            lastPid = -1
            synchronized(deathLock) { deathLock.notifyAll() }
        }
    }

    fun start() {
        if (running) return
        running = true
        if (!injectBin.exists() || !libFile.exists()) {
            SystemLogger.error(
                "injector: missing artifacts (inject=${injectBin.exists()} lib=${libFile.exists()}) " +
                    "under ${moduleDir.absolutePath}/$abi"
            )
        }
        injectBin.setExecutable(true, false)
        Thread({ loop() }, "teesim-injector").apply {
            isDaemon = true
            start()
        }
    }

    private fun loop() {
        while (running) {
            // Block until the keystore service is registered. waitForService is itself event-driven
            // (it parks on the binder death/registration path internally), so this is not a poll.
            val binder = waitForService()
            if (!running) return
            if (binder == null) {
                // waitForService unavailable (stripped build / very old API) — fall back to a single
                // getService, and if that is also missing, back off briefly. This is the only sleep on
                // the no-service branch, not a watch poll.
                val got = try { ServiceManager.getService(serviceName) } catch (_: Throwable) { null }
                if (got == null) {
                    SystemLogger.warning("injector: $procName service unavailable; retrying")
                    sleep(2000)
                    continue
                }
                if (!injectOnce(got)) backoffOnFault(got) else parkUntilDeath()
            } else {
                if (!injectOnce(binder)) backoffOnFault(binder) else parkUntilDeath()
            }
        }
    }

    /**
     * Link the death recipient, resolve the pid once, inject, and confirm. Returns true when the
     * interceptor is live in [lastPid] (the caller then parks on the death event); false on any fault
     * (pid not found / inject binary failed), in which case the caller backs off and retries.
     */
    private fun injectOnce(binder: IBinder): Boolean {
        // Register for death first so a race between inject and a crash still wakes the loop.
        try {
            binder.linkToDeath(deathRecipient, 0)
        } catch (e: Exception) {
            SystemLogger.warning("injector: linkToDeath failed: ${e.message}")
        }

        val pid = findPid(procName)
        // Tell the log tail which process to capture, so the Logs panel shows the target keystore's
        // own output — even before we manage to inject it.
        LogTail.targetPid = if (pid > 0) pid else -1
        if (pid <= 0) {
            SystemLogger.warning("injector: $procName service up but pid not found; will retry")
            return false
        }
        if (pid == lastPid) return true // already injected this pid; treat as success (park)
        if (inject(pid)) {
            lastPid = pid
            confirmAsync(pid)
            return true
        } else {
            SystemLogger.warning("injector: injection into pid=$pid failed; will retry")
            return false
        }
    }

    /** Park on the death monitor until the keystore service dies. No polling while injected. */
    private fun parkUntilDeath() {
        synchronized(deathLock) {
            // lastPid is cleared by the death recipient; any spurious wake re-checks and parks again.
            while (running && lastPid != -1) {
                deathLock.wait()
            }
        }
    }

    /** A fault (no pid / inject failed): back off, unlink the recipient we just linked, and retry. */
    private fun backoffOnFault(binder: IBinder) {
        sleep(2000)
        // unlink so a re-inject re-links cleanly against the same still-live service.
        try { binder.unlinkToDeath(deathRecipient, 0) } catch (_: Exception) {}
    }

    /**
     * Block until the keystore service is registered, returning its binder or null when unavailable.
     * Uses ServiceManager.waitForService (event-driven) where present; the caller falls back to
     * getService on a null return.
     */
    private fun waitForService(): IBinder? {
        return try {
            ServiceManager.waitForService(serviceName)
        } catch (e: Throwable) {
            // Some ROMs throw on a service that never appears; treat as "unavailable" and let the
            // caller's getService fallback handle it.
            null
        }
    }

    /** The control-channel hello is the real proof the lib loaded and bound the control socket. Warn
     * (don't re-inject — that risks double-hooking) if it never arrives. */
    private fun confirmAsync(pid: Int) {
        Thread({
                for (i in 0 until 24) { // ~12s
                    if (Control.libApi != 0) return@Thread
                    sleep(500)
                }
                SystemLogger.warning(
                    "injector: injected pid=$pid but the lib never checked in over ${Const.CONTROL_SOCKET_PATH} " +
                        "(SELinux on the control socket? look for 'avc: denied' in logcat)"
                )
            }, "teesim-inject-confirm")
            .apply {
                isDaemon = true
                start()
            }
    }

    private fun inject(pid: Int): Boolean {
        return try {
            val proc =
                ProcessBuilder(
                        injectBin.absolutePath,
                        pid.toString(),
                        libFile.absolutePath,
                        "entry",
                    )
                    .redirectErrorStream(true)
                    .start()
            val output = proc.inputStream.bufferedReader().readText()
            val code = proc.waitFor()
            if (code != 0) SystemLogger.warning("injector: inject exit=$code output=$output")
            code == 0
        } catch (e: Exception) {
            SystemLogger.error("injector: failed to run inject binary", e)
            false
        }
    }

    /** Return the pid whose /proc/<pid>/cmdline basename matches [name], else -1. */
    private fun findPid(name: String): Int {
        val proc = File("/proc")
        val entries =
            proc.listFiles { f -> f.isDirectory && f.name.all { it.isDigit() } } ?: return -1
        for (dir in entries) {
            val cmdlineFile = File(dir, "cmdline")
            val cmd =
                try {
                    cmdlineFile.readBytes()
                } catch (e: Exception) {
                    continue
                }
            if (cmd.isEmpty()) continue
            val end = cmd.indexOf(0.toByte()).let { if (it < 0) cmd.size else it }
            val arg0 = String(cmd, 0, end)
            val base = arg0.substringAfterLast('/')
            if (base == name) return dir.name.toIntOrNull() ?: continue
        }
        return -1
    }

    private fun sleep(ms: Long) {
        try {
            Thread.sleep(ms)
        } catch (ignored: InterruptedException) {}
    }
}