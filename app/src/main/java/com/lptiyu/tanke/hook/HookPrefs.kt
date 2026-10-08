package com.lptiyu.tanke.hook

import de.robv.android.xposed.XSharedPreferences
import de.robv.android.xposed.XposedBridge

/**
 * 全局偏好设置单例，持有所有功能开关的键常量和运行时值。
 *
 * [load] 在 initZygote 和 handleLoadPackage 时被调用；
 * 各 Hook 模块通过只读属性访问，不持有 Context 引用。
 */
object HookPrefs {

    const val PREFS_NAME = "tanke_hook_prefs"

    // ── SharedPreferences 键常量 ─────────────────────────────────
    // 抓包辅助
    const val KEY_BYPASS_SSL       = "bypass_ssl_pinning"
    const val KEY_DISABLE_HTTPDNS  = "disable_httpdns"
    // 广告屏蔽
    const val KEY_DISABLE_ADS      = "disable_ads"
    const val KEY_SKIP_SPLASH_AD   = "skip_splash_ad"
    // 反检测
    const val KEY_FAKE_STACK       = "fake_stack_trace"
    const val KEY_BYPASS_PROXY     = "bypass_proxy_detect"
    const val KEY_BYPASS_ROOT      = "bypass_root_detect"
    const val KEY_BYPASS_DEBUGGER  = "bypass_debugger_detect"
    const val KEY_BYPASS_VAPP      = "bypass_vapp_detect"
    const val KEY_BYPASS_FRIDA     = "bypass_frida_detect"
    // 调试
    const val KEY_VERBOSE_LOG      = "verbose_log"
    const val KEY_LOG_REGISTER_NATIVES = "log_register_natives"
    // 扫码登录
    const val KEY_SCAN_ON      = "scan_login_on"
    const val KEY_SCAN_OPENID  = "scan_login_openid"
    const val KEY_SCAN_TOKEN   = "scan_login_token"
    const val KEY_SCAN_NICK    = "scan_login_nickname"
    const val KEY_SCAN_AVATAR  = "scan_login_avatar"

    // ── 运行时开关（全部默认开启）────────────────────────────────
    @Volatile var bypassSsl      = true
    @Volatile var disableHttpdns = true
    @Volatile var disableAds     = true
    @Volatile var skipSplashAd   = true
    @Volatile var fakeStack      = true
    @Volatile var bypassProxy    = true
    @Volatile var bypassRoot     = true
    @Volatile var bypassDebugger = true
    @Volatile var bypassVapp     = true
    @Volatile var bypassFrida    = false
    @Volatile var verboseLog     = false
    @Volatile var logRegisterNatives = false
    // 扫码登录运行时值
    @Volatile var scanOn     = false
    @Volatile var scanOpenid = ""
    @Volatile var scanToken  = ""
    @Volatile var scanNickname = ""
    @Volatile var scanAvatar = ""

    @Suppress("DEPRECATION")
    fun load(modulePackage: String = "com.lptiyu.tanke.hook") {
        try {
            val xsp = XSharedPreferences(modulePackage, PREFS_NAME)
            xsp.makeWorldReadable()
            xsp.reload()
            bypassSsl      = xsp.getBoolean(KEY_BYPASS_SSL,      true)
            disableHttpdns = xsp.getBoolean(KEY_DISABLE_HTTPDNS, true)
            disableAds     = xsp.getBoolean(KEY_DISABLE_ADS,     true)
            skipSplashAd   = xsp.getBoolean(KEY_SKIP_SPLASH_AD,  true)
            fakeStack      = xsp.getBoolean(KEY_FAKE_STACK,      true)
            bypassProxy    = xsp.getBoolean(KEY_BYPASS_PROXY,    true)
            bypassRoot     = xsp.getBoolean(KEY_BYPASS_ROOT,     true)
            bypassDebugger = xsp.getBoolean(KEY_BYPASS_DEBUGGER, true)
            bypassVapp     = xsp.getBoolean(KEY_BYPASS_VAPP,     true)
            bypassFrida    = xsp.getBoolean(KEY_BYPASS_FRIDA,    false)
            verboseLog     = xsp.getBoolean(KEY_VERBOSE_LOG,     false)
            logRegisterNatives = xsp.getBoolean(KEY_LOG_REGISTER_NATIVES, false)
            scanOn     = xsp.getBoolean(KEY_SCAN_ON, false)
            scanOpenid = xsp.getString(KEY_SCAN_OPENID, "") ?: ""
            scanToken  = xsp.getString(KEY_SCAN_TOKEN,  "") ?: ""
            scanNickname = xsp.getString(KEY_SCAN_NICK, "") ?: ""
            scanAvatar = xsp.getString(KEY_SCAN_AVATAR, "") ?: ""
            XposedBridge.log(
                "TankeHook: prefs — ssl=$bypassSsl dns=$disableHttpdns ads=$disableAds " +
                "splash=$skipSplashAd stack=$fakeStack proxy=$bypassProxy root=$bypassRoot " +
                "dbg=$bypassDebugger vapp=$bypassVapp frida=$bypassFrida verbose=$verboseLog rnLog=$logRegisterNatives " +
                "scanOn=$scanOn scanOpenid=${if (scanOpenid.isBlank()) "-" else scanOpenid.take(6) + ".."}"
            )
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: prefs load failed (using defaults): ${e.message}")
        }
    }

    fun vlog(msg: String) {
        if (verboseLog) XposedBridge.log("TankeHook[V]: $msg")
    }
}
