package com.lptiyu.tanke.hook

import android.app.Activity
import android.content.Context
import android.content.res.Configuration
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.text.TextUtils
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView

/**
 * LSPosed 模块设置界面。
 * 纯代码构建 UI，无需 XML/AppCompat，最小化依赖。
 * 支持跟随系统深色/浅色模式。
 *
 * 开关值保存在 MODE_WORLD_READABLE SharedPreferences；
 * MainHook 在每次 handleLoadPackage 时通过 XSharedPreferences 读取。
 */
class SettingsActivity : Activity() {

    // ── 颜色方案（随系统深浅色动态计算）────────────────────────────────
    private val isDark get() =
        (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) ==
                Configuration.UI_MODE_NIGHT_YES

    private val colorBackground  get() = if (isDark) Color.parseColor("#1C1C1E") else Color.parseColor("#F2F2F7")
    private val colorCard        get() = if (isDark) Color.parseColor("#2C2C2E") else Color.WHITE
    private val colorPrimary     get() = if (isDark) Color.WHITE                 else Color.parseColor("#1C1C1E")
    private val colorSecondary   get() = if (isDark) Color.parseColor("#8E8E93") else Color.parseColor("#8E8E93")
    private val colorSectionLabel get() = if (isDark) Color.parseColor("#8E8E93") else Color.parseColor("#6D6D72")
    private val colorDivider     get() = if (isDark) Color.parseColor("#38383A") else Color.parseColor("#C6C6C8")

    private data class PrefEntry(
        val key: String,
        val title: String,
        val summary: String,
        val defaultValue: Boolean
    )

    private data class Section(val label: String, val entries: List<PrefEntry>)

    private val sections = listOf(
        Section("抓包工具辅助", listOf(
            PrefEntry(HookPrefs.KEY_BYPASS_SSL, "绕过 SSL Pinning",
                "禁用证书校验与 HostnameVerifier，用于抓包分析", true),
            PrefEntry(HookPrefs.KEY_DISABLE_HTTPDNS, "禁用阿里云 HttpDNS",
                "阻止 OSS SDK 使用 IP 直连，使抓包代理可以正常捕获上传流量", true),
        )),
        Section("广告屏蔽", listOf(
            PrefEntry(HookPrefs.KEY_DISABLE_ADS, "去广告（拦截 SDK 初始化）",
                "阻止 YFAds / 北智融合 / 快手 KsAd 等 SDK 完成初始化", true),
            PrefEntry(HookPrefs.KEY_SKIP_SPLASH_AD, "跳过启动广告",
                "拦截 SplashActivity 中的开屏广告展示，直接进入主界面", true),
        )),
        Section("反检测", listOf(
            PrefEntry(HookPrefs.KEY_FAKE_STACK, "伪造调用栈帧",
                "Zygote 级别 Hook，伪造 Thread/Throwable.getStackTrace()、StackTraceElement 等", true),
            PrefEntry(HookPrefs.KEY_BYPASS_PROXY, "屏蔽代理检测",
                "拦截 C16270p2.m72734R()，规避 error_code 3009", true),
            PrefEntry(HookPrefs.KEY_BYPASS_ROOT, "屏蔽 Root 检测",
                "拦截 C16270p2.m72726J()，规避 error_code 4004（Root）", true),
            PrefEntry(HookPrefs.KEY_BYPASS_DEBUGGER, "屏蔽调试器检测",
                "拦截 Debug.isDebuggerConnected + C16270p2.m72766x()，规避 error_code 4004（调试器）", true),
            PrefEntry(HookPrefs.KEY_BYPASS_VAPP, "屏蔽虚拟环境检测",
                "拦截 C16270p2.m72733Q / m72767y()，规避 error_code 4005", true),
            PrefEntry(HookPrefs.KEY_BYPASS_FRIDA, "屏蔽 Frida 检测（实验）",
                "开启后在 native 层对疑似 Frida 检测触发的 SIGILL 线程做熔断，降低附加时闪退概率", false),
        )),
        Section("扫码登录（免微信客户端）", listOf(
            PrefEntry(HookPrefs.KEY_SCAN_ON, "启用扫码登录注入",
                "PC 端 WeAuth 扫码获取 openid+access_token 后填入下方，点乐跑微信登录即自动注入", false),
        )),
        Section("调试", listOf(
            PrefEntry(HookPrefs.KEY_VERBOSE_LOG, "详细日志",
                "在 logcat 中输出每个 Hook 命中记录（调试用）", false),
            PrefEntry(HookPrefs.KEY_LOG_REGISTER_NATIVES, "打印 RegisterNatives 偏移",
                "输出 native 方法绑定信息（class/name/signature/module/base/offset），用于定位极验 getData 实际实现", false),
        )),
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        buildUi()
    }

    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        buildUi()
    }

    @Suppress("DEPRECATION")
    private fun buildUi() {
        val prefs = getSharedPreferences(HookPrefs.PREFS_NAME, Context.MODE_WORLD_READABLE)

        val root = ScrollView(this).apply {
            setBackgroundColor(colorBackground)
        }

        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, dp(16), 0, dp(32))
        }

        container.addView(buildSectionHeader("Tanke LSPosed Hook"))
        container.addView(buildCaption("设置将在下次目标应用启动时生效"))

        for (section in sections) {
            container.addView(buildSectionLabel(section.label))
            val card = buildCard()
            section.entries.forEachIndexed { index, entry ->
                val current = prefs.getBoolean(entry.key, entry.defaultValue)
                card.addView(buildSwitchRow(entry, current, prefs, index < section.entries.size - 1))
            }
            container.addView(card)
        }

        container.addView(buildCaption("部分功能需要 LSPosed 框架版本 >= 1.9.2，且模块已激活作用域为 com.lptiyu.tanke。"))

        // ── 扫码登录凭据输入区 ────────────────────────────────
        container.addView(buildSectionLabel("扫码登录凭据（WeAuth 获取）"))
        val credCard = buildCard()
        credCard.addView(buildInputRow("OpenID", HookPrefs.KEY_SCAN_OPENID, prefs))
        credCard.addView(buildDivider())
        credCard.addView(buildInputRow("Access Token", HookPrefs.KEY_SCAN_TOKEN, prefs))
        credCard.addView(buildDivider())
        credCard.addView(buildInputRow("Refresh Token（选填，自动续期）", HookPrefs.KEY_SCAN_REFRESH, prefs))
        credCard.addView(buildDivider())
        credCard.addView(buildInputRow("昵称（可选）", HookPrefs.KEY_SCAN_NICK, prefs))
        credCard.addView(buildDivider())
        credCard.addView(buildInputRow("头像 URL（可选）", HookPrefs.KEY_SCAN_AVATAR, prefs))
        container.addView(credCard)
        container.addView(buildCaption("凭据来源：手机装微信→登乐跑→root 抠 /data/data/com.lptiyu.tanke/files/Pers/cn_sharesdk_weibodb_Wechat_1 → 卸微信。填 openid + refresh token 即可（access token 留空，模块自动刷新）。填好后打开上方开关，重启步道乐跑——到登录页 1.5 秒后自动注入，无需点任何按钮。"))

        root.addView(container)
        setContentView(root)
        title = "Tanke Hook 设置"

        window.statusBarColor = colorBackground
        window.navigationBarColor = colorBackground
    }

    @Suppress("DEPRECATION")
    private fun buildSwitchRow(
        entry: PrefEntry,
        initialValue: Boolean,
        prefs: android.content.SharedPreferences,
        showDivider: Boolean
    ): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(16), dp(14), dp(12), dp(14))
            gravity = Gravity.CENTER_VERTICAL
            setBackgroundColor(colorCard)
        }

        val texts = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        val titleView = TextView(this).apply {
            text = entry.title
            textSize = 16f
            setTextColor(colorPrimary)
            setTypeface(typeface, Typeface.NORMAL)
        }
        val summaryView = TextView(this).apply {
            text = entry.summary
            textSize = 13f
            setTextColor(colorSecondary)
            maxLines = 2
            ellipsize = TextUtils.TruncateAt.END
        }
        texts.addView(titleView)
        texts.addView(summaryView)

        val toggle = Switch(this).apply {
            isChecked = initialValue
            setOnCheckedChangeListener { _, isChecked ->
                prefs.edit().putBoolean(entry.key, isChecked).apply()
            }
        }

        row.addView(texts)
        row.addView(toggle)

        if (!showDivider) return row

        val wrapper = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        wrapper.addView(row)
        wrapper.addView(View(this).apply {
            setBackgroundColor(colorDivider)
            val lp = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 1
            ).apply { marginStart = dp(16) }
            layoutParams = lp
        })
        return wrapper
    }

    private fun buildCard(): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(colorCard)
            val lp = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(dp(16), 0, dp(16), dp(8))
            }
            layoutParams = lp
            elevation = dp(2).toFloat()
        }
    }

    private fun buildDivider(): View {
        return View(this).apply {
            setBackgroundColor(colorDivider)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 1
            ).apply { marginStart = dp(16) }
        }
    }

    private fun buildInputRow(
        label: String,
        key: String,
        prefs: android.content.SharedPreferences
    ): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(12), dp(16), dp(12))
            setBackgroundColor(colorCard)
        }
        val labelView = TextView(this).apply {
            text = label
            textSize = 13f
            setTextColor(colorSecondary)
        }
        val input = android.widget.EditText(this).apply {
            setText(prefs.getString(key, "") ?: "")
            textSize = 14f
            setTextColor(colorPrimary)
            isSingleLine = true
            setOnFocusChangeListener { _, hasFocus ->
                if (!hasFocus) {
                    prefs.edit().putString(key, text.toString().trim()).apply()
                }
            }
        }
        row.addView(labelView)
        row.addView(input)
        return row
    }

    private fun buildSectionHeader(text: String): View {
        return TextView(this).apply {
            this.text = text
            textSize = 22f
            setTypeface(typeface, Typeface.BOLD)
            setTextColor(colorPrimary)
            val lp = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(dp(20), dp(8), dp(20), dp(4)) }
            layoutParams = lp
        }
    }

    private fun buildSectionLabel(text: String): View {
        return TextView(this).apply {
            this.text = text.uppercase()
            textSize = 12f
            setTextColor(colorSectionLabel)
            val lp = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(dp(32), dp(20), dp(32), dp(6)) }
            layoutParams = lp
        }
    }

    private fun buildCaption(text: String): View {
        return TextView(this).apply {
            this.text = text
            textSize = 12f
            setTextColor(colorSecondary)
            val lp = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(dp(32), dp(4), dp(32), dp(4)) }
            layoutParams = lp
        }
    }

    private fun dp(value: Int): Int {
        return (value * resources.displayMetrics.density + 0.5f).toInt()
    }
}
