package com.lptiyu.tanke.hook

import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import org.json.JSONObject

/**
 * 扫码登录（免微信客户端）注入模块。
 *
 * 原理（逆向 com.lptiyu.tanke 4.1.5，classes5.dex）：
 *  - 微信登录按钮 → com.lptiyu.tanke.utils.q2.e()：
 *      检查微信已安装（v0.a("com.tencent.mm", cb)）→ SendAuth.Req scope=snsapi_userinfo
 *  - 授权完成回调链 q2.onComplete → q2.d(openid, 3, icon, name, ...)：
 *      POST {api}/Login/quickLoginV339  openid + accesstoken(pref user_access_token) + type=3
 *  - q2.f(String json)：解析 {"openid","nickname","headimgurl",...}，写 nickname/avatar 偏好后调 d()。
 *      注意 f() 不写 accesstoken，d() 从 h.x.c.q.a.S()（pref user_access_token）读取 → 注入前必须先写。
 *
 * 注入流程：
 *  PC 端 WeAuth（微信协议扫码）拿到 access_token/openid → 粘贴到模块设置
 *  → 用户点乐跑"微信登录" → 本模块拦截 q2.e()：
 *      1. 写 user_access_token 偏好（h.x.c.q.a 的 setter，第269行 f2.j(f.E, str) 所在方法）
 *      2. 构造 f() 格式 JSON，callMethod(q2Instance, "f", json)
 *      3. 跳过原 e()（不拉起微信）
 *  兜底：hook v0.a(...) 返回 true 过"未安装微信"检查；hook Wechat.checkAuthorize 直接注入。
 */
object ScanLoginHooks {

    private var installed = false
    /** 捕获的 q2(ThirdLoginHelper) 实例，兜底路径需要 */
    @Volatile private var helperInstance: Any? = null

    fun install(classLoader: ClassLoader) {
        if (!HookPrefs.scanOn) return
        if (installed) return
        installed = true

        hookHelperConstructor(classLoader)
        hookLoginEntry(classLoader)
        hookWechatInstalledCheck(classLoader)
        hookShareSdkAuthorize(classLoader)
    }

    // ── 捕获 q2 实例（兜底注入用）──────────────────────────────

    private fun hookHelperConstructor(classLoader: ClassLoader) {
        try {
            XposedHelpers.findAndHookConstructor(
                "com.lptiyu.tanke.utils.q2", classLoader,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        helperInstance = param.thisObject
                        HookPrefs.vlog("ScanLogin: captured ThirdLoginHelper instance")
                    }
                }
            )
        } catch (t: Throwable) {
            XposedBridge.log("TankeHook[ScanLogin]: q2 ctor hook failed: ${t.message}")
        }
    }

    // ── 主注入点：q2.e()（微信登录按钮逻辑）───────────────────

    private fun hookLoginEntry(classLoader: ClassLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                "com.lptiyu.tanke.utils.q2", classLoader, "e",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        if (!injectCredentials(param.thisObject)) return
                        param.result = null   // 跳过原逻辑：不检查微信、不拉起 SendAuth
                    }
                }
            )
            XposedBridge.log("TankeHook[ScanLogin]: hooked q2.e() (login button)")
        } catch (t: Throwable) {
            XposedBridge.log("TankeHook[ScanLogin]: q2.e hook failed: ${t.message}")
        }
    }

    // ── 过"未安装微信"检查（v0.a 包名检测）────────────────────

    private fun hookWechatInstalledCheck(classLoader: ClassLoader) {
        for (sig in arrayOf(
            arrayOf<Any>("com.lptiyu.tanke.utils.v0", "a", String::class.java, "h.x.c.t.q"),
            arrayOf<Any>("com.lptiyu.tanke.utils.v0", "a", String::class.java)
        )) {
            try {
                val argTypes = sig.drop(2).map { t ->
                    @Suppress("UNCHECKED_CAST")
                    if (t is String && t.startsWith("h.x.")) XposedHelpers.findClass(t as String, classLoader)
                    else t as Class<*>
                }.toTypedArray()
                XposedHelpers.findAndHookMethod(
                    sig[0] as String, classLoader, sig[1] as String, *argTypes,
                    object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            val pkg = param.args.filterIsInstance<String>().firstOrNull()
                            if (pkg == "com.tencent.mm") {
                                HookPrefs.vlog("ScanLogin: faking WeChat installed")
                                param.result = true
                            }
                        }
                    }
                )
                XposedBridge.log("TankeHook[ScanLogin]: hooked v0.a(${argTypes.joinToString { it.toString() }})")
                break
            } catch (_: Throwable) { /* try next signature */ }
        }
    }

    // ── 兜底：ShareSDK Wechat.checkAuthorize → 直接注入 ─────────

    private fun hookShareSdkAuthorize(classLoader: ClassLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                "cn.sharesdk.wechat.friends.Wechat", classLoader, "checkAuthorize",
                Int::class.javaPrimitiveType, Object::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val helper = helperInstance ?: run {
                            // 没捕获到实例则放行原逻辑
                            return
                        }
                        if (injectCredentials(helper)) {
                            param.result = true
                        }
                    }
                }
            )
            XposedBridge.log("TankeHook[ScanLogin]: hooked Wechat.checkAuthorize (fallback)")
        } catch (t: Throwable) {
            XposedBridge.log("TankeHook[ScanLogin]: checkAuthorize hook failed: ${t.message}")
        }
    }

    // ── 核心注入：写 accesstoken 偏好 → 调 f(json) ─────────────

    private fun injectCredentials(helper: Any?): Boolean {
        if (helper == null) return false
        val openid = HookPrefs.scanOpenid
        val token = HookPrefs.scanToken
        if (openid.isBlank() || token.isBlank()) {
            XposedBridge.log("TankeHook[ScanLogin]: credentials missing (openid/token empty), skip")
            return false
        }
        return try {
            // 1. accesstoken 写入 pref user_access_token（q2.d() 会读 a.S()）
            writePrefViaSetter(helper, openid, token)

            // 2. 构造 q2.f() 期望的 JSON 并调用
            val json = JSONObject().apply {
                put("openid", openid)
                put("nickname", HookPrefs.scanNickname.ifBlank { "乐跑用户" })
                put("sex", "1")
                put("province", "")
                put("city", "")
                put("country", "")
                put("headimgurl", HookPrefs.scanAvatar)
                put("unionid", "")
            }
            XposedHelpers.callMethod(helper, "f", json.toString())
            XposedBridge.log("TankeHook[ScanLogin]: injected scan-login credentials ✓")
            true
        } catch (t: Throwable) {
            XposedBridge.log("TankeHook[ScanLogin]: inject failed: ${t}")
            false
        }
    }

    /**
     * 写 lptiyu 偏好：openid → user_openId，accesstoken → user_access_token。
     * 优先用 h.x.c.q.a 的静态 setter（O1 写 f.D；f.E 的 setter 在269行附近，按签名匹配 void(String)），
     * 失败则直接操作底层 f2（SharedPreferences 封装）。
     */
    private fun writePrefViaSetter(helper: Any, openid: String, token: String) {
        try {
            val clsA = XposedHelpers.findClass("h.x.c.q.a", helper.javaClass.classLoader)
            val clsF = XposedHelpers.findClass("h.x.c.q.f", helper.javaClass.classLoader)
            val dField = XposedHelpers.getStaticObjectField(clsF, "D")
            val eField = XposedHelpers.getStaticObjectField(clsF, "E")

            // 遍历 clsA 的静态单参 String 方法，借 f2.j(key, value) 直接写
            val f2Cls = XposedHelpers.findClass("h.x.c.q.f2", helper.javaClass.classLoader)
            var jMethod: java.lang.reflect.Method? = null
            for (m in f2Cls.declaredMethods) {
                if (m.parameterCount == 2 &&
                    m.parameterTypes[0] == String::class.java &&
                    m.parameterTypes[1] == CharSequence::class.java
                ) {
                    jMethod = m; break
                }
            }
            if (jMethod == null) {
                for (m in f2Cls.declaredMethods) {
                    if (m.parameterCount == 2 && m.parameterTypes.all { it == String::class.java }) {
                        jMethod = m; break
                    }
                }
            }
            if (jMethod != null) {
                jMethod.isAccessible = true
                jMethod.invoke(null, dField, openid)
                jMethod.invoke(null, eField, token)
                HookPrefs.vlog("ScanLogin: prefs written via f2.j(user_openId/user_access_token)")
                return
            }
            throw IllegalStateException("f2.j(String,String) not found")
        } catch (t: Throwable) {
            XposedBridge.log("TankeHook[ScanLogin]: writePrefViaSetter failed: ${t.message} (trying setter fallback)")
            // 兜底：a.O1(String) 写 openid；accesstoken setter 按行为匹配
            try {
                val clsA = XposedHelpers.findClass("h.x.c.q.a", helper.javaClass.classLoader)
                XposedHelpers.callStaticMethod(clsA, "O1", openid)
                XposedBridge.log("TankeHook[ScanLogin]: openid written via a.O1; token NOT written — check logs")
            } catch (t2: Throwable) {
                XposedBridge.log("TankeHook[ScanLogin]: setter fallback failed too: ${t2.message}")
            }
        }
    }
}
