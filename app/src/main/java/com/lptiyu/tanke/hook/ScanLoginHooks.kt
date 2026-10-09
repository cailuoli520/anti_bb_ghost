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
    private var q2Hooked = false
    private var v0Hooked = false
    private var checkAuthHooked = false
    private var shareSdkHooked = false
    private var injectedOnce = false
    /** 捕获的 q2(ThirdLoginHelper) 实例，兜底路径需要 */
    @Volatile private var helperInstance: Any? = null

    fun install(classLoader: ClassLoader) {
        if (!HookPrefs.scanOn) return
        if (installed) return
        installed = true

        // SecNeo 壳启动时真实类未解密：先注册延迟装钩，
        // 真实类经 ClassLoader.loadClass 加载时由 onClassLoaded 补装。
        installNow(classLoader)   // 万一已解密（热路径）直接装
    }

    /** 装载真实(解密后)类的 ClassLoader —— 由 ClassLoader monitor 回调持续更新。 */
    @Volatile private var realClassLoader: ClassLoader? = null

    /** ClassLoader monitor 回调：目标类真正可用时装钩。 */
    fun onClassLoaded(name: String, loader: ClassLoader, clazz: Class<*>) {
        if (!HookPrefs.scanOn) return
        realClassLoader = loader   // 任何解密类加载都记录其 loader
        when {
            name == "com.lptiyu.tanke.utils.q2" && !q2Hooked -> {
                q2Hooked = true
                hookQ2(loader)
            }
            name == "com.lptiyu.tanke.utils.v0" && !v0Hooked -> {
                v0Hooked = true
                hookWechatInstalledCheck(loader)
            }
            name == "cn.sharesdk.wechat.friends.Wechat" && !checkAuthHooked -> {
                checkAuthHooked = true
                hookShareSdkAuthorize(loader)
            }
            // 万能观测点：任何登录相关 Activity 加载即打日志（诊断用户到底在哪个页面）
            (name == "com.lptiyu.tanke.activities.login.LoginActivity" ||
             name == "com.lptiyu.tanke.activities.BeforeLoginActivity" ||
             name == "com.lptiyu.tanke.activities.LoginHomeActivity" ||
             name == "com.lptiyu.tanke.activities.QrLoginActivity") -> {
                XposedBridge.log("TankeHook[ScanLogin]: login screen loaded → $name")
                hookLoginActivityLifecycle(clazz)
            }
            // ShareSDK.getPlatform("Wechat") — 无论从哪个页面发起的微信授权都经过这里
            name == "cn.sharesdk.framework.ShareSDK" && !shareSdkHooked -> {
                shareSdkHooked = true
                hookShareSdkGetPlatform(loader)
            }
        }
    }

    private fun installNow(classLoader: ClassLoader) {
        try {
            Class.forName("com.lptiyu.tanke.utils.q2", false, classLoader)
            q2Hooked = true; hookQ2(classLoader)
        } catch (_: Throwable) { }
        try {
            Class.forName("com.lptiyu.tanke.utils.v0", false, classLoader)
            v0Hooked = true; hookWechatInstalledCheck(classLoader)
        } catch (_: Throwable) { }
        try {
            Class.forName("cn.sharesdk.wechat.friends.Wechat", false, classLoader)
            checkAuthHooked = true; hookShareSdkAuthorize(classLoader)
        } catch (_: Throwable) { }
        XposedBridge.log("TankeHook[ScanLogin]: installed (q2=$q2Hooked v0=$v0Hooked wx=$checkAuthHooked)")
    }

    private fun hookQ2(classLoader: ClassLoader) {
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
            // 主入口：LoginActivity 微信按钮 → q2.g("Wechat") → ShareSDK.showUser
            XposedHelpers.findAndHookMethod(
                "com.lptiyu.tanke.utils.q2", classLoader, "g", String::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val plat = param.args[0] as? String ?: return
                        if (plat != "Wechat" && plat != "WechatFavorites" && plat != q2WechatName()) return
                        if (!injectCredentials(param.thisObject)) return
                        param.result = null   // 跳过 showUser 整条授权链
                    }
                }
            )
            // 次入口（LoginHomeActivity 旧路径）：q2.e()
            XposedHelpers.findAndHookMethod(
                "com.lptiyu.tanke.utils.q2", classLoader, "e",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        if (!injectCredentials(param.thisObject)) return
                        param.result = null
                    }
                }
            )
            XposedBridge.log("TankeHook[ScanLogin]: hooked q2 ctor + g(String) + e() ✓")
        } catch (t: Throwable) {
            XposedBridge.log("TankeHook[ScanLogin]: q2 hook failed: ${t}")
        }
    }

    private fun q2WechatName(): String {
        return try {
            // q2.b 常量 = Wechat.NAME；不可达时用字面量
            "Wechat"
        } catch (_: Throwable) { "Wechat" }
    }

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

    // ── 登录页生命周期观测 + 自动注入 ──────────────────────────

    private fun hookLoginActivityLifecycle(clazz: Class<*>) {
        try {
            XposedHelpers.findAndHookMethod(
                clazz, "onCreate", android.os.Bundle::class.java,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        XposedBridge.log("TankeHook[ScanLogin]: ${clazz.simpleName}.onCreate ✓ (user is on this screen)")
                        // LoginHomeActivity 到达即自动注入（native 按钮不可 hook，绕开 UI）
                        if (clazz.simpleName == "LoginHomeActivity") {
                            val act = param.thisObject
                            android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
                                autoInject(act)
                            }, 1500)
                        }
                    }
                }
            )
        } catch (_: Throwable) { }
    }

    /**
     * 自动注入：构造 q2(ThirdLoginHelper) 实例（反射），写入凭据偏好后调 f(json)。
     * q2 无参构造 → h(str)/k(str) 等 setter 填 school/appToken（可空字符串）→ f(json) → d() 登录。
     */
    /** 枚举进程内所有 ClassLoader，找到能加载目标类的那个。 */
    private fun findLoaderAnywhere(className: String): ClassLoader? {
        // 1) monitor 记录的解密类 loader
        realClassLoader?.let { cl ->
            try { Class.forName(className, false, cl); return cl } catch (_: Throwable) {}
        }
        // 2) 遍历所有线程的 contextClassLoader + 已知 loader 树
        val seen = HashSet<ClassLoader>()
        fun tryCl(cl: ClassLoader?): Boolean {
            if (cl == null || !seen.add(cl)) return false
            return try { Class.forName(className, false, cl); true } catch (_: Throwable) { false }
        }
        // 当前线程 ctx
        var cl = Thread.currentThread().contextClassLoader
        if (tryCl(cl)) return cl
        // 所有线程
        var found: ClassLoader? = null
        Thread.getAllStackTraces().keys.forEach { t ->
            if (found == null) {
                val c = t.contextClassLoader
                if (tryCl(c)) found = c
            }
        }
        found?.let { return it }
        // 系统的 application 的 classLoader（Android App 的 PathClassLoader 链含壳注入的 dex）
        try {
            val app = Class.forName("android.app.ActivityThread")
                .getMethod("currentApplication").invoke(null)
            val c = app?.javaClass?.classLoader
            if (tryCl(c)) return c
            // 还可以遍历它的 parent 链
            var p = c?.parent
            while (p != null) {
                if (tryCl(p)) return p
                p = p.parent
            }
        } catch (_: Throwable) {}
        return null
    }

    private fun autoInject(activity: Any?) {
        if (injectedOnce) return
        if (HookPrefs.scanOpenid.isBlank() || (HookPrefs.scanToken.isBlank() && HookPrefs.scanRefresh.isBlank())) {
            XposedBridge.log("TankeHook[ScanLogin]: autoInject skipped — credentials empty")
            return
        }
        injectedOnce = true
        Thread {
            try {
                val fresh = refreshWxToken()
                if (fresh != null) {
                    HookPrefs.scanToken = fresh
                    XposedBridge.log("TankeHook[ScanLogin]: wx access_token refreshed ✓")
                } else if (HookPrefs.scanToken.isBlank()) {
                    XposedBridge.log("TankeHook[ScanLogin]: no token and refresh failed — abort")
                    return@Thread
                }
                val cl = findLoaderAnywhere("com.lptiyu.tanke.utils.q2")
                if (cl == null) {
                    XposedBridge.log("TankeHook[ScanLogin]: q2 classloader NOT found in process — dump loaders")
                    Thread.getAllStackTraces().keys.forEach { t ->
                        XposedBridge.log("TankeHook[ScanLogin]:   thread ${t.name} ctx=${t.contextClassLoader}")
                    }
                    return@Thread
                }
                XposedBridge.log("TankeHook[ScanLogin]: q2 loader found: $cl")
                val q2cls = XposedHelpers.findClass("com.lptiyu.tanke.utils.q2", cl)
                val helper = q2cls.getDeclaredConstructor().newInstance()
                try { XposedHelpers.callMethod(helper, "h", "") } catch (_: Throwable) {}
                try { XposedHelpers.callMethod(helper, "k", "") } catch (_: Throwable) {}
                injectCredentials(helper)
            } catch (t: Throwable) {
                XposedBridge.log("TankeHook[ScanLogin]: autoInject failed: ${t}")
            }
        }.start()
    }

    /** 用 refresh_token 换新 access_token（在目标 app 进程内执行，网络可用）。 */
    private fun refreshWxToken(): String? {
        return try {
            val rt = HookPrefs.scanRefresh
            if (rt.isBlank()) return null
            Thread.sleep(50) // 已在后台线程
            val url = java.net.URL(
                "https://api.weixin.qq.com/sns/oauth2/refresh_token?appid=wx5a2e1ff396785475" +
                "&grant_type=refresh_token&refresh_token=" + java.net.URLEncoder.encode(rt, "UTF-8")
            )
            val conn = url.openConnection() as java.net.HttpURLConnection
            conn.connectTimeout = 8000; conn.readTimeout = 8000
            val body = conn.inputStream.bufferedReader().readText()
            conn.disconnect()
            XposedBridge.log("TankeHook[ScanLogin]: refresh resp: ${body.take(80)}")
            val jo = org.json.JSONObject(body)
            if (jo.has("access_token")) jo.getString("access_token") else null
        } catch (t: Throwable) {
            XposedBridge.log("TankeHook[ScanLogin]: refreshWxToken failed: ${t}")
            null
        }
    }

    // ── ShareSDK.getPlatform 万能拦截：任何来源的 Wechat 授权 ──

    private fun hookShareSdkGetPlatform(classLoader: ClassLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                "cn.sharesdk.framework.ShareSDK", classLoader, "getPlatform", String::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val name = param.args[0] as? String ?: return
                        if (name != "Wechat") return
                        XposedBridge.log("TankeHook[ScanLogin]: ShareSDK.getPlatform(\"Wechat\") called — blocking & injecting")
                        if (!injectCredentials(helperInstance)) {
                            // 没有 q2 实例时也先拦截，防拉微信；凭据缺失时记录
                            if (HookPrefs.scanOpenid.isBlank() || HookPrefs.scanToken.isBlank()) {
                                XposedBridge.log("TankeHook[ScanLogin]: credentials EMPTY — check module settings!")
                            } else {
                                XposedBridge.log("TankeHook[ScanLogin]: helper instance not captured yet, cannot inject")
                            }
                        }
                        param.result = null   // 返回 null Platform，阻断授权链
                    }
                }
            )
            XposedBridge.log("TankeHook[ScanLogin]: hooked ShareSDK.getPlatform ✓")
        } catch (t: Throwable) {
            XposedBridge.log("TankeHook[ScanLogin]: ShareSDK.getPlatform hook failed: ${t.message}")
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
