package com.lptiyu.tanke.hook

import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.IXposedHookZygoteInit
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam

/**
 * LSPosed 模块主入口 — 精简调度器。
 *
 * 各功能实现已拆分到独立模块：
 *  - [HookPrefs]            : 偏好设置 key 常量 + 运行时值 + 日志工具
 *  - [StackTraceHooks]      : Zygote 级栈帧伪装（7 个 hook）
 *  - [NetworkHooks]         : SSL/TrustManager/OkHttp/OSS HttpDNS 绕过
 *  - [AdHooks]              : 广告 SDK 初始化拦截 + 开屏广告跳过
 *  - [DetectionBypassHooks] : 代理/Root/调试器/虚拟环境检测绕过
 */
class MainHook : IXposedHookLoadPackage, IXposedHookZygoteInit {

    /** ClassLoader.loadClass 重入保护，防止 hook 回调中再次触发 hook 安装 */
    private val isInstallingHooks: ThreadLocal<Boolean> = ThreadLocal.withInitial { false }
    private var classLoaderMonitorInstalled = false
    private val observedClassNames = HashSet<String>()

    override fun initZygote(startupParam: IXposedHookZygoteInit.StartupParam) {
        HookPrefs.load()
        NativeHelper.install(startupParam.modulePath)
        NativeHelper.setRegisterNativesLogEnabled(HookPrefs.logRegisterNatives)
        NativeHelper.setFridaBypassEnabled(HookPrefs.bypassFrida)
        if (HookPrefs.fakeStack) {
            StackTraceHooks.installZygote()
        }
    }

    override fun handleLoadPackage(lpparam: LoadPackageParam) {
        if (lpparam.packageName != "com.lptiyu.tanke") return
        XposedBridge.log("TankeHook: loading for ${lpparam.packageName}")
        HookPrefs.load()
        NativeHelper.setRegisterNativesLogEnabled(HookPrefs.logRegisterNatives)
        NativeHelper.setFridaBypassEnabled(HookPrefs.bypassFrida)
        if (HookPrefs.logRegisterNatives) {
            NativeHelper.probeStaticJniGetDataSymbols()
        }
        val cl = lpparam.classLoader
        SecNeoHooks.install(cl)
        NetworkHooks.install(cl)
        AdHooks.install(cl)
        DetectionBypassHooks.install(cl)
        GeetestHooks.install(cl)
        ScanLoginHooks.install(cl)
        installClassLoaderMonitor()
    }

    /**
     * 监听 ClassLoader.loadClass，在目标类延迟加载时通知各模块安装 hook。
     * ThreadLocal 重入保护防止 hook 回调中调用 findClass 触发无限递归。
     */
    private fun installClassLoaderMonitor() {
        if (classLoaderMonitorInstalled) return
        classLoaderMonitorInstalled = true
        try {
            val callback = object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    if (isInstallingHooks.get() == true) return
                    val name   = param.args[0] as? String         ?: return
                    if (!isRelevantClassName(name)) return
                    val loader = param.thisObject as? ClassLoader ?: return
                    val clazz  = param.result  as? Class<*>       ?: return
                    synchronized(observedClassNames) {
                        if (!observedClassNames.add(name)) return
                    }
                    isInstallingHooks.set(true)
                    try {
                        if (HookPrefs.logRegisterNatives && name.startsWith("com.geetest.core")) {
                            NativeHelper.probeStaticJniGetDataSymbols()
                        }
                        NetworkHooks.onClassLoaded(name, loader, clazz)
                        AdHooks.onClassLoaded(name, loader, clazz)
                        DetectionBypassHooks.onClassLoaded(name, loader)
                        GeetestHooks.onClassLoaded(name, clazz)
                        ScanLoginHooks.onClassLoaded(name, loader, clazz)
                    } finally {
                        isInstallingHooks.set(false)
                    }
                }
            }
            XposedHelpers.findAndHookMethod(
                ClassLoader::class.java, "loadClass", String::class.java, callback
            )
            XposedHelpers.findAndHookMethod(
                ClassLoader::class.java, "loadClass", String::class.java,
                Boolean::class.javaPrimitiveType, callback
            )
            XposedBridge.log("TankeHook: ClassLoader monitor installed")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: ClassLoader monitor failed: ${e.message}")
        }
    }

    private fun isRelevantClassName(name: String): Boolean {
        if (name == "p1141g.p1147a0.p1158c.utils.p2") return true
        if (name == "com.secneo.apkwrapper.H") return true
        if (name == "com.secneo.apkwrapper.AW") return true
        if (name == "com.secneo.apkwrapper.AP") return true
        if (name.startsWith("com.geetest.core.")) return true
        if (name.startsWith("com.lptiyu.tanke.activities.school_run.RunHelper")) return true
        if (name.startsWith("com.lptiyu.tanke.fragments.TrackFragment")) return true
        if (name.startsWith("com.alibaba.sdk.android.oss")) return true
        if (name.startsWith("okhttp3")) return true
        if (name.startsWith("com.yfanads")) return true
        if (name.startsWith("com.beizi")) return true
        if (name.startsWith("com.kwad")) return true
        if (name.startsWith("com.bytedance.sdk.openadsdk")) return true
        if (name.startsWith("com.lptiyu.tanke") && name.contains("Splash")) return true
        if (name.startsWith("com.lptiyu.tanke.utils.q2")) return true
        if (name.startsWith("com.lptiyu.tanke.utils.v0")) return true
        if (name.startsWith("cn.sharesdk.wechat")) return true
        if (name.startsWith("cn.sharesdk.framework.PlatformDb")) return true
        if (name.startsWith("h.x.c.q.f2")) return true
        if (name.contains("HostnameVerifier")) return true
        return false
    }
}
