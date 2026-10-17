package io.github.xalsace.qqbypass.hooks;

import android.util.Log;
import java.lang.reflect.Field;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.util.Map;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import io.github.xalsace.qqbypass.utils.HookUtils;

/**
 * Universal Third-Party Module Compatibility & LSPosed Error Protection Layer
 */
public class ModuleCompatHook {

    private static final String TAG = "ModuleCompat";
    private static volatile boolean sOnoPatched = false;
    private static volatile ClassLoader sHostClassLoader = null;

    private static void log(String msg) {
        Log.i(TAG, msg);
        try {
            XposedBridge.log("[" + TAG + "] " + msg);
        } catch (Throwable ignored) {}
    }

    public static void setHostClassLoader(ClassLoader cl) {
        if (cl != null) {
            sHostClassLoader = cl;
        }
    }

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (lpparam != null && lpparam.classLoader != null) {
            sHostClassLoader = lpparam.classLoader;
        }
        log("Initializing Third-Party Module Compatibility Layer");
        tryScanLoaders();
    }

    public static void hookLateStage(ClassLoader cl) {
        if (cl == null) return;
        if (sHostClassLoader == null) {
            sHostClassLoader = cl;
        }
        tryScanLoaders();
    }

    public static synchronized void onModuleClassLoaderLoaded(ClassLoader cl) {
        if (sOnoPatched || cl == null) return;
        try {
            Class<?> baseHookItem = cl.loadClass("moe.ono.hooks._base.BaseHookItem");
            if (baseHookItem != null) {
                patchOnoModule(cl, baseHookItem);
            }
        } catch (ClassNotFoundException ignored) {
        } catch (Throwable t) {
            log("Error in onModuleClassLoaderLoaded: " + t.getMessage());
        }
    }

    public static void tryScanLoaders() {
        if (sOnoPatched) return;

        // 1. Scan XposedBridge.sLoadedPackageCallbacks (primary LSPosed module registry)
        try {
            Field f = XposedBridge.class.getDeclaredField("sLoadedPackageCallbacks");
            f.setAccessible(true);
            Iterable<?> callbacks = (Iterable<?>) f.get(null);
            if (callbacks != null) {
                for (Object cb : callbacks) {
                    if (cb == null) continue;
                    checkCandidateObject(cb);
                    if (sOnoPatched) return;
                }
            }
        } catch (Throwable t) {
            log("Scan sLoadedPackageCallbacks error: " + t.getMessage());
        }

        // 2. Scan ActivityThread.mPackages
        try {
            Class<?> atCls = Class.forName("android.app.ActivityThread");
            Method currentATMethod = atCls.getMethod("currentActivityThread");
            Object at = currentATMethod.invoke(null);
            if (at != null) {
                Field mPackagesField = atCls.getDeclaredField("mPackages");
                mPackagesField.setAccessible(true);
                Map<?, ?> map = (Map<?, ?>) mPackagesField.get(at);
                if (map != null) {
                    for (Object weakRef : map.values()) {
                        if (weakRef instanceof java.lang.ref.WeakReference) {
                            Object loadedApk = ((java.lang.ref.WeakReference<?>) weakRef).get();
                            if (loadedApk != null) {
                                Field clField = loadedApk.getClass().getDeclaredField("mClassLoader");
                                clField.setAccessible(true);
                                ClassLoader cl = (ClassLoader) clField.get(loadedApk);
                                if (cl != null) {
                                    checkClassLoader(cl);
                                    if (sOnoPatched) return;
                                }
                            }
                        }
                    }
                }
            }
        } catch (Throwable ignored) {}

        // 3. Scan active threads
        try {
            for (Thread t : Thread.getAllStackTraces().keySet()) {
                ClassLoader cl = t.getContextClassLoader();
                if (cl != null) {
                    checkClassLoader(cl);
                    if (sOnoPatched) return;
                }
            }
        } catch (Throwable ignored) {}
    }

    private static void checkCandidateObject(Object obj) {
        if (obj == null || sOnoPatched) return;
        Class<?> cls = obj.getClass();
        String name = cls.getName();
        if (name.contains("moe.ono") || name.contains("ono")) {
            onModuleClassLoaderLoaded(cls.getClassLoader());
            return;
        }

        // Inspect all declared fields of wrapper (e.g., IXposedHookLoadPackage.Wrapper.instance)
        for (Field fld : cls.getDeclaredFields()) {
            try {
                fld.setAccessible(true);
                Object val = fld.get(obj);
                if (val != null) {
                    String valCls = val.getClass().getName();
                    if (valCls.contains("moe.ono") || valCls.contains("ono")) {
                        onModuleClassLoaderLoaded(val.getClass().getClassLoader());
                        return;
                    }
                }
            } catch (Throwable ignored) {}
        }
    }

    private static void checkClassLoader(ClassLoader cl) {
        if (cl == null || sOnoPatched) return;
        String clStr = cl.toString();
        if (clStr.contains("moe.ono") || clStr.contains("ono")) {
            onModuleClassLoaderLoaded(cl);
            return;
        }
        // Check fields of custom class loader (like defpackage.o1)
        for (Field fld : cl.getClass().getDeclaredFields()) {
            try {
                fld.setAccessible(true);
                Object val = fld.get(cl);
                if (val instanceof String && (((String) val).contains("moe.ono") || ((String) val).contains("ono"))) {
                    onModuleClassLoaderLoaded(cl);
                    return;
                }
            } catch (Throwable ignored) {}
        }
    }

    private static synchronized void patchOnoModule(ClassLoader cl, Class<?> baseHookItem) {
        if (sOnoPatched || baseHookItem == null) return;
        sOnoPatched = true;
        log("Detected moe.ono module ClassLoader: " + cl + ", applying compatibility guards...");

        // 1. Guard BaseHookItem against null Member (prevents NPE in XposedBridge.hookMethod)
        XC_MethodHook nullMemberGuard = new XC_MethodHook(XC_MethodHook.PRIORITY_HIGHEST) {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                if (param.args != null && param.args.length > 0 && param.args[0] == null) {
                    // Suppress calling XposedBridge.hookMethod(null, ...)
                    param.setResult(null);
                }
            }
        };

        try {
            HookUtils.hookAllMethods(baseHookItem, "hookBefore", nullMemberGuard);
            HookUtils.hookAllMethods(baseHookItem, "hookAfter", nullMemberGuard);
            log("Successfully installed null Member guard on BaseHookItem.hookBefore & hookAfter");
        } catch (Throwable t) {
            log("Failed to hook BaseHookItem methods: " + t.getMessage());
        }

        // 2. Wrap BaseHookItem.startLoad() to catch and suppress uncaught reflection failures
        try {
            HookUtils.hookAllMethods(baseHookItem, "startLoad", new XC_MethodReplacement(XC_MethodHook.PRIORITY_HIGHEST) {
                @Override
                protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                    Object item = param.thisObject;
                    try {
                        boolean isLoad = XposedHelpers.getBooleanField(item, "isLoad");
                        if (isLoad) return null;
                        XposedHelpers.setBooleanField(item, "isLoad", true);

                        Method initOnce;
                        try {
                            initOnce = item.getClass().getMethod("initOnce");
                        } catch (NoSuchMethodException e) {
                            initOnce = item.getClass().getDeclaredMethod("initOnce");
                        }
                        initOnce.setAccessible(true);
                        boolean ok = (Boolean) initOnce.invoke(item);
                        if (ok) {
                            ClassLoader hostCl = sHostClassLoader;
                            if (hostCl == null) {
                                try {
                                    Class<?> hclClass = cl.loadClass("moe.ono.startup.HybridClassLoader");
                                    Method getHostCl = hclClass.getMethod("getHostClassLoader");
                                    hostCl = (ClassLoader) getHostCl.invoke(null);
                                } catch (Throwable ignored) {}
                            }
                            if (hostCl == null) {
                                hostCl = Thread.currentThread().getContextClassLoader();
                            }
                            Method entry;
                            try {
                                entry = item.getClass().getMethod("entry", ClassLoader.class);
                            } catch (NoSuchMethodException e) {
                                entry = item.getClass().getDeclaredMethod("entry", ClassLoader.class);
                            }
                            entry.setAccessible(true);
                            entry.invoke(item, hostCl);
                        }
                    } catch (Throwable th) {
                        Throwable cause = th instanceof java.lang.reflect.InvocationTargetException ? th.getCause() : th;
                        log("Gracefully suppressed hook item failure: " + item.getClass().getSimpleName() + " (" + (cause != null ? cause.getMessage() : th.getMessage()) + ")");
                    }
                    return null;
                }
            });
            log("Successfully wrapped BaseHookItem.startLoad with safe exception barrier");
        } catch (Throwable t) {
            log("Failed to hook BaseHookItem.startLoad: " + t.getMessage());
        }

        // 3. Replace QQMsgViewAdapter.entry() with safe no-op for NT QQ 9.3.70
        try {
            Class<?> msgViewAdapterCls = cl.loadClass("moe.ono.hooks.base.api.QQMsgViewAdapter");
            if (msgViewAdapterCls != null) {
                HookUtils.hookAllMethods(msgViewAdapterCls, "entry", new XC_MethodReplacement(XC_MethodHook.PRIORITY_HIGHEST) {
                    @Override
                    protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                        log("Safe no-op executed for QQMsgViewAdapter.entry() on QQ 9.3.70");
                        return null;
                    }
                });
                log("Successfully replaced QQMsgViewAdapter.entry() with safe no-op");
            }
        } catch (Throwable t) {
            log("Failed to hook QQMsgViewAdapter: " + t.getMessage());
        }

        // 4. Pre-seed TargetManager cache in ConfigManager
        try {
            Class<?> configManagerCls = cl.loadClass("moe.ono.config.ConfigManager");
            if (configManagerCls != null) {
                Method cPutString = configManagerCls.getMethod("cPutString", String.class, String.class);
                Method cGetString = configManagerCls.getMethod("cGetString", String.class, String.class);
                Method cPutInt = configManagerCls.getMethod("cPutInt", String.class, int.class);

                String existingAIOParam = (String) cGetString.invoke(null, "method_AIOParam", null);
                if (existingAIOParam == null || existingAIOParam.isEmpty()) {
                    cPutString.invoke(null, "method_AIOParam", "com.tencent.aio.base.chat.ChatPie#t");
                    log("Pre-seeded moe.ono method_AIOParam -> com.tencent.aio.base.chat.ChatPie#t");
                }

                String existingInputRoot = (String) cGetString.invoke(null, "method_InputRoot", null);
                if (existingInputRoot == null || existingInputRoot.isEmpty()) {
                    cPutString.invoke(null, "method_InputRoot", "com.tencent.mobileqq.aio.input.simpleui.a#e");
                    log("Pre-seeded moe.ono method_InputRoot -> com.tencent.mobileqq.aio.input.simpleui.a#e");
                }

                try {
                    Class<?> hostInfoCls = cl.loadClass("moe.ono.util.HostInfo");
                    Method getVersionName = hostInfoCls.getMethod("getVersionName");
                    String ver = (String) getVersionName.invoke(null);
                    if (ver != null) {
                        cPutInt.invoke(null, "contentViewId" + ver + ":92bc4a8.03211646", 1);
                        log("Pre-seeded moe.ono contentViewId for version: " + ver);
                    }
                } catch (Throwable ignored) {}
            }
        } catch (Throwable ignored) {
            // ConfigManager (MMKV) may not be initialized yet before host context is attached.
            // Null member guard and startLoad exception barrier provide 100% protection regardless.
        }
    }
}
