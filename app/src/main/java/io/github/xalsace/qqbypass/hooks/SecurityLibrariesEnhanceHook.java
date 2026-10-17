package io.github.xalsace.qqbypass.hooks;

import android.content.Context;
import android.text.TextUtils;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.utils.HookUtils;

/**
 * Enhanced Protection for Security & Diagnostic Libraries:
 * - libbugly_shadowhook.so / libshadowhook.so: com.bytedance.shadowhook.ShadowHook
 * - libqqPerfNativeTool.so: com.tencent.mobileqq.qqperfnativetool.signalTool.SignalCatcherJNI
 * - libandroid_desensitization.so: com.luggage.desensitization.DesensitizationJni
 * - RuntimeEnvCensorTask & FEKit Companion:
 *     com.tencent.mobileqq.fe.utils.a (ClassLoader & dexElements scanner)
 *     com.tencent.mobileqq.dt.app.Dtc (isAbnormalConfig, checkAppInstalled, dtcSendMessage)
 */
public class SecurityLibrariesEnhanceHook {

    private static final Set<String> sHookedClasses =
        Collections.newSetFromMap(new ConcurrentHashMap<>());
    private static final Map<String, List<ClassHookCallback>> sPendingClassHooks =
        new ConcurrentHashMap<>();

    private static final String[] SENSITIVE_STACK_KEYWORDS = {
        "xposed", "lsposed", "lspatch", "qauxv", "qqbypass",
        "native-bypass", "bytehook", "sandhook", "pine", "yahfa",
        "riru", "zygisk", "magisk", "top.nkbe", "npatch",
        "moe.ono", "ono", "lzlnb", "cnm", "xalsace", "canyie"
    };

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        XposedEntry.log("SecurityLibrariesEnhanceHook: Initializing enhanced security and censor hooks");
        ClassLoader cl = lpparam != null && lpparam.classLoader != null ? lpparam.classLoader : HookConfig.getClassLoader();
        hookAll(cl);
    }

    public static void hookLateStage(ClassLoader cl) {
        if (cl == null) return;
        hookAll(cl);
        resolvePendingHooks(cl);
    }

    private static void hookAll(ClassLoader cl) {
        if (cl == null) return;
        hookFEKitAndDtc(cl);
        hookShadowHook(cl);
        hookQQPerfNativeTool(cl);
        hookDesensitization(cl);
        hookRMonitorAndBuglyDumpers(cl);
    }

    /**
     * 1. Neutralize FEKit RuntimeEnvCensor companion classes:
     * - com.tencent.mobileqq.fe.utils.a:
     *     g(Context) -> checks ClassLoader hierarchy and dexElements; returns true if abnormal.
     *     Hook all methods to return false/clean values!
     * - com.tencent.mobileqq.dt.app.Dtc:
     *     isAbnormalConfig() -> delegates to fe.utils.a.g; hook to return false!
     *     checkAppInstalled(String) -> probes root/Xposed packages; hook to return false if suspicious!
     *     getAccessibilityEnabledServiceList(...) -> filter out automation services!
     *     dtcSendMessage(String cmd, byte[] data, long callbackId) -> intercept SSO reports and synthesize 1000 ACK!
     */
    private static void hookFEKitAndDtc(ClassLoader cl) {
        final String feUtilsA = "com.tencent.mobileqq.fe.utils.a";
        hookSafe(cl, feUtilsA, new ClassHookCallback() {
            @Override
            public void onClassFound(Class<?> clazz) {
                // Hook all methods in fe.utils.a to prevent environment anomaly detection
                for (Method m : clazz.getDeclaredMethods()) {
                    Class<?> retType = m.getReturnType();
                    if (retType == boolean.class) {
                        XposedBridge.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                                param.setResult(false);
                            }
                        });
                    } else if (retType == String.class) {
                        XposedBridge.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                                param.setResult("");
                            }
                        });
                    } else if (retType == int.class) {
                        XposedBridge.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                                param.setResult(0);
                            }
                        });
                    }
                }
                XposedEntry.log("[FEKitCensor] Successfully neutralized com.tencent.mobileqq.fe.utils.a");
            }
        });

        final String dtcCls = "com.tencent.mobileqq.dt.app.Dtc";
        hookSafe(cl, dtcCls, new ClassHookCallback() {
            @Override
            public void onClassFound(Class<?> clazz) {
                // 1. isAbnormalConfig -> false
                HookUtils.hookAllMethods(clazz, "isAbnormalConfig", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult(false);
                    }
                });

                // 2. checkAppInstalled -> false for suspicious packages
                HookUtils.hookAllMethods(clazz, "checkAppInstalled", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null && param.args.length > 0 && param.args[0] instanceof String) {
                            String pkg = (String) param.args[0];
                            if (DynamicRootDetectionHook.isSuspiciousPackage(pkg)) {
                                param.setResult(false);
                                XposedEntry.log("[Dtc] Neutralized checkAppInstalled probe: " + pkg);
                            }
                        }
                    }
                });

                // 3. getAccessibilityEnabledServiceList -> empty or safe
                HookUtils.hookAllMethods(clazz, "getAccessibilityEnabledServiceList", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult("");
                    }
                });

                // 4. dtcSendMessage(String cmd, byte[] data, long callbackId) -> intercept SSO report & synthesize 1000 ACK
                HookUtils.hookAllMethods(clazz, "dtcSendMessage", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args == null || param.args.length < 1 || !(param.args[0] instanceof String)) return;
                        String cmd = (String) param.args[0];
                        if (NetworkReportHook.shouldBlock(cmd)) {
                            long callbackId = 0L;
                            if (param.args.length >= 3 && param.args[2] instanceof Number) {
                                callbackId = ((Number) param.args[2]).longValue();
                            }
                            NetworkReportHook.injectNativeReceiveSuccess(cl, cmd, callbackId);
                            // Dtc.dtcSendMessage returns 1 on success
                            param.setResult(1);
                            XposedEntry.log("[Dtc] Intercepted & fulfilled dtcSendMessage: " + cmd + " (cbId=" + callbackId + ")");
                        }
                    }
                });

                XposedEntry.log("[FEKitCensor] Successfully neutralized com.tencent.mobileqq.dt.app.Dtc");
            }
        });
    }

    /**
     * 2. Neutralize ByteDance ShadowHook (libbugly_shadowhook.so / libshadowhook.so):
     * com.bytedance.shadowhook.ShadowHook
     * Prevents Bugly / RMonitor from dumping hooked functions or detecting inline trampolines.
     */
    private static void hookShadowHook(ClassLoader cl) {
        final String shadowHookCls = "com.bytedance.shadowhook.ShadowHook";
        hookSafe(cl, shadowHookCls, new ClassHookCallback() {
            @Override
            public void onClassFound(Class<?> clazz) {
                // nativeGetRecords / getRecords -> empty string
                HookUtils.hookAllMethods(clazz, "nativeGetRecords", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult("");
                    }
                });
                HookUtils.hookAllMethods(clazz, "getRecords", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult("");
                    }
                });

                // nativeGetRecordable / getRecordable -> false
                HookUtils.hookAllMethods(clazz, "nativeGetRecordable", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult(false);
                    }
                });
                HookUtils.hookAllMethods(clazz, "getRecordable", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult(false);
                    }
                });

                // nativeGetDebuggable -> false
                HookUtils.hookAllMethods(clazz, "nativeGetDebuggable", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult(false);
                    }
                });

                // init / b -> 0 (SUCCESS)
                HookUtils.hookAllMethods(clazz, "nativeInit", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult(0);
                    }
                });
                HookUtils.hookAllMethods(clazz, "b", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult(0);
                    }
                });

                XposedEntry.log("[ShadowHook] Successfully neutralized com.bytedance.shadowhook.ShadowHook");
            }
        });
    }

    /**
     * 3. Neutralize QQPerfNativeTool signal reporting:
     * com.tencent.mobileqq.qqperfnativetool.signalTool.SignalCatcherJNI
     * Scrubs stack traces passed to onSignalCaught so Xposed / hook framework frames are never reported.
     */
    private static void hookQQPerfNativeTool(ClassLoader cl) {
        final String signalCatcherCls = "com.tencent.mobileqq.qqperfnativetool.signalTool.SignalCatcherJNI";
        hookSafe(cl, signalCatcherCls, new ClassHookCallback() {
            @Override
            public void onClassFound(Class<?> clazz) {
                // Hook onSignalCaught(int sig, int code, int errno, int arg4, String stackTrace)
                HookUtils.hookAllMethods(clazz, "onSignalCaught", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args == null || param.args.length == 0) return;

                        int sig = 0;
                        if (param.args[0] instanceof Number) {
                            sig = ((Number) param.args[0]).intValue();
                        }

                        // Locate stack trace argument
                        int strIdx = -1;
                        for (int i = param.args.length - 1; i >= 0; i--) {
                            if (param.args[i] instanceof String) {
                                strIdx = i;
                                break;
                            }
                        }

                        if (strIdx >= 0) {
                            String rawTrace = (String) param.args[strIdx];
                            if (rawTrace != null && !rawTrace.isEmpty()) {
                                String cleanTrace = sanitizeStackTrace(rawTrace);
                                param.args[strIdx] = cleanTrace;
                            }
                        }

                        // If signal is self-directed anti-tamper crash (SIGSEGV=11, SIGBUS=7, SIGILL=4, SIGTRAP=5, SIGABRT=6)
                        if (sig == 11 || sig == 7 || sig == 4 || sig == 5 || sig == 6) {
                            XposedEntry.log("[SignalCatcher] Sanitized signal telemetry for sig=" + sig);
                        }
                    }
                });

                // Inhibit unwanted native signal catchers from taking over signal chain
                HookUtils.hookAllMethods(clazz, "initANRSignalCatcher", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult(0);
                    }
                });
                HookUtils.hookAllMethods(clazz, "initNativeCrashSignalCatcher", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult(0);
                    }
                });

                XposedEntry.log("[QQPerfTool] Successfully hooked SignalCatcherJNI");
            }
        });
    }

    /**
     * 4. Neutralize Tencent Luggage Desensitization JNI:
     * com.luggage.desensitization.DesensitizationJni
     */
    private static void hookDesensitization(ClassLoader cl) {
        final String desensCls = "com.luggage.desensitization.DesensitizationJni";
        hookSafe(cl, desensCls, new ClassHookCallback() {
            @Override
            public void onClassFound(Class<?> clazz) {
                XC_MethodHook desensHook = new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null && param.args.length > 0 && param.args[0] instanceof String) {
                            String input = (String) param.args[0];
                            if (input != null) {
                                boolean modified = false;
                                for (String kw : SENSITIVE_STACK_KEYWORDS) {
                                    if (input.toLowerCase().contains(kw)) {
                                        input = input.replaceAll("(?i)" + java.util.regex.Pattern.quote(kw), "normal");
                                        modified = true;
                                    }
                                }
                                if (modified) {
                                    param.args[0] = input;
                                }
                            }
                        }
                    }
                };

                HookUtils.hookAllMethods(clazz, "a", desensHook);
                HookUtils.hookAllMethods(clazz, "nativeStrDesensitizeDetectedContentWithMask", desensHook);
                HookUtils.hookAllMethods(clazz, "nativeStrDesensitizeWithMask", desensHook);

                XposedEntry.log("[Desensitization] Successfully hooked DesensitizationJni");
            }
        });
    }

    private static String sanitizeStackTrace(String rawTrace) {
        if (rawTrace == null || rawTrace.isEmpty()) return rawTrace;
        String[] lines = rawTrace.split("\n");
        StringBuilder sb = new StringBuilder();
        int removedCount = 0;
        for (String line : lines) {
            boolean sensitive = false;
            String lower = line.toLowerCase();
            for (String kw : SENSITIVE_STACK_KEYWORDS) {
                if (lower.contains(kw)) {
                    sensitive = true;
                    break;
                }
            }
            if (!sensitive) {
                sb.append(line).append("\n");
            } else {
                removedCount++;
            }
        }
        if (removedCount > 0) {
            XposedEntry.log("[SignalCatcher] Scrubbed " + removedCount + " sensitive frames from stack trace");
        }
        if (sb.length() == 0) {
            return "java.lang.Throwable: Normal\n\tat android.os.MessageQueue.nativePollOnce(Native Method)\n";
        }
        return sb.toString();
    }

    /**
     * 5. Neutralize RMonitor and Bugly In-Memory Thread & Heap Dumpers (librmonitor_base.so / bytehook)
     */
    private static void hookRMonitorAndBuglyDumpers(ClassLoader cl) {
        // com.tencent.rmonitor.base.thread.suspend.ThreadSuspend: hooks ART stack trace & suspends threads
        hookSafe(cl, "com.tencent.rmonitor.base.thread.suspend.ThreadSuspend", new ClassHookCallback() {
            @Override
            public void onClassFound(Class<?> clazz) {
                for (Method m : clazz.getDeclaredMethods()) {
                    String name = m.getName();
                    if ("nativeHookStackTrace".equals(name)) {
                        XposedBridge.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                                p.setResult(false);
                                XposedEntry.log("[RMonitorPatch] Neutralized ThreadSuspend.nativeHookStackTrace");
                            }
                        });
                    } else if ("nativeInit".equals(name)) {
                        XposedBridge.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                                p.setResult(0);
                                XposedEntry.log("[RMonitorPatch] Neutralized ThreadSuspend.nativeInit");
                            }
                        });
                    } else if ("nativeSuspendThread".equals(name)) {
                        XposedBridge.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                                p.setResult(false);
                            }
                        });
                    } else if ("nativeResumeThread".equals(name)) {
                        XposedBridge.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                                p.setResult(true);
                            }
                        });
                    }
                }
            }
        });

        // com.tencent.bugly.common.heapdump.StripHeapDumper: hooks open/write via ByteHook
        hookSafe(cl, "com.tencent.bugly.common.heapdump.StripHeapDumper", new ClassHookCallback() {
            @Override
            public void onClassFound(Class<?> clazz) {
                for (Method m : clazz.getDeclaredMethods()) {
                    String name = m.getName();
                    if (name.startsWith("nSet") || name.startsWith("nEnable") || name.startsWith("nStrip")) {
                        Class<?> ret = m.getReturnType();
                        if (ret == boolean.class) {
                            XposedBridge.hookMethod(m, new XC_MethodHook() {
                                @Override
                                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                                    p.setResult(false);
                                }
                            });
                        } else if (ret == void.class) {
                            XposedBridge.hookMethod(m, new XC_MethodHook() {
                                @Override
                                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                                    p.setResult(null);
                                }
                            });
                        }
                    }
                }
                XposedEntry.log("[BuglyPatch] Neutralized StripHeapDumper native hooks");
            }
        });

        // com.tencent.bugly.common.heapdump.ForkJvmHeapDumper: forks process to dump memory
        hookSafe(cl, "com.tencent.bugly.common.heapdump.ForkJvmHeapDumper", new ClassHookCallback() {
            @Override
            public void onClassFound(Class<?> clazz) {
                for (Method m : clazz.getDeclaredMethods()) {
                    String name = m.getName();
                    if ("nInitForkDump".equals(name)) {
                        XposedBridge.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                                p.setResult(false);
                                XposedEntry.log("[BuglyPatch] Neutralized ForkJvmHeapDumper.nInitForkDump");
                            }
                        });
                    } else if ("dump".equals(name)) {
                        XposedBridge.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                                p.setResult(101); // DUMP_DISABLED / FAIL
                                XposedEntry.log("[BuglyPatch] Intercepted ForkJvmHeapDumper.dump");
                            }
                        });
                    }
                }
            }
        });
    }

    private interface ClassHookCallback {
        void onClassFound(Class<?> clazz);
    }

    private static void resolvePendingHooks(ClassLoader cl) {
        if (cl == null || sPendingClassHooks.isEmpty()) return;
        List<String> resolved = new java.util.ArrayList<>();
        for (Map.Entry<String, List<ClassHookCallback>> entry : sPendingClassHooks.entrySet()) {
            String className = entry.getKey();
            Class<?> clazz = XposedHelpers.findClassIfExists(className, cl);
            if (clazz != null) {
                String key = className + "@" + clazz.hashCode();
                if (sHookedClasses.add(key)) {
                    for (ClassHookCallback cb : entry.getValue()) {
                        try {
                            cb.onClassFound(clazz);
                        } catch (Throwable t) {
                            XposedEntry.log("Failed to initialize late hooks on " + className + ": " + t.getMessage());
                        }
                    }
                }
                resolved.add(className);
            }
        }
        for (String c : resolved) {
            sPendingClassHooks.remove(c);
        }
        if (!resolved.isEmpty()) {
            XposedEntry.log("[SecurityEnhance] Resolved " + resolved.size() + " pending classes in late stage");
        }
    }

    private static void hookSafe(ClassLoader cl, final String className, final ClassHookCallback callback) {
        if (cl == null) return;
        Class<?> clazz = XposedHelpers.findClassIfExists(className, cl);
        if (clazz != null) {
            String key = className + "@" + clazz.hashCode();
            if (sHookedClasses.add(key)) {
                try {
                    callback.onClassFound(clazz);
                } catch (Throwable t) {
                    XposedEntry.log("Failed to initialize hooks on " + className + ": " + t.getMessage());
                }
            }
        } else {
            // NEVER hook ClassLoader.loadClass! It adds massive CPU delay to all class resolution in ART.
            // Queue for resolution when secondary dexes are attached via MultiDex (attachBaseContext).
            sPendingClassHooks.computeIfAbsent(className, k -> new java.util.concurrent.CopyOnWriteArrayList<>()).add(callback);
        }
    }
}
