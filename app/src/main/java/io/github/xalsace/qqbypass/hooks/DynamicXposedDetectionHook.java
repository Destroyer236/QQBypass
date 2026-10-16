package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.detector.DexMethodData;

import java.lang.reflect.Member;
import java.util.List;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.detector.DexKitDetector;
import io.github.xalsace.qqbypass.utils.HookUtils;

/**
 * DexKit-based Xposed/LSPosed Detection Bypass
 * Dynamically locates and hooks obfuscated framework detection methods
 */
public class DynamicXposedDetectionHook {

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_XPOSED_BYPASS) return;

        XposedEntry.log("Initializing DexKit-based Xposed Detection Bypass");

        // Universal hook: Stack trace sanitization (removes xposed/lsposed/qb frames)
        hookStackTrace();

        // ClassLoader and reflection probing bypass (ClassNotFoundException for hook framework queries)
        hookClassLoaderAndReflection(lpparam);

        // Crash reporter (Bugly / QQPerf) xposed status spoofing
        hookBuglyCrashReporter(lpparam);

        // Dynamic hooks: DexKit-discovered detection points
        new Thread(() -> {
            try {
                // Wait for the shared scan instead of a fixed sleep (the old
                // sleep(5000) raced the scan and read an empty cache).
                if (!DexKitDetector.awaitReady(30000)) {
                    XposedEntry.log("DynamicXposed: DexKit not available, skipping dynamic hooks");
                    return;
                }
                hookArtMethodDetectors(lpparam);
                hookMapsReaders(lpparam);
                hookQSecDetectors(lpparam);

            } catch (Throwable e) {
                XposedEntry.log("Dynamic Xposed detection hook failed: " + e.getMessage());
            }
        }).start();
    }

    private static void hookArtMethodDetectors(XC_LoadPackage.LoadPackageParam lpparam) {
        List<DexMethodData> artDetectors = DexKitDetector.findArtHookDetectors();
        if (artDetectors.isEmpty()) {
            XposedEntry.log("DynamicXposed: No ArtMethod detectors found by DexKit");
            return;
        }

        XposedEntry.log("DynamicXposed: Hooking " + artDetectors.size() + " ArtMethod detectors");

        for (DexMethodData methodData : artDetectors) {
            try {
                String className = methodData.getClassName();
                String methodName = methodData.getMethodName();

                Member method;
                try {
                    method = methodData.getMethodInstance(lpparam.classLoader);
                } catch (Throwable t) {
                    continue;
                }

                XposedBridge.hookMethod(method, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Object result = param.getResult();

                        // If returns boolean (isHooked check), force false
                        if (result instanceof Boolean && (Boolean) result) {
                            param.setResult(false);
                            XposedEntry.log("ArtMethod detector neutralized: " + className);
                        }

                        // If returns int (hook count), force 0
                        if (result instanceof Integer && (Integer) result > 0) {
                            param.setResult(0);
                            XposedEntry.log("ArtMethod hook count zeroed: " + className);
                        }

                        // If returns List/Array (hooked methods list), force empty
                        if (result instanceof java.util.List && !((java.util.List<?>) result).isEmpty()) {
                            param.setResult(new java.util.ArrayList<>());
                            XposedEntry.log("ArtMethod hook list cleared: " + className);
                        }
                    }
                });

                XposedEntry.log("Hooked ArtMethod detector: " + className + "." + methodName);

            } catch (Exception e) {
                XposedEntry.log("Failed to hook ArtMethod detector: " + e.getMessage());
            }
        }
    }

    private static void hookMapsReaders(XC_LoadPackage.LoadPackageParam lpparam) {
        List<DexMethodData> mapsReaders = DexKitDetector.findMapsReaders();
        if (mapsReaders.isEmpty()) {
            XposedEntry.log("DynamicXposed: No maps readers found by DexKit");
            return;
        }

        XposedEntry.log("DynamicXposed: Hooking " + mapsReaders.size() + " /proc/self/maps readers");

        for (DexMethodData methodData : mapsReaders) {
            try {
                String className = methodData.getClassName();
                String methodName = methodData.getMethodName();

                Member method;
                try {
                    method = methodData.getMethodInstance(lpparam.classLoader);
                } catch (Throwable t) {
                    continue;
                }

                XposedBridge.hookMethod(method, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Object result = param.getResult();

                        // If returns String (maps content), filter suspicious lines
                        if (result instanceof String) {
                            String filtered = filterMapsContent((String) result);
                            if (!filtered.equals(result)) {
                                param.setResult(filtered);
                                XposedEntry.log("Maps reader output filtered: " + className);
                            }
                        }

                        // If returns List<String> (maps lines), filter
                        if (result instanceof java.util.List) {
                            java.util.List<?> list = (java.util.List<?>) result;
                            if (!list.isEmpty() && list.get(0) instanceof String) {
                                @SuppressWarnings("unchecked")
                                java.util.List<String> lines = (java.util.List<String>) list;
                                java.util.List<String> filtered = filterMapsList(lines);
                                if (filtered.size() != lines.size()) {
                                    param.setResult(filtered);
                                    XposedEntry.log("Maps reader list filtered: " + className);
                                }
                            }
                        }
                    }
                });

                XposedEntry.log("Hooked maps reader: " + className + "." + methodName);

            } catch (Exception e) {
                XposedEntry.log("Failed to hook maps reader: " + e.getMessage());
            }
        }
    }

    private static void hookQSecDetectors(XC_LoadPackage.LoadPackageParam lpparam) {
        List<DexMethodData> qsecDetectors = DexKitDetector.findQSecHookDetectors();
        if (qsecDetectors.isEmpty()) {
            XposedEntry.log("DynamicXposed: No QSec detectors found by DexKit");
            return;
        }

        XposedEntry.log("DynamicXposed: Hooking " + qsecDetectors.size() + " QSec hook detectors");

        for (DexMethodData methodData : qsecDetectors) {
            try {
                String className = methodData.getClassName();
                String methodName = methodData.getMethodName();

                Member method;
                try {
                    method = methodData.getMethodInstance(lpparam.classLoader);
                } catch (Throwable t) {
                    continue;
                }

                XposedBridge.hookMethod(method, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Object result = param.getResult();

                        // Neutralize positive detection results
                        if (result instanceof Boolean && (Boolean) result) {
                            param.setResult(false);
                            XposedEntry.log("QSec detector neutralized: " + className + "." + methodName);
                        }

                        if (result instanceof Integer && (Integer) result != 0) {
                            String mLower = methodName.toLowerCase();
                            if (mLower.contains("check") || mLower.contains("detect")
                                    || mLower.contains("hook") || mLower.contains("is")
                                    || mLower.contains("verify") || mLower.contains("status")
                                    || mLower.contains("scan") || mLower.contains("count")) {
                                param.setResult(0);
                                XposedEntry.log("QSec detection code zeroed: " + className + "." + methodName);
                            }
                        }
                    }
                });

                XposedEntry.log("Hooked QSec detector: " + className + "." + methodName);

            } catch (Exception e) {
                XposedEntry.log("Failed to hook QSec detector: " + e.getMessage());
            }
        }
    }

    private static String filterMapsContent(String content) {
        if (content == null) return content;

        StringBuilder filtered = new StringBuilder();
        for (String line : content.split("\n")) {
            if (!isSuspiciousMapLine(line)) {
                filtered.append(line).append("\n");
            }
        }
        return filtered.toString();
    }

    private static java.util.List<String> filterMapsList(java.util.List<String> lines) {
        java.util.List<String> filtered = new java.util.ArrayList<>();
        for (String line : lines) {
            if (!isSuspiciousMapLine(line)) {
                filtered.add(line);
            }
        }
        return filtered;
    }

    private static boolean isSuspiciousMapLine(String line) {
        if (line == null) return false;
        String lower = line.toLowerCase();

        return lower.contains("xposed") || lower.contains("lsposed")
            || lower.contains("edxposed") || lower.contains("magisk")
            || lower.contains("zygisk") || lower.contains("riru")
            || lower.contains("frida") || lower.contains("substrate")
            || lower.contains("/data/adb") || lower.contains("shamiko")
            || lower.contains("dexkit") || lower.contains("libdexkit")
            || lower.contains("flatbuffers") || lower.contains("sandhook")
            || lower.contains("yahfa") || lower.contains("epic")
            || lower.contains("pine") || lower.contains("taichi")
            || lower.contains("top.canyie") || lower.contains("liblspd")
            // Filter our own module and native dependencies
            || lower.contains("xalsace") || lower.contains("qqbypass")
            || lower.contains("bypass") || lower.contains("libnative-bypass")
            || lower.contains("bytehook") || lower.contains("libbytehook")
            // Filter QAuxv and related
            || lower.contains("qauxv") || lower.contains("io.github.qauxv")
            || lower.contains("libqauxv") || lower.contains("libqauxv-core0")
            || lower.contains("cc.ioctl") || lower.contains("qnotified");
    }

    private static StackTraceElement[] filterStackTrace(StackTraceElement[] traces) {
        if (traces == null) return null;
        if (Boolean.TRUE.equals(bypassStackFilter.get())) {
            return traces;
        }
        java.util.List<StackTraceElement> clean = new java.util.ArrayList<>();
        for (StackTraceElement element : traces) {
            String cls = element.getClassName();
            String method = element.getMethodName();
            if (cls == null) continue;
            String lower = cls.toLowerCase();
            if (lower.contains("de.robv.android.xposed") ||
                lower.contains("org.lsposed") ||
                lower.contains("io.github.xalsace") ||
                lower.contains("edxposed") ||
                lower.contains("sandhook") ||
                lower.contains("epic") ||
                lower.contains("pine") ||
                lower.contains("yahfa") ||
                lower.contains("taichi") ||
                lower.contains("top.canyie") ||
                lower.contains("me.weishu") ||
                lower.contains("me.bmax") ||
                lower.contains("org.luckypray.dexkit") ||
                lower.contains("com.google.flatbuffers") ||
                lower.contains("com.elderdrivers.riru") ||
                lower.contains("bytehook") ||
                lower.contains("bin.mt") ||
                lower.contains("top.nkbe.npatch") ||
                lower.contains("npatch") ||
                lower.contains("io.github.qauxv") ||
                lower.contains("qauxv") ||
                lower.contains("cc.ioctl") ||
                lower.contains("me.singleneuron") ||
                lower.contains("nep.timeline") ||
                lower.contains("me.ketal") ||
                lower.contains("me.hd") ||
                lower.contains("xyz.nextalone") ||
                lower.contains("top.linl") ||
                lower.contains("net.bytebuddy") ||
                lower.contains("io.github.libxposed") ||
                lower.contains("qnotified")) {
                continue;
            }
            if (method != null) {
                if (method.equals("handleHookedMethod") ||
                    method.equals("beforeHookedMethod") ||
                    method.equals("afterHookedMethod") ||
                    method.equals("invokedTargetMethod")) {
                    continue;
                }
            }
            clean.add(element);
        }
        return clean.toArray(new StackTraceElement[0]);
    }

    private static void hookStackTrace() {
        try {
            HookUtils.hookMethod(Throwable.class, "getStackTrace", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof StackTraceElement[]) {
                        StackTraceElement[] traces = (StackTraceElement[]) res;
                        StackTraceElement[] clean = filterStackTrace(traces);
                        if (clean.length != traces.length) {
                            param.setResult(clean);
                        }
                    }
                }
            });

            HookUtils.hookMethod(Thread.class, "getStackTrace", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof StackTraceElement[]) {
                        StackTraceElement[] traces = (StackTraceElement[]) res;
                        StackTraceElement[] clean = filterStackTrace(traces);
                        if (clean.length != traces.length) {
                            param.setResult(clean);
                        }
                    }
                }
            });

            HookUtils.hookMethod(Thread.class, "getAllStackTraces", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof java.util.Map) {
                        @SuppressWarnings("unchecked")
                        java.util.Map<Thread, StackTraceElement[]> map = (java.util.Map<Thread, StackTraceElement[]>) res;
                        java.util.Map<Thread, StackTraceElement[]> cleanMap = new java.util.HashMap<>();
                        for (java.util.Map.Entry<Thread, StackTraceElement[]> entry : map.entrySet()) {
                            Thread thread = entry.getKey();
                            if (thread != null) {
                                String name = thread.getName();
                                if (name != null) {
                                    String nameLower = name.toLowerCase();
                                    if (nameLower.contains("dexkit") || nameLower.contains("qqbypass") || nameLower.contains("xalsace")
                                            || nameLower.contains("qauxv") || nameLower.contains("qnotified") || nameLower.contains("cc.ioctl")) {
                                        continue;
                                    }
                                }
                            }
                            StackTraceElement[] cleanStack = filterStackTrace(entry.getValue());
                            cleanMap.put(thread, cleanStack);
                        }
                        param.setResult(cleanMap);
                    }
                }
            });
        } catch (Throwable t) {
            XposedEntry.log("Failed to hook StackTrace: " + t.getMessage());
        }
    }

    private static final ThreadLocal<Boolean> bypassStackFilter = new ThreadLocal<Boolean>() {
        @Override
        protected Boolean initialValue() {
            return false;
        }
    };

    private static final ThreadLocal<Boolean> inReflectionHook = new ThreadLocal<Boolean>() {
        @Override
        protected Boolean initialValue() {
            return false;
        }
    };

    private static boolean isSuspiciousClass(String name) {
        if (name == null) return false;
        String lower = name.toLowerCase();
        return lower.startsWith("de.robv.android.xposed.")
            || lower.startsWith("org.lsposed.")
            || lower.startsWith("edxposed.")
            || lower.startsWith("com.swift.sandhook.")
            || lower.startsWith("top.canyie.pine.")
            || lower.startsWith("lab.galaxy.yahfa.")
            || lower.startsWith("me.ele.epic.")
            || lower.startsWith("me.weishu.exposed.")
            || lower.startsWith("bin.mt.")
            || lower.startsWith("top.nkbe.npatch.")
            || lower.startsWith("io.github.qauxv.")
            || lower.startsWith("cc.ioctl.")
            || lower.startsWith("me.singleneuron.")
            || lower.startsWith("nep.timeline.")
            || lower.startsWith("net.bytebuddy.")
            || lower.startsWith("io.github.libxposed.");
    }

    private static boolean isCallerWhitelisted() {
        try {
            bypassStackFilter.set(true);
            StackTraceElement[] stack = Thread.currentThread().getStackTrace();
            boolean hasTencentCaller = false;
            for (StackTraceElement elem : stack) {
                String cls = elem.getClassName();
                if (cls == null) continue;
                if (cls.equals(DynamicXposedDetectionHook.class.getName())
                    || cls.equals("java.lang.Thread")
                    || cls.equals("java.lang.Class")
                    || cls.equals("java.lang.ClassLoader")
                    || cls.startsWith("de.robv.android.xposed.XC_MethodHook")
                    || cls.startsWith("de.robv.android.xposed.XposedBridge")) {
                    continue;
                }
                if (cls.startsWith("io.github.xalsace.")
                    || cls.startsWith("io.github.qauxv.")
                    || cls.startsWith("cc.ioctl.")
                    || cls.startsWith("me.singleneuron.")
                    || cls.startsWith("nep.timeline.")
                    || cls.startsWith("me.ketal.")
                    || cls.startsWith("xyz.nextalone.")
                    || cls.startsWith("top.linl.")
                    || cls.startsWith("net.bytebuddy.")
                    || cls.startsWith("io.github.libxposed.")
                    || cls.startsWith("bin.mt.")
                    || cls.startsWith("de.robv.android.xposed.")
                    || cls.startsWith("org.lsposed.")) {
                    return true;
                }
                if (cls.startsWith("com.tencent.") || cls.startsWith("oicq.") || cls.startsWith("mqq.")) {
                    hasTencentCaller = true;
                    break;
                }
            }
            if (hasTencentCaller) {
                return false;
            }
            return true;
        } finally {
            bypassStackFilter.set(false);
        }
    }

    private static void hookClassLoaderAndReflection(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            final ClassLoader moduleLoader = DynamicXposedDetectionHook.class.getClassLoader();

            XC_MethodHook loadClassHook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (inReflectionHook.get()) return;
                    if (param.thisObject == moduleLoader) return;
                    try {
                        inReflectionHook.set(true);
                        if (param.args != null && param.args.length > 0 && param.args[0] instanceof String) {
                            String className = (String) param.args[0];
                            if (isSuspiciousClass(className) && !isCallerWhitelisted()) {
                                param.setThrowable(new ClassNotFoundException("Didn't find class \"" + className + "\""));
                            }
                        }
                    } finally {
                        inReflectionHook.set(false);
                    }
                }
            };

            HookUtils.hookMethod(ClassLoader.class, "loadClass", String.class, loadClassHook);
            HookUtils.hookMethod(ClassLoader.class, "loadClass", String.class, boolean.class, loadClassHook);

            HookUtils.hookMethod(Class.class, "forName", String.class, boolean.class, ClassLoader.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (inReflectionHook.get()) return;
                    if (param.args != null && param.args.length > 2 && param.args[2] == moduleLoader) return;
                    try {
                        inReflectionHook.set(true);
                        if (param.args != null && param.args.length > 0 && param.args[0] instanceof String) {
                            String className = (String) param.args[0];
                            if (isSuspiciousClass(className) && !isCallerWhitelisted()) {
                                param.setThrowable(new ClassNotFoundException("Didn't find class \"" + className + "\""));
                            }
                        }
                    } finally {
                        inReflectionHook.set(false);
                    }
                }
            });

            HookUtils.hookMethod(ClassLoader.class, "toString", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof String) {
                        String s = (String) res;
                        if (s.contains("xposed") || s.contains("lsposed") || s.contains("edxposed")) {
                            param.setResult(s.replaceAll("(?i)xposed", "dalvik")
                                            .replaceAll("(?i)lsposed", "dalvik")
                                            .replaceAll("(?i)edxposed", "dalvik"));
                        }
                    }
                }
            });
            XposedEntry.log("ClassLoader and reflection hook protection installed");
        } catch (Throwable t) {
            XposedEntry.log("Failed to hook ClassLoader and reflection: " + t.getMessage());
        }
    }

    private static boolean containsSensitiveLog(String s) {
        if (s == null) return false;
        String lower = s.toLowerCase();
        return lower.contains("xposed") || lower.contains("lsposed") || lower.contains("qauxv")
            || lower.contains("qqbypass") || lower.contains("nativebypass") || lower.contains("native-bypass")
            || lower.contains("dexkit") || lower.contains("bin.mt") || lower.contains("npatch")
            || lower.contains("bytebuddy") || lower.contains("singleneuron") || lower.contains("magisk")
            || lower.contains("shamiko") || lower.contains("kernel_su") || lower.contains("apatch");
    }

    private static void hookBuglyCrashReporter(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> crashHandlerClass = de.robv.android.xposed.XposedHelpers.findClassIfExists(
                "com.tencent.qqperf.monitor.crash.c", lpparam.classLoader);
            if (crashHandlerClass != null) {
                HookUtils.hookAllMethods(crashHandlerClass, "c", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Object res = param.getResult();
                        if (res instanceof String) {
                            String str = (String) res;
                            if (str.contains("isXposedInstalled: true")) {
                                str = str.replace("isXposedInstalled: true", "isXposedInstalled: false");
                                param.setResult(str);
                            }
                        }
                    }
                });
                XposedEntry.log("Bugly crash reporter xposed spoofing hooked");
            }
        } catch (Throwable t) {
            XposedEntry.log("Failed to hook Bugly crash reporter: " + t.getMessage());
        }

        // Sanitize BuglyLog to drop sensitive framework logs
        try {
            Class<?> buglyLogClass = de.robv.android.xposed.XposedHelpers.findClassIfExists(
                "com.tencent.bugly.crashreport.BuglyLog", lpparam.classLoader);
            if (buglyLogClass != null) {
                XC_MethodHook buglyFilter = new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null) {
                            for (Object arg : param.args) {
                                if (arg instanceof String && containsSensitiveLog((String) arg)) {
                                    param.setResult(null);
                                    return;
                                }
                            }
                        }
                    }
                };
                for (String m : new String[]{"v", "d", "i", "w", "e"}) {
                    HookUtils.hookAllMethods(buglyLogClass, m, buglyFilter);
                }
                XposedEntry.log("BuglyLog sanitization installed");
            }
        } catch (Throwable t) {
            XposedEntry.log("Failed to hook BuglyLog: " + t.getMessage());
        }

        // Sanitize QLog to drop sensitive module/framework logs
        try {
            Class<?> qLogClass = de.robv.android.xposed.XposedHelpers.findClassIfExists(
                "com.tencent.qphone.base.util.QLog", lpparam.classLoader);
            if (qLogClass != null) {
                XC_MethodHook qlogFilter = new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null) {
                            for (Object arg : param.args) {
                                if (arg instanceof String && containsSensitiveLog((String) arg)) {
                                    param.setResult(null);
                                    return;
                                }
                            }
                        }
                    }
                };
                for (String m : new String[]{"d", "i", "w", "e"}) {
                    HookUtils.hookAllMethods(qLogClass, m, qlogFilter);
                }
                XposedEntry.log("QLog sanitization installed");
            }
        } catch (Throwable t) {
            XposedEntry.log("Failed to hook QLog: " + t.getMessage());
        }

        // Sanitize CrashReport.putUserData
        try {
            Class<?> crashReportCls = de.robv.android.xposed.XposedHelpers.findClassIfExists(
                "com.tencent.bugly.crashreport.CrashReport", lpparam.classLoader);
            if (crashReportCls != null) {
                HookUtils.hookAllMethods(crashReportCls, "putUserData", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null) {
                            for (Object arg : param.args) {
                                if (arg instanceof String && containsSensitiveLog((String) arg)) {
                                    param.setResult(null);
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        } catch (Throwable ignored) {}
    }
}
