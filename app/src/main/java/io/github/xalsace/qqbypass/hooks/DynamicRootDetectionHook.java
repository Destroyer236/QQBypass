package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.detector.DexMethodData;

import java.io.File;
import java.lang.reflect.Member;
import java.util.ArrayList;
import java.util.List;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.detector.DexKitDetector;
import io.github.xalsace.qqbypass.utils.HookUtils;

/**
 * DexKit-based Root Detection Bypass
 * Dynamically locates and hooks obfuscated su path checkers
 */
public class DynamicRootDetectionHook {

    private static final String[] SU_PATHS = {
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/su/bin/su",
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/adb/magisk",
        "/data/adb/ksu",
        "/data/adb/ap",
        "/data/adb/modules",
        "/data/adb/shamiko"
    };

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_ROOT_BYPASS) return;

        XposedEntry.log("Initializing DexKit-based Root Detection Bypass");

        // Universal hook: File methods - catches all path checks
        hookFileChecks();

        // Environment properties & package inventory checks
        hookInstalledPackages(lpparam);
        hookActivityManager(lpparam);
        hookInstalledAppListMonitor(lpparam);
        hookUsageStatsManager(lpparam);
        hookSystemProperties();

        // Gatherer SDK root detection hook
        hookGathererRootCheck(lpparam);

        // Tencent Beacon root detection & device info hooks
        hookBeaconRootCheck(lpparam);

        // Dynamic hooks: DexKit-discovered su path checkers
        new Thread(() -> {
            try {
                // Wait for the shared scan to finish instead of a fixed sleep.
                if (!DexKitDetector.awaitReady(30000)) {
                    XposedEntry.log("DynamicRoot: DexKit not available, skipping dynamic hooks");
                    return;
                }
                hookSuPathCheckers(lpparam);
                hookPackageQueries(lpparam);

            } catch (Throwable e) {
                XposedEntry.log("Dynamic root detection hook failed: " + e.getMessage());
            }
        }).start();
    }

    private static void hookFileChecks() {
        XC_MethodHook booleanFileHook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                File file = (File) param.thisObject;
                String path = file.getAbsolutePath();

                if (isSuspiciousPath(path)) {
                    param.setResult(false);
                    XposedEntry.log("File check blocked: " + path);
                    UnifiedHookCoordinator.notifyNativeIfAvailable("file_blocked", path);
                }
            }
        };

        HookUtils.hookMethod(File.class, "exists", booleanFileHook);
        HookUtils.hookMethod(File.class, "canRead", booleanFileHook);
        HookUtils.hookMethod(File.class, "canExecute", booleanFileHook);
        HookUtils.hookMethod(File.class, "isFile", booleanFileHook);

        HookUtils.hookMethod(File.class, "length", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                File file = (File) param.thisObject;
                String path = file.getAbsolutePath();

                if (isSuspiciousPath(path)) {
                    param.setResult(0L);
                    UnifiedHookCoordinator.notifyNativeIfAvailable("file_blocked", path);
                }
            }
        });

        HookUtils.hookMethod(File.class, "list", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                String[] list = (String[]) param.getResult();
                if (list == null || list.length == 0) return;
                List<String> filtered = new ArrayList<>(list.length);
                for (String name : list) {
                    if (isSuspiciousPath(name)) continue;
                    filtered.add(name);
                }
                if (filtered.size() != list.length) {
                    param.setResult(filtered.toArray(new String[0]));
                }
            }
        });

        HookUtils.hookMethod(File.class, "listFiles", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                File[] list = (File[]) param.getResult();
                if (list == null || list.length == 0) return;
                List<File> filtered = new ArrayList<>(list.length);
                for (File f : list) {
                    if (f != null && isSuspiciousPath(f.getAbsolutePath())) continue;
                    filtered.add(f);
                }
                if (filtered.size() != list.length) {
                    param.setResult(filtered.toArray(new File[0]));
                }
            }
        });
    }

    private static void hookGathererRootCheck(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> userInfoImplClass = de.robv.android.xposed.XposedHelpers.findClassIfExists(
                "com.tencent.gathererga.core.internal.provider.impl.UserInfoImpl", lpparam.classLoader);
            if (userInfoImplClass != null) {
                HookUtils.hookAllMethods(userInfoImplClass, "isRooted", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        Class<?> cClass = de.robv.android.xposed.XposedHelpers.findClassIfExists(
                            "com.tencent.gathererga.core.internal.provider.c", lpparam.classLoader);
                        if (cClass != null) {
                            try {
                                Object notRooted = de.robv.android.xposed.XposedHelpers.newInstance(cClass, 0L, Boolean.FALSE);
                                param.setResult(notRooted);
                                XposedEntry.log("[GathererPatch] UserInfoImpl.isRooted preempted with Boolean.FALSE");
                                return;
                            } catch (Throwable t) {
                                XposedEntry.log("[GathererPatch] Failed to instantiate c: " + t.getMessage());
                            }
                        }
                    }

                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Object result = param.getResult();
                        if (result != null) {
                            try {
                                de.robv.android.xposed.XposedHelpers.setObjectField(result, "b", Boolean.FALSE);
                                XposedEntry.log("[GathererPatch] UserInfoImpl.isRooted result forced to Boolean.FALSE");
                            } catch (Throwable ignored) {}
                        }
                    }
                });
                XposedEntry.log("[GathererPatch] Hooked UserInfoImpl.isRooted successfully");
            }
        } catch (Throwable t) {
            XposedEntry.log("[GathererPatch] Failed to hook UserInfoImpl.isRooted: " + t.getMessage());
        }
    }

    /**
     * Intercept Tencent Beacon Root Detection:
     * com.tencent.beacon.base.util.d:
     * - d(): overall root status (returns false)
     * - a(): su command execution probe (returns false)
     * - b(): /system/app/Superuser.apk probe (returns false)
     * - c(): Build.TAGS test-keys probe (returns false)
     * - e(): executes "/system/bin/sh -c type su" via RuntimeMonitor.exec (neutralized to return empty list)
     * - static boolean a: latched root flag (force to false)
     *
     * com.tencent.beacon.a.c.e:
     * - m(): device hardware provider root check (returns false)
     */
    private static final java.util.Set<Class<?>> sHookedBeaconClasses =
        java.util.Collections.newSetFromMap(new java.util.concurrent.ConcurrentHashMap<>());

    private static void hookBeaconClassD(Class<?> beaconUtilD) {
        if (beaconUtilD == null || sHookedBeaconClasses.contains(beaconUtilD)) return;
        sHookedBeaconClasses.add(beaconUtilD);
        try {
            XC_MethodHook falseHook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(false);
                }
            };

            HookUtils.hookAllMethods(beaconUtilD, "d", falseHook);
            HookUtils.hookAllMethods(beaconUtilD, "a", falseHook);
            HookUtils.hookAllMethods(beaconUtilD, "b", falseHook);
            HookUtils.hookAllMethods(beaconUtilD, "c", falseHook);

            // Neutralize e() so it never forks shell commands
            HookUtils.hookAllMethods(beaconUtilD, "e", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(new java.util.ArrayList<String>());
                }
            });

            // Reset static latched flag 'a'
            try {
                de.robv.android.xposed.XposedHelpers.setStaticBooleanField(beaconUtilD, "a", false);
            } catch (Throwable ignored) {}

            XposedEntry.log("[BeaconRoot] Fully neutralized com.tencent.beacon.base.util.d root probes");
        } catch (Throwable t) {
            XposedEntry.log("[BeaconRoot] Failed to hook com.tencent.beacon.base.util.d: " + t.getMessage());
        }
    }

    private static void hookBeaconClassE(Class<?> beaconDevInfo) {
        if (beaconDevInfo == null || sHookedBeaconClasses.contains(beaconDevInfo)) return;
        sHookedBeaconClasses.add(beaconDevInfo);
        try {
            HookUtils.hookAllMethods(beaconDevInfo, "m", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(false);
                }
            });
            XposedEntry.log("[BeaconRoot] Neutralized com.tencent.beacon.a.c.e.m root check");
        } catch (Throwable t) {
            XposedEntry.log("[BeaconRoot] Failed to hook com.tencent.beacon.a.c.e: " + t.getMessage());
        }
    }

    private static void hookBeaconReport(Class<?> beaconReportCls) {
        if (beaconReportCls == null || sHookedBeaconClasses.contains(beaconReportCls)) return;
        sHookedBeaconClasses.add(beaconReportCls);
        try {
            HookUtils.hookAllMethods(beaconReportCls, "report", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 0 && param.args[0] != null) {
                        Object event = param.args[0];
                        try {
                            String code = (String) de.robv.android.xposed.XposedHelpers.callMethod(event, "getCode");
                            if (code != null) {
                                String lower = code.toLowerCase();
                                // Whitelist standard UI, messaging, NT, lifecycle, and network performance events
                                if (lower.startsWith("actnt") || lower.startsWith("actmain") || lower.startsWith("actmsg")
                                        || lower.startsWith("actaio") || lower.startsWith("actavif") || lower.startsWith("actperf")
                                        || lower.startsWith("actsync") || lower.startsWith("actlogin") || lower.startsWith("actfriend")
                                        || lower.startsWith("actgroup") || lower.startsWith("actc2c") || lower.startsWith("actfile")
                                        || lower.startsWith("actmini") || lower.startsWith("actweb") || lower.startsWith("actvideo")
                                        || lower.startsWith("actalbum") || lower.startsWith("actcamera") || lower.startsWith("actguild")) {
                                    return;
                                }

                                // Targeted security / root event match
                                boolean isSecurityRisk = lower.contains("root") || lower.contains("security") || lower.contains("jailbreak")
                                        || lower.contains("xposed") || lower.contains("magisk") || lower.contains("lsposed")
                                        || lower.contains("frida") || lower.contains("substrate") || lower.contains("superuser")
                                        || lower.contains("secrisk") || lower.contains("risk_check") || lower.contains("root_check")
                                        || lower.contains("env_check") || lower.contains("danger") || lower.contains("busybox")
                                        || lower.equals("su") || lower.startsWith("su_") || lower.endsWith("_su") || lower.contains("_su_")
                                        || lower.contains("/su") || lower.contains("su/");

                                if (isSecurityRisk) {
                                    Class<?> eventResultCls = de.robv.android.xposed.XposedHelpers.findClassIfExists("com.tencent.beacon.event.open.EventResult", event.getClass().getClassLoader());
                                    if (eventResultCls != null) {
                                        Object successResult = de.robv.android.xposed.XposedHelpers.newInstance(eventResultCls, 0, 0L, "ok");
                                        param.setResult(successResult);
                                    } else {
                                        param.setResult(null);
                                    }
                                    XposedEntry.log("[BeaconReport] Dropped security event: " + code);
                                }
                            }
                        } catch (Throwable ignored) {}
                    }
                }
            });
            XposedEntry.log("[BeaconReport] Neutralized BeaconReport.report for security/root events");
        } catch (Throwable t) {
            XposedEntry.log("[BeaconReport] Failed to hook BeaconReport: " + t.getMessage());
        }
    }

    public static void hookLateStage(ClassLoader cl) {
        if (cl == null) return;
        try {
            Class<?> beaconUtilD = de.robv.android.xposed.XposedHelpers.findClassIfExists("com.tencent.beacon.base.util.d", cl);
            if (beaconUtilD != null) {
                hookBeaconClassD(beaconUtilD);
            }
            Class<?> beaconDevInfo = de.robv.android.xposed.XposedHelpers.findClassIfExists("com.tencent.beacon.a.c.e", cl);
            if (beaconDevInfo != null) {
                hookBeaconClassE(beaconDevInfo);
            }
            Class<?> beaconReportCls = de.robv.android.xposed.XposedHelpers.findClassIfExists("com.tencent.beacon.event.open.BeaconReport", cl);
            if (beaconReportCls != null) {
                hookBeaconReport(beaconReportCls);
            }
            Class<?> userInfoImpl = de.robv.android.xposed.XposedHelpers.findClassIfExists(
                "com.tencent.gathererga.core.internal.provider.impl.UserInfoImpl", cl);
            if (userInfoImpl != null && !sHookedBeaconClasses.contains(userInfoImpl)) {
                sHookedBeaconClasses.add(userInfoImpl);
                HookUtils.hookAllMethods(userInfoImpl, "isRooted", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Object result = param.getResult();
                        if (result != null) {
                            try {
                                de.robv.android.xposed.XposedHelpers.setObjectField(result, "b", Boolean.FALSE);
                            } catch (Throwable ignored) {}
                        }
                    }
                });
            }
        } catch (Throwable t) {
            XposedEntry.log("[BeaconRoot] hookLateStage error: " + t.getMessage());
        }
    }

    private static void hookBeaconRootCheck(XC_LoadPackage.LoadPackageParam lpparam) {
        ClassLoader cl = lpparam != null && lpparam.classLoader != null ? lpparam.classLoader : HookConfig.getClassLoader();
        if (cl != null) {
            Class<?> beaconUtilD = de.robv.android.xposed.XposedHelpers.findClassIfExists("com.tencent.beacon.base.util.d", cl);
            if (beaconUtilD != null) {
                hookBeaconClassD(beaconUtilD);
            }
            Class<?> beaconDevInfo = de.robv.android.xposed.XposedHelpers.findClassIfExists("com.tencent.beacon.a.c.e", cl);
            if (beaconDevInfo != null) {
                hookBeaconClassE(beaconDevInfo);
            }
            Class<?> beaconReportCls = de.robv.android.xposed.XposedHelpers.findClassIfExists("com.tencent.beacon.event.open.BeaconReport", cl);
            if (beaconReportCls != null) {
                hookBeaconReport(beaconReportCls);
            }
        }

        // Dynamically monitor ClassLoader.loadClass for Beacon classes in secondary dexes
        try {
            HookUtils.hookAllMethods(ClassLoader.class, "loadClass", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args != null && p.args.length > 0 && p.args[0] instanceof String) {
                        String name = (String) p.args[0];
                        if ("com.tencent.beacon.base.util.d".equals(name)) {
                            Class<?> clazz = (Class<?>) p.getResult();
                            if (clazz != null) hookBeaconClassD(clazz);
                        } else if ("com.tencent.beacon.a.c.e".equals(name)) {
                            Class<?> clazz = (Class<?>) p.getResult();
                            if (clazz != null) hookBeaconClassE(clazz);
                        } else if ("com.tencent.beacon.event.open.BeaconReport".equals(name)) {
                            Class<?> clazz = (Class<?>) p.getResult();
                            if (clazz != null) hookBeaconReport(clazz);
                        }
                    }
                }
            });
        } catch (Throwable t) {
            XposedEntry.log("[BeaconRoot] Failed to hook ClassLoader.loadClass: " + t.getMessage());
        }
    }

    private static void hookSuPathCheckers(XC_LoadPackage.LoadPackageParam lpparam) {
        List<DexMethodData> suCheckers = DexKitDetector.findSuPathCheckers();
        if (suCheckers.isEmpty()) {
            XposedEntry.log("DynamicRoot: No su path checkers found by DexKit");
            return;
        }

        XposedEntry.log("DynamicRoot: Hooking " + suCheckers.size() + " su path checkers");

        for (DexMethodData methodData : suCheckers) {
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
                        // If method returns boolean (isRooted check), force false
                        if (param.getResult() instanceof Boolean && (Boolean) param.getResult()) {
                            param.setResult(false);
                            XposedEntry.log("Su path checker neutralized: " + className);
                        } else if (param.getResult() != null) {
                            try {
                                Object res = param.getResult();
                                if (Boolean.TRUE.equals(de.robv.android.xposed.XposedHelpers.getObjectField(res, "b"))) {
                                    de.robv.android.xposed.XposedHelpers.setObjectField(res, "b", Boolean.FALSE);
                                    XposedEntry.log("Su path checker object field b neutralized: " + className);
                                }
                            } catch (Throwable ignored) {}
                        }
                    }
                });

                XposedEntry.log("Hooked su path checker: " + className + "." + methodName);

            } catch (Exception e) {
                XposedEntry.log("Failed to hook su checker: " + e.getMessage());
            }
        }
    }

    private static void hookPackageQueries(XC_LoadPackage.LoadPackageParam lpparam) {
        List<DexMethodData> packageQueries = DexKitDetector.findSuspiciousPackageQueries();
        if (packageQueries.isEmpty()) {
            XposedEntry.log("DynamicRoot: No package queries found by DexKit");
            return;
        }

        XposedEntry.log("DynamicRoot: Hooking " + packageQueries.size() + " package queries");

        for (DexMethodData methodData : packageQueries) {
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
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        // Check if querying for suspicious packages
                        for (Object arg : param.args) {
                            if (arg instanceof String) {
                                String pkg = (String) arg;
                                if (isSuspiciousPackage(pkg)) {
                                    if (param.method instanceof java.lang.reflect.Method) {
                                        java.lang.reflect.Method m = (java.lang.reflect.Method) param.method;
                                        Class<?> retType = m.getReturnType();
                                        if (retType == boolean.class) {
                                            param.setResult(false);
                                            return;
                                        }
                                        boolean canThrow = false;
                                        for (Class<?> ex : m.getExceptionTypes()) {
                                            if (ex.isAssignableFrom(android.content.pm.PackageManager.NameNotFoundException.class)) {
                                                canThrow = true;
                                                break;
                                            }
                                        }
                                        if (canThrow) {
                                            param.setThrowable(new android.content.pm.PackageManager.NameNotFoundException(
                                                "Package not found: " + pkg));
                                            return;
                                        } else {
                                            param.setResult(null);
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                    }
                });

                XposedEntry.log("Hooked package query: " + className + "." + methodName);

            } catch (Exception e) {
                XposedEntry.log("Failed to hook package query: " + e.getMessage());
            }
        }
    }

    @SuppressWarnings("deprecation")
    private static void hookInstalledPackages(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> pmsClass = de.robv.android.xposed.XposedHelpers.findClassIfExists(
                "android.app.ApplicationPackageManager", lpparam.classLoader);
            if (pmsClass == null) {
                pmsClass = android.content.pm.PackageManager.class;
            }

            // Hook getInstalledPackages
            HookUtils.hookAllMethods(pmsClass, "getInstalledPackages", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.content.pm.PackageInfo) {
                                String pn = ((android.content.pm.PackageInfo) item).packageName;
                                if (!isSuspiciousPackage(pn)) {
                                    filtered.add(item);
                                }
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            // Hook getInstalledApplications
            HookUtils.hookAllMethods(pmsClass, "getInstalledApplications", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.content.pm.ApplicationInfo) {
                                String pn = ((android.content.pm.ApplicationInfo) item).packageName;
                                if (!isSuspiciousPackage(pn)) {
                                    filtered.add(item);
                                }
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            // Hook getPackageInfo & getPackageInfoAsUser: 拦截敏感包查询，注入官方签名
            XC_MethodHook packageInfoHook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 0 && param.args[0] instanceof String) {
                        String pkg = (String) param.args[0];
                        if (isMtManagerPackage(pkg) && !isCallerSecurityComponent()) {
                            return;
                        }
                        if (isSuspiciousPackage(pkg)) {
                            if (isCallerQAuxv()) {
                                return;
                            }
                            param.setThrowable(new android.content.pm.PackageManager.NameNotFoundException("Package not found: " + pkg));
                            return;
                        }
                    }
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof android.content.pm.PackageInfo) {
                        android.content.pm.PackageInfo pi = (android.content.pm.PackageInfo) res;
                        String hostPkg = lpparam.packageName != null ? lpparam.packageName : "com.tencent.mobileqq";
                        if (hostPkg.equals(pi.packageName) || "com.tencent.mobileqq".equals(pi.packageName)) {
                            byte[] certBytes = android.util.Base64.decode(OFFICIAL_QQ_SIGNATURE_B64, android.util.Base64.DEFAULT);
                            android.content.pm.Signature officialSig = new android.content.pm.Signature(certBytes);

                            if (pi.signatures != null || isSignatureFlagRequested(param.args)) {
                                pi.signatures = new android.content.pm.Signature[]{ officialSig };
                            }

                            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                                try {
                                    if (pi.signingInfo != null) {
                                        java.lang.reflect.Field detailsField = pi.signingInfo.getClass().getDeclaredField("mSigningDetails");
                                        detailsField.setAccessible(true);
                                        Object signingDetails = detailsField.get(pi.signingInfo);
                                        if (signingDetails != null) {
                                            java.lang.reflect.Field sigsField = signingDetails.getClass().getDeclaredField("signatures");
                                            sigsField.setAccessible(true);
                                            sigsField.set(signingDetails, new android.content.pm.Signature[]{ officialSig });
                                        }
                                    }
                                } catch (Throwable ignored) {}
                            }
                        }
                    }
                }
            };
            HookUtils.hookAllMethods(pmsClass, "getPackageInfo", packageInfoHook);
            HookUtils.hookAllMethods(pmsClass, "getPackageInfoAsUser", packageInfoHook);

            // Hook getApplicationInfo & getPackageUid: 隐藏敏感包
            XC_MethodHook appInfoHook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 0 && param.args[0] instanceof String) {
                        String pkg = (String) param.args[0];
                        if (isMtManagerPackage(pkg) && !isCallerSecurityComponent()) {
                            return;
                        }
                        if (isSuspiciousPackage(pkg)) {
                            if (isCallerQAuxv()) {
                                return;
                            }
                            param.setThrowable(new android.content.pm.PackageManager.NameNotFoundException("Package not found: " + pkg));
                            return;
                        }
                    }
                }
            };
            HookUtils.hookAllMethods(pmsClass, "getApplicationInfo", appInfoHook);
            HookUtils.hookAllMethods(pmsClass, "getApplicationInfoAsUser", appInfoHook);
            HookUtils.hookAllMethods(pmsClass, "getPackageUid", appInfoHook);
            HookUtils.hookAllMethods(pmsClass, "getPackageUidAsUser", appInfoHook);

            // Hook QQ 内部 PackageUtil.isAppInstalled，防止 Bugly 等探测
            Class<?> pkgUtilClass = de.robv.android.xposed.XposedHelpers.findClassIfExists(
                "com.tencent.mobileqq.utils.PackageUtil", lpparam.classLoader);
            if (pkgUtilClass != null) {
                HookUtils.hookAllMethods(pkgUtilClass, "isAppInstalled", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null && param.args.length > 1 && param.args[1] instanceof String) {
                            String pkg = (String) param.args[1];
                            if (isMtManagerPackage(pkg) && !isCallerSecurityComponent()) {
                                return;
                            }
                            if (isSuspiciousPackage(pkg)) {
                                if (isCallerQAuxv()) {
                                    return;
                                }
                                param.setResult(false);
                            }
                        }
                    }
                });
            }

            // Hook queryIntentActivities
            HookUtils.hookAllMethods(pmsClass, "queryIntentActivities", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        boolean isFileIntent = isFileShareOrViewIntent(param.args);
                        for (Object item : list) {
                            if (item instanceof android.content.pm.ResolveInfo) {
                                android.content.pm.ResolveInfo ri = (android.content.pm.ResolveInfo) item;
                                String pkg = ri.activityInfo != null ? ri.activityInfo.packageName : null;
                                if (isMtManagerPackage(pkg)) {
                                    if (isFileIntent || !isCallerSecurityComponent()) {
                                        filtered.add(item);
                                        continue;
                                    }
                                }
                                if (!isSuspiciousPackage(pkg)) {
                                    filtered.add(item);
                                }
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            // Hook queryIntentServices
            HookUtils.hookAllMethods(pmsClass, "queryIntentServices", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.content.pm.ResolveInfo) {
                                android.content.pm.ResolveInfo ri = (android.content.pm.ResolveInfo) item;
                                String pkg = ri.serviceInfo != null ? ri.serviceInfo.packageName : null;
                                if (!isSuspiciousPackage(pkg)) {
                                    filtered.add(item);
                                }
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            // Hook queryBroadcastReceivers
            HookUtils.hookAllMethods(pmsClass, "queryBroadcastReceivers", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.content.pm.ResolveInfo) {
                                android.content.pm.ResolveInfo ri = (android.content.pm.ResolveInfo) item;
                                String pkg = ri.activityInfo != null ? ri.activityInfo.packageName : null;
                                if (!isSuspiciousPackage(pkg)) {
                                    filtered.add(item);
                                }
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            // Hook queryContentProviders
            HookUtils.hookAllMethods(pmsClass, "queryContentProviders", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.content.pm.ProviderInfo) {
                                android.content.pm.ProviderInfo pi = (android.content.pm.ProviderInfo) item;
                                if (!isSuspiciousPackage(pi.packageName)) {
                                    filtered.add(item);
                                }
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            // Hook resolveContentProvider
            HookUtils.hookAllMethods(pmsClass, "resolveContentProvider", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof android.content.pm.ProviderInfo) {
                        android.content.pm.ProviderInfo pi = (android.content.pm.ProviderInfo) res;
                        if (isSuspiciousPackage(pi.packageName) || (pi.authority != null && (pi.authority.contains("qauxv") || pi.authority.contains("lsposed")))) {
                            if (isCallerQAuxv()) return;
                            param.setResult(null);
                        }
                    }
                }
            });

            // Hook resolveActivity
            HookUtils.hookAllMethods(pmsClass, "resolveActivity", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof android.content.pm.ResolveInfo) {
                        android.content.pm.ResolveInfo ri = (android.content.pm.ResolveInfo) res;
                        String pkg = ri.activityInfo != null ? ri.activityInfo.packageName : null;
                        if (isMtManagerPackage(pkg)) {
                            if (isFileShareOrViewIntent(param.args) || !isCallerSecurityComponent()) {
                                return;
                            }
                        }
                        if (isSuspiciousPackage(pkg)) {
                            if (isCallerQAuxv()) return;
                            param.setResult(null);
                        }
                    }
                }
            });
        } catch (Throwable t) {
            XposedEntry.log("Failed to hook getInstalledPackages: " + t.getMessage());
        }
    }

    private static final String OFFICIAL_QQ_SIGNATURE_B64 =
        "MIICUzCCAbygAwIBAgIES7sDYTANBgkqhkiG9w0BAQUFADBtMQ4wDAYDVQQGEwVDaGluYTEPMA0GA1UE" +
        "CAwG5YyX5LqsMQ8wDQYDVQQHDAbljJfkuqwxDzANBgNVBAoMBuiFvuiurzEbMBkGA1UECwwS5peg57q/" +
        "5Lia5Yqh57O757ufMQswCQYDVQQDEwJRUTAgFw0xMDA0MDYwOTQ4MTdaGA8yMjg0MDEyMDA5NDgxN1ow" +
        "bTEOMAwGA1UEBhMFQ2hpbmExDzANBgNVBAgMBuWMl+S6rDEPMA0GA1UEBwwG5YyX5LqsMQ8wDQYDVQQK" +
        "DAbohb7orq8xGzAZBgNVBAsMEuaXoOe6v+S4muWKoeezu+e7nzELMAkGA1UEAxMCUVEwgZ8wDQYJKoZI" +
        "hvcNAQEBBQADgY0AMIGJAoGBAKFel1Yhb2lMWRXgtSkJUlQ2fE5k+u/weuE0iNlGYVpY3cMaQV9xfQGe" +
        "3G0wuWA9Pip7PeCrfgz1Lf7jk3O8Ry+plwJ9eY1Z+B1SWmns8Vbohf0eJ5CSQ4ayIwzJDjt63JVgPdz0" +
        "xAvccvItsPIWqZw3HTv4nLpleMYGmeig1TaVAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAlKm4DoBpFkXd" +
        "QtZhF3WoVfcbzU13y2Co4pQEA1peALIbzF1KViSCEmvZG2sOUHCTd86574wu/RLMixav2aFZ81C7JwsU" +
        "IE/wZdhDgycgcC4otBSR+8OiBfXy9CUm1n8XYU2Kl03mSHsshm7+3jtOSaD5FrqjwTNv0u4bFillIEk=";

    private static boolean isSignatureFlagRequested(Object[] args) {
        if (args == null || args.length < 2) return false;
        for (int i = 1; i < args.length; i++) {
            Object arg = args[i];
            if (arg instanceof Integer) {
                int flags = (Integer) arg;
                if ((flags & 0x00000040) != 0 || (flags & 0x08000000) != 0) {
                    return true;
                }
            } else if (arg instanceof Long) {
                long flags = (Long) arg;
                if ((flags & 0x00000040L) != 0 || (flags & 0x08000000L) != 0) {
                    return true;
                }
            }
        }
        return false;
    }

    private static void hookSystemProperties() {
        try {
            HookUtils.hookAllMethods("android.os.SystemProperties", "get", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length == 0 || !(param.args[0] instanceof String)) return;
                    String key = (String) param.args[0];
                    if ("ro.debuggable".equals(key)) {
                        param.setResult("0");
                    } else if ("ro.secure".equals(key)) {
                        param.setResult("1");
                    } else if ("ro.build.tags".equals(key)) {
                        param.setResult("release-keys");
                    } else if ("ro.boot.flash.locked".equals(key)) {
                        param.setResult("1");
                    } else if ("ro.boot.verifiedbootstate".equals(key)) {
                        param.setResult("green");
                    } else if ("sys.usb.config".equals(key) || "sys.usb.state".equals(key) || "persist.sys.usb.config".equals(key)) {
                        param.setResult("none");
                    } else if ("init.svc.adbd".equals(key)) {
                        param.setResult("stopped");
                    } else if (key.contains("magisk") || key.contains("ksu") || key.contains("apatch")) {
                        String def = param.args.length > 1 && param.args[1] instanceof String ? (String) param.args[1] : "";
                        param.setResult(def);
                    }
                }
            });

            HookUtils.hookAllMethods("android.os.SystemProperties", "getInt", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length == 0 || !(param.args[0] instanceof String)) return;
                    String key = (String) param.args[0];
                    if ("ro.debuggable".equals(key)) {
                        param.setResult(0);
                    } else if ("ro.secure".equals(key)) {
                        param.setResult(1);
                    } else if ("ro.boot.flash.locked".equals(key)) {
                        param.setResult(1);
                    } else if ("sys.usb.config".equals(key) || "sys.usb.state".equals(key)) {
                        param.setResult(0);
                    }
                }
            });

            HookUtils.hookAllMethods("android.os.SystemProperties", "getBoolean", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length == 0 || !(param.args[0] instanceof String)) return;
                    String key = (String) param.args[0];
                    if ("ro.debuggable".equals(key)) {
                        param.setResult(false);
                    } else if ("ro.secure".equals(key)) {
                        param.setResult(true);
                    } else if ("sys.usb.config".equals(key) || "sys.usb.state".equals(key)) {
                        param.setResult(false);
                    }
                }
            });
        } catch (Throwable t) {
            XposedEntry.log("Failed to hook SystemProperties: " + t.getMessage());
        }
    }

    private static void hookActivityManager(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> amClass = android.app.ActivityManager.class;

            // Hook getRunningAppProcesses
            HookUtils.hookAllMethods(amClass, "getRunningAppProcesses", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.app.ActivityManager.RunningAppProcessInfo) {
                                android.app.ActivityManager.RunningAppProcessInfo pi =
                                    (android.app.ActivityManager.RunningAppProcessInfo) item;
                                if (isSuspiciousPackage(pi.processName)) continue;
                                boolean hasSuspPkg = false;
                                if (pi.pkgList != null) {
                                    for (String p : pi.pkgList) {
                                        if (isSuspiciousPackage(p)) {
                                            hasSuspPkg = true;
                                            break;
                                        }
                                    }
                                }
                                if (hasSuspPkg) continue;
                                filtered.add(item);
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            // Hook getRunningTasks
            HookUtils.hookAllMethods(amClass, "getRunningTasks", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.app.ActivityManager.RunningTaskInfo) {
                                android.app.ActivityManager.RunningTaskInfo ti =
                                    (android.app.ActivityManager.RunningTaskInfo) item;
                                String topPkg = ti.topActivity != null ? ti.topActivity.getPackageName() : null;
                                String basePkg = ti.baseActivity != null ? ti.baseActivity.getPackageName() : null;
                                if (isSuspiciousPackage(topPkg) || isSuspiciousPackage(basePkg)) {
                                    continue;
                                }
                                filtered.add(item);
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            // Hook getRecentTasks
            HookUtils.hookAllMethods(amClass, "getRecentTasks", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.app.ActivityManager.RecentTaskInfo) {
                                android.app.ActivityManager.RecentTaskInfo rti =
                                    (android.app.ActivityManager.RecentTaskInfo) item;
                                String pkg = rti.baseIntent != null && rti.baseIntent.getComponent() != null ?
                                    rti.baseIntent.getComponent().getPackageName() : null;
                                if (isSuspiciousPackage(pkg)) {
                                    continue;
                                }
                                filtered.add(item);
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            // Hook getRunningServices
            HookUtils.hookAllMethods(amClass, "getRunningServices", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.app.ActivityManager.RunningServiceInfo) {
                                android.app.ActivityManager.RunningServiceInfo rsi =
                                    (android.app.ActivityManager.RunningServiceInfo) item;
                                String pkg = rsi.service != null ? rsi.service.getPackageName() : null;
                                if (isSuspiciousPackage(pkg) || isSuspiciousPackage(rsi.process)) {
                                    continue;
                                }
                                filtered.add(item);
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });
            XposedEntry.log("[DynamicRoot] Hooked ActivityManager running processes/tasks/services");
        } catch (Throwable t) {
            XposedEntry.log("[DynamicRoot] Failed to hook ActivityManager: " + t.getMessage());
        }
    }

    private static void hookInstalledAppListMonitor(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> monitorClass = de.robv.android.xposed.XposedHelpers.findClassIfExists(
                "com.tencent.qmethod.pandoraex.monitor.InstalledAppListMonitor", lpparam.classLoader);
            if (monitorClass == null) return;

            // Hook getRunningAppProcesses
            HookUtils.hookAllMethods(monitorClass, "getRunningAppProcesses", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.app.ActivityManager.RunningAppProcessInfo) {
                                android.app.ActivityManager.RunningAppProcessInfo pi =
                                    (android.app.ActivityManager.RunningAppProcessInfo) item;
                                if (isSuspiciousPackage(pi.processName)) continue;
                                boolean hasSuspPkg = false;
                                if (pi.pkgList != null) {
                                    for (String p : pi.pkgList) {
                                        if (isSuspiciousPackage(p)) {
                                            hasSuspPkg = true;
                                            break;
                                        }
                                    }
                                }
                                if (hasSuspPkg) continue;
                                filtered.add(item);
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            // Hook getRunTasks
            HookUtils.hookAllMethods(monitorClass, "getRunTasks", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.app.ActivityManager.RunningTaskInfo) {
                                android.app.ActivityManager.RunningTaskInfo ti =
                                    (android.app.ActivityManager.RunningTaskInfo) item;
                                String topPkg = ti.topActivity != null ? ti.topActivity.getPackageName() : null;
                                String basePkg = ti.baseActivity != null ? ti.baseActivity.getPackageName() : null;
                                if (isSuspiciousPackage(topPkg) || isSuspiciousPackage(basePkg)) {
                                    continue;
                                }
                                filtered.add(item);
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            // Hook getInstalledPackages
            HookUtils.hookAllMethods(monitorClass, "getInstalledPackages", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.content.pm.PackageInfo) {
                                String pn = ((android.content.pm.PackageInfo) item).packageName;
                                if (!isSuspiciousPackage(pn)) {
                                    filtered.add(item);
                                }
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            // Hook getInstalledApplications
            HookUtils.hookAllMethods(monitorClass, "getInstalledApplications", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.content.pm.ApplicationInfo) {
                                String pn = ((android.content.pm.ApplicationInfo) item).packageName;
                                if (!isSuspiciousPackage(pn)) {
                                    filtered.add(item);
                                }
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            // Hook getPackageInfo
            HookUtils.hookAllMethods(monitorClass, "getPackageInfo", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 1 && param.args[1] instanceof String) {
                        String pkg = (String) param.args[1];
                        if (isSuspiciousPackage(pkg)) {
                            if (isCallerQAuxv()) return;
                            param.setThrowable(new android.content.pm.PackageManager.NameNotFoundException(pkg));
                        }
                    }
                }
            });

            // Hook getLaunchIntentForPackage
            HookUtils.hookAllMethods(monitorClass, "getLaunchIntentForPackage", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 1 && param.args[1] instanceof String) {
                        String pkg = (String) param.args[1];
                        if (isSuspiciousPackage(pkg)) {
                            if (isCallerQAuxv()) return;
                            param.setResult(null);
                        }
                    }
                }
            });

            // Hook queryIntentActivities
            HookUtils.hookAllMethods(monitorClass, "queryIntentActivities", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        boolean isFileIntent = isFileShareOrViewIntent(param.args);
                        for (Object item : list) {
                            if (item instanceof android.content.pm.ResolveInfo) {
                                android.content.pm.ResolveInfo ri = (android.content.pm.ResolveInfo) item;
                                String pkg = ri.activityInfo != null ? ri.activityInfo.packageName : null;
                                if (isMtManagerPackage(pkg)) {
                                    if (isFileIntent || !isCallerSecurityComponent()) {
                                        filtered.add(item);
                                        continue;
                                    }
                                }
                                if (!isSuspiciousPackage(pkg)) {
                                    filtered.add(item);
                                }
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            // Hook queryIntentServices
            HookUtils.hookAllMethods(monitorClass, "queryIntentServices", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.content.pm.ResolveInfo) {
                                android.content.pm.ResolveInfo ri = (android.content.pm.ResolveInfo) item;
                                String pkg = ri.serviceInfo != null ? ri.serviceInfo.packageName : null;
                                if (!isSuspiciousPackage(pkg)) {
                                    filtered.add(item);
                                }
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            // Hook getLastApplicationInfoList & getLastPackageInfoList
            HookUtils.hookAllMethods(monitorClass, "getLastApplicationInfoList", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.content.pm.ApplicationInfo) {
                                String pn = ((android.content.pm.ApplicationInfo) item).packageName;
                                if (!isSuspiciousPackage(pn)) filtered.add(item);
                            } else filtered.add(item);
                        }
                        param.setResult(filtered);
                    }
                }
            });

            HookUtils.hookAllMethods(monitorClass, "getLastPackageInfoList", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.content.pm.PackageInfo) {
                                String pn = ((android.content.pm.PackageInfo) item).packageName;
                                if (!isSuspiciousPackage(pn)) filtered.add(item);
                            } else filtered.add(item);
                        }
                        param.setResult(filtered);
                    }
                }
            });

            XposedEntry.log("[DynamicRoot] Hooked InstalledAppListMonitor");
        } catch (Throwable t) {
            XposedEntry.log("[DynamicRoot] Failed to hook InstalledAppListMonitor: " + t.getMessage());
        }
    }

    private static void hookUsageStatsManager(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> usmClass = android.app.usage.UsageStatsManager.class;
            HookUtils.hookAllMethods(usmClass, "queryUsageStats", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.app.usage.UsageStats) {
                                String pn = ((android.app.usage.UsageStats) item).getPackageName();
                                if (!isSuspiciousPackage(pn)) filtered.add(item);
                            } else filtered.add(item);
                        }
                        param.setResult(filtered);
                    }
                }
            });
            HookUtils.hookAllMethods(usmClass, "queryAndAggregateUsageStats", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof java.util.Map) {
                        @SuppressWarnings("unchecked")
                        java.util.Map<String, android.app.usage.UsageStats> map =
                            (java.util.Map<String, android.app.usage.UsageStats>) res;
                        java.util.Map<String, android.app.usage.UsageStats> filtered = new java.util.HashMap<>();
                        for (java.util.Map.Entry<String, android.app.usage.UsageStats> entry : map.entrySet()) {
                            if (!isSuspiciousPackage(entry.getKey())) {
                                filtered.put(entry.getKey(), entry.getValue());
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });
            XposedEntry.log("[DynamicRoot] Hooked UsageStatsManager");
        } catch (Throwable t) {
            XposedEntry.log("[DynamicRoot] Failed to hook UsageStatsManager: " + t.getMessage());
        }
    }

    public static boolean isCallerQAuxv() {
        try {
            StackTraceElement[] stack = Thread.currentThread().getStackTrace();
            for (StackTraceElement elem : stack) {
                String cls = elem.getClassName();
                if (cls != null && (
                    cls.startsWith("io.github.qauxv.") ||
                    cls.startsWith("cc.ioctl.") ||
                    cls.startsWith("me.singleneuron.") ||
                    cls.startsWith("nep.timeline.") ||
                    cls.startsWith("me.ketal.") ||
                    cls.startsWith("me.hd.") ||
                    cls.startsWith("xyz.nextalone.") ||
                    cls.startsWith("top.linl.") ||
                    cls.startsWith("net.bytebuddy.") ||
                    cls.startsWith("io.github.libxposed.") ||
                    cls.startsWith("com.android.dx.")
                )) {
                    return true;
                }
            }
        } catch (Throwable ignored) {}
        return false;
    }

    public static boolean isCallerSecurityComponent() {
        try {
            StackTraceElement[] stack = Thread.currentThread().getStackTrace();
            for (StackTraceElement elem : stack) {
                String cls = elem.getClassName();
                if (cls == null) continue;
                String lower = cls.toLowerCase();
                if (lower.contains(".qsec.") || lower.contains(".turing") || lower.contains(".beacon.")
                        || lower.contains(".pandora") || lower.contains(".bugly.")
                        || lower.contains(".feedback.") || lower.contains("gathererga")
                        || lower.contains("camerasdk.avreport")
                        || lower.contains(".mobileqq.msf.")
                        || lower.contains("oicq.wlogin_sdk")
                        || lower.contains(".qqperf.")) {
                    return true;
                }
            }
        } catch (Throwable ignored) {}
        return false;
    }

    public static boolean isMtManagerPackage(String pkg) {
        if (pkg == null) return false;
        String lower = pkg.toLowerCase();
        return lower.contains("bin.mt.") || lower.equals("bin.mt") || lower.contains("bin.mt.plus")
                || lower.contains("bin.mt.manager") || lower.contains("bin.mt.termex");
    }

    public static boolean isFileShareOrViewIntent(Object[] args) {
        if (args == null) return false;
        for (Object arg : args) {
            if (arg instanceof android.content.Intent) {
                android.content.Intent intent = (android.content.Intent) arg;
                String action = intent.getAction();
                if (action == null) {
                    if (intent.getData() != null || intent.getType() != null) return true;
                    continue;
                }
                if (android.content.Intent.ACTION_VIEW.equals(action)
                        || android.content.Intent.ACTION_SEND.equals(action)
                        || android.content.Intent.ACTION_SEND_MULTIPLE.equals(action)
                        || android.content.Intent.ACTION_EDIT.equals(action)
                        || android.content.Intent.ACTION_CHOOSER.equals(action)
                        || action.contains("OPEN") || action.contains("SHARE")
                        || action.contains("VIEW") || action.contains("SEND")) {
                    return true;
                }
                if (intent.getData() != null || intent.getType() != null) {
                    return true;
                }
            }
        }
        return false;
    }

    public static boolean isSuspiciousPath(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase();

        // QAuxiliary storage and private directories: allow QAuxv, hide ONLY from security components
        if (lower.contains("qa_mmkv") || lower.contains("tmp_qa_")
                || lower.contains("qa_dyn_lib") || lower.contains("qa_misc")
                || lower.contains("io.github.qauxv") || lower.contains("libqauxv")) {
            if (isCallerQAuxv()) {
                return false;
            }
            return isCallerSecurityComponent();
        }

        // MT Manager paths & storage: hide only from security components, allow user/file actions
        if (lower.contains("bin.mt.plus") || lower.contains("bin.mt.manager")
                || lower.contains("bin.mt.termex") || lower.contains("bin.mt.")
                || lower.contains("/mt2")) {
            return isCallerSecurityComponent();
        }

        if (lower.contains("top.nkbe.npatch") || lower.contains("npatch")
                || lower.contains("org.lsposed.manager")) {
            return true;
        }

        for (String suPath : SU_PATHS) {
            if (lower.contains(suPath)) return true;
        }

        return lower.contains("magisk") || lower.contains("supersu")
            || lower.contains("superuser") || lower.contains("ksu")
            || lower.contains("apatch") || lower.contains("shamiko")
            || lower.contains("xposed") || lower.contains("lsposed")
            || lower.contains("frida") || lower.contains("/data/adb")
            || lower.contains("dexkit") || lower.contains("sandhook")
            || lower.contains("yahfa") || lower.contains("liblspd")
            || lower.contains("qqbypass") || lower.contains("native-bypass")
            || lower.contains("bytehook") || lower.contains("xalsace");
    }

    public static boolean isSuspiciousPackage(String pkg) {
        if (pkg == null) return false;
        String lower = pkg.toLowerCase();

        // MT Manager: hide from security scanners (QSec, Turing, Beacon, Pandora), but allow in file viewer/UI chooser
        if (isMtManagerPackage(lower)) {
            return isCallerSecurityComponent();
        }

        return lower.contains("magisk") || lower.contains("supersu")
            || lower.contains("superuser") || lower.contains("xposed")
            || lower.contains("lsposed") || lower.contains("edxposed")
            || lower.contains("kernelsu") || lower.contains("apatch")
            || lower.contains("shamiko") || lower.contains("frida")
            || lower.contains("me.weishu") || lower.contains("me.bmax")
            || lower.contains("sandhook") || lower.contains("taichi")
            || lower.contains("top.canyie") || lower.contains("xalsace")
            || lower.contains("qqbypass") || lower.contains("dexkit")
            || lower.contains("top.nkbe.npatch") || lower.contains("npatch")
            || lower.contains("org.lsposed.manager") || lower.contains("youqu.android.todesk")
            || lower.contains("com.netease.uuremote") || lower.contains("com.topjohnwu.magisk")
            || lower.contains("io.github.qauxv") || lower.contains("qauxv")
            || lower.contains("qnotified") || lower.contains("cc.ioctl")
            || lower.contains("me.singleneuron") || lower.contains("nep.timeline");
    }
}
