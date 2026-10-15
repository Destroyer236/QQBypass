package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.detector.DexMethodData;

import java.io.File;
import java.lang.reflect.Member;
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
    private static volatile boolean sBeaconDHooked = false;
    private static volatile boolean sBeaconEHooked = false;

    private static void hookBeaconClassD(Class<?> beaconUtilD) {
        if (sBeaconDHooked || beaconUtilD == null) return;
        sBeaconDHooked = true;
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
        if (sBeaconEHooked || beaconDevInfo == null) return;
        sBeaconEHooked = true;
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
                    }
                }
            });
        } catch (Throwable t) {
            XposedEntry.log("Failed to hook SystemProperties: " + t.getMessage());
        }
    }

    private static boolean isCallerQAuxv() {
        try {
            StackTraceElement[] stack = Thread.currentThread().getStackTrace();
            for (StackTraceElement elem : stack) {
                String cls = elem.getClassName();
                if (cls != null && (cls.startsWith("io.github.qauxv.") || cls.startsWith("cc.ioctl."))) {
                    return true;
                }
            }
        } catch (Throwable ignored) {}
        return false;
    }

    private static boolean isSuspiciousPath(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase();

        for (String suPath : SU_PATHS) {
            if (lower.contains(suPath)) return true;
        }

        return lower.contains("magisk") || lower.contains("supersu")
            || lower.contains("superuser") || lower.contains("ksu")
            || lower.contains("apatch") || lower.contains("shamiko")
            || lower.contains("xposed") || lower.contains("lsposed")
            || lower.contains("frida") || lower.contains("/data/adb")
            || lower.contains("dexkit") || lower.contains("sandhook")
            || lower.contains("yahfa") || lower.contains("liblspd");
    }

    private static boolean isSuspiciousPackage(String pkg) {
        if (pkg == null) return false;
        String lower = pkg.toLowerCase();

        return lower.contains("magisk") || lower.contains("supersu")
            || lower.contains("superuser") || lower.contains("xposed")
            || lower.contains("lsposed") || lower.contains("edxposed")
            || lower.contains("kernelsu") || lower.contains("apatch")
            || lower.contains("shamiko") || lower.contains("frida")
            || lower.contains("me.weishu") || lower.contains("me.bmax")
            || lower.contains("sandhook") || lower.contains("taichi")
            || lower.contains("top.canyie") || lower.contains("xalsace")
            || lower.contains("qqbypass") || lower.contains("dexkit")
            || lower.contains("bin.mt.plus") || lower.contains("youqu.android.todesk")
            || lower.contains("com.netease.uuremote") || lower.contains("com.topjohnwu.magisk")
            || lower.contains("io.github.qauxv") || lower.contains("qauxv")
            || lower.contains("qnotified") || lower.contains("cc.ioctl");
    }
}
