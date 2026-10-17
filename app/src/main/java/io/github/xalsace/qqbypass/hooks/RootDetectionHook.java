package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.utils.HookUtils;

import java.io.File;

/**
 * Root Detection Bypass Hook
 *
 * Bypasses Java-layer root detection implementations:
 * 1. oicq.wlogin_sdk.request.w.h() - Wlogin SDK
 * 2. org.light.device.LightDeviceUtils.isRooted()
 * 3. com.tenpay.charge.v2.util.ChargeV2Utils.isDeviceRooted()
 *
 * Note: Native-layer detection (libfekit.so) requires native hooks
 * QQ 9.3.50 removed: gathererga.UserInfoImpl, bugly.proguard.cp, camerasdk.avreport.DeviceInfo
 */
public class RootDetectionHook {

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_ROOT_BYPASS) return;

        XposedEntry.log("Initializing Root Detection Bypass");

        // Hook 1: Wlogin SDK root check
        hookWloginRoot();

        // Hook 2: Light Device Utils
        hookLightDeviceRoot();

        // Hook 3: Tenpay charge utils
        hookTenpayRoot();

        // Generic file existence checks for su binaries
        hookFileExists();

        // Hook Runtime.exec to prevent su detection
        hookRuntimeExec();
    }

    private static void hookWloginRoot() {
        HookUtils.hookAllMethods("oicq.wlogin_sdk.request.w", "h",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    // This method collects device info including root status
                    // We let it run but will block the network report
                    XposedEntry.log("Wlogin root check intercepted");
                }
            });
    }

    private static void hookLightDeviceRoot() {
        HookUtils.hookMethod("org.light.device.LightDeviceUtils", "isRooted",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(false);
                    XposedEntry.log("LightDevice isRooted: false");
                }
            });
    }

    private static void hookTenpayRoot() {
        HookUtils.hookMethod("com.tenpay.charge.v2.util.ChargeV2Utils", "isDeviceRooted",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(false);
                    XposedEntry.log("Tenpay isDeviceRooted: false");
                }
            });
    }

    private static void hookFileExists() {
        // Hook File status methods to hide su binaries and root artifacts
        XC_MethodHook fileCheckHook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                File file = (File) param.thisObject;
                String path = file.getAbsolutePath();
                if (isSuspiciousPath(path)) {
                    String methodName = param.method.getName();
                    if ("length".equals(methodName)) {
                        param.setResult(0L);
                    } else {
                        param.setResult(false);
                    }
                }
            }
        };

        HookUtils.hookMethod(File.class, "exists", fileCheckHook);
        HookUtils.hookMethod(File.class, "canRead", fileCheckHook);
        HookUtils.hookMethod(File.class, "canExecute", fileCheckHook);
        HookUtils.hookMethod(File.class, "length", fileCheckHook);
    }

    private static void hookRuntimeExec() {
        // Hook Runtime.exec to prevent command-based detection
        HookUtils.hookAllMethods("java.lang.Runtime", "exec",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args.length > 0) {
                        String command = param.args[0].toString();

                        // Block root-detection commands
                        if (command.contains("su") ||
                            command.contains("magisk") ||
                            command.contains("which") ||
                            (command.contains("mount") && command.contains("grep"))) {

                            XposedEntry.log("Blocked Runtime.exec: " + command);
                            // Return a dummy process that exits immediately
                            param.setResult(new ProcessBuilder("echo").start());
                        }
                    }
                }
            });
    }

    private static boolean isSuspiciousPath(String path) {
        if (path == null) return false;
        // Comprehensive list of root-related paths
        String[] suspiciousPaths = {
            "/data/local/su",
            "/data/local/bin/su",
            "/data/local/xbin/su",
            "/sbin/su",
            "/su/bin/su",
            "/system/bin/su",
            "/system/bin/.ext/.su",
            "/system/sd/xbin/su",
            "/system/usr/we-need-root/su",
            "/system/xbin/su",
            "/system/app/Superuser.apk",
            "/system/app/SuperSU.apk",
            "/system/etc/init.d/99SuperSUDaemon",
            "/dev/com.koushikdutta.superuser.daemon/",
            "/system/xbin/daemonsu",
            // Magisk & KernelSU & APatch
            "/data/adb",
            "/sbin/.magisk",
            "/cache/magisk.log",
            "mountify",
            "tricky_store",
            "zygisksu",
            "metamodule",
            "busybox"
        };

        for (String suspicious : suspiciousPaths) {
            if (path.contains(suspicious)) {
                return true;
            }
        }
        return false;
    }
}
