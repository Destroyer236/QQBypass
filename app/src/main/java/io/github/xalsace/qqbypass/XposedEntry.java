package io.github.xalsace.qqbypass;

import android.util.Log;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.detector.DexKitDetector;
import io.github.xalsace.qqbypass.hooks.*;

/**
 * QQ Enhanced Bypass - Comprehensive Detection Bypass Module
 *
 * This module provides multi-layered protection against QQ's environment detection:
 * - Java Layer: Root/Xposed/Debug detection bypass (30%)
 * - Native Layer: libc/libfekit/libturingxq hooks (70%)
 * - Network reporting interception
 * - Device info spoofing with cross-validation protection
 */
public class XposedEntry implements IXposedHookLoadPackage {

    private static final String TAG = "QQEnhancedBypass";
    private static final String TARGET_PACKAGE = "com.tencent.mobileqq";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (!TARGET_PACKAGE.equals(lpparam.packageName)) {
            return;
        }

        log("=== QQ Enhanced Bypass v2.0 ===");
        log("Package: " + lpparam.packageName);
        log("Process: " + lpparam.processName);

        // Initialize configuration
        HookConfig.init(lpparam);

        // Process gate: DexKitBridge.create() parses the whole ~112MB APK. QQ runs
        // several processes (main, :MSF, ...); parsing in every one caused a
        // memory/CPU spike that could get the process killed on cold start (the
        // "1-2s flash-exit"). Only the main process runs DexKit; subprocesses keep
        // the cheap universal framework hooks. main process: processName == packageName.
        boolean isMainProcess = lpparam.packageName.equals(lpparam.processName);
        DexKitDetector.setEnabled(isMainProcess);
        log("DexKit enabled for this process: " + isMainProcess);

        // === DexKit Disk Cache Check (< 5ms) ===
        // If app and module versions are unchanged, load cached method signatures from disk directly
        boolean cacheHit = DexKitDetector.tryInitWithCache(lpparam);
        if (cacheHit) {
            log("=== DexKit: Disk cache HIT! Restored " + DexKitDetector.getCachedCount() + " detection points from disk, DexKit scan skipped ===");
        } else if (isMainProcess) {
            // === DexKit Dynamic Detection (Background Thread) on Cache Miss ===
            new Thread(() -> {
                try {
                    log("=== DexKit: Disk cache MISS or EXPIRED, starting dynamic scan ===");
                    String apkPath = lpparam.appInfo != null ? lpparam.appInfo.sourceDir : null;
                    if (apkPath == null) {
                        try {
                            android.content.Context context = (android.content.Context)
                                de.robv.android.xposed.XposedHelpers.callStaticMethod(
                                    de.robv.android.xposed.XposedHelpers.findClass(
                                        "android.app.ActivityThread", null),
                                    "currentApplication");
                            if (context != null && context.getApplicationInfo() != null) {
                                apkPath = context.getApplicationInfo().sourceDir;
                            }
                        } catch (Throwable ignored) { }
                    }

                    if (apkPath != null) {
                        DexKitDetector.scanAndCache(apkPath, lpparam);
                        log("=== DexKit Scan & Disk Caching Complete (" + DexKitDetector.getCachedCount() + " points cached) ===");
                    }
                } catch (Throwable e) {
                    log("DexKit scan failed: " + e.getMessage());
                }
            }).start();
        }

        try {
            // === Initialize Unified Hook Coordinator ===
            // This coordinates Java and Native layers seamlessly
            UnifiedHookCoordinator.initialize(lpparam);

            // === Java Layer Hooks (30% detection coverage) ===

            // Layer 1: Network reporting interception (highest priority)
            NetworkReportHook.hook(lpparam);

            // Layer 2: Root detection bypass (DexKit-based dynamic version)
            DynamicRootDetectionHook.hook(lpparam);

            // Layer 3: Xposed/Hook framework detection mitigation (DexKit-based dynamic version)
            DynamicXposedDetectionHook.hook(lpparam);

            // Layer 4: Device info consistency protection (DexKit-based dynamic version)
            DynamicDeviceInfoHook.hook(lpparam);

            // Layer 5: Debug/Emulator detection bypass (DexKit-based dynamic version)
            DynamicDebugDetectionHook.hook(lpparam);

            // Layer 6: Runtime monitoring bypass (DexKit-based dynamic version)
            DynamicRuntimeMonitorHook.hook(lpparam);

            // Layer 7: QQ 9.3.50 detection-point completion (real risk/kick targets)
            QQ950PatchHook.hook(lpparam);

            // Layer 8: QAuxv (QNotified) compatibility & BaseApk crash prevention
            io.github.xalsace.qqbypass.hooks.QAuxvCompatHook.hook(lpparam);

            // === Report Status ===
            log("=== Java Hooks Initialized ===");
            log("Initial Protection Level: " + UnifiedHookCoordinator.getProtectionLevel());
            // Native 层在后台线程异步安装，稍后报告最终等级
            UnifiedHookCoordinator.reportFinalProtectionLevelAsync();

        } catch (Throwable t) {
            log("Error during hook initialization: " + t.getMessage());
            t.printStackTrace();
        }
    }

    /**
     * Initialize native layer hooks (deprecated - now handled by UnifiedHookCoordinator)
     */
    @Deprecated
    private void initNativeHooks() {
        // This method is kept for compatibility but functionality moved to UnifiedHookCoordinator
    }

    public static void log(String message) {
        Log.i(TAG, message);
    }

    public static void logError(String message, Throwable t) {
        Log.e(TAG, message, t);
    }
}
