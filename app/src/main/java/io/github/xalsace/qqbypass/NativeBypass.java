package io.github.xalsace.qqbypass;

import android.util.Log;

/**
 * JNI bridge for native hooks
 *
 * This class loads the native library and provides interface
 * to initialize and check native hook status.
 */
public class NativeBypass {

    private static final String TAG = "NativeBypass";
    private static boolean libraryLoaded = false;

    static {
        loadLibraries();
    }

    private static synchronized void loadLibraries() {
        if (libraryLoaded) return;
        try {
            // 1. 尝试直接加载 libbytehook.so
            try {
                System.loadLibrary("bytehook");
            } catch (Throwable t) {
                try {
                    com.bytedance.android.bytehook.ByteHook.init();
                } catch (Throwable ignored) {}
            }

            // 2. 尝试加载 libnative-bypass.so
            System.loadLibrary("native-bypass");
            libraryLoaded = true;
            Log.i(TAG, "Native library loaded successfully via System.loadLibrary");
            return;
        } catch (Throwable e) {
            Log.w(TAG, "System.loadLibrary failed, attempting fallback extraction: " + e.getMessage());
        }

        // 3. Fallback: 从模块 APK 动态提取 .so 到目标应用 code_cache 目录并直接 load
        try {
            java.io.File cacheDir = new java.io.File("/data/data/com.tencent.mobileqq/code_cache");
            if (!cacheDir.exists()) cacheDir.mkdirs();

            String moduleApkPath = null;
            try {
                java.io.File maps = new java.io.File("/proc/self/maps");
                if (maps.exists()) {
                    java.io.BufferedReader br = new java.io.BufferedReader(new java.io.FileReader(maps));
                    String line;
                    while ((line = br.readLine()) != null) {
                        if (line.contains("io.github.xalsace.qqbypass") && line.contains(".apk")) {
                            int idx = line.indexOf('/');
                            if (idx != -1) {
                                moduleApkPath = line.substring(idx).trim();
                                break;
                            }
                        }
                    }
                    br.close();
                }
            } catch (Throwable ignored) {}

            if (moduleApkPath != null && new java.io.File(moduleApkPath).exists()) {
                java.util.zip.ZipFile zf = new java.util.zip.ZipFile(moduleApkPath);
                
                // 提取 libbytehook.so
                java.util.zip.ZipEntry bhEntry = zf.getEntry("lib/arm64-v8a/libbytehook.so");
                if (bhEntry != null) {
                    java.io.File bhOut = new java.io.File(cacheDir, "libbytehook_bypass.so");
                    java.io.InputStream in = zf.getInputStream(bhEntry);
                    java.io.FileOutputStream fos = new java.io.FileOutputStream(bhOut);
                    byte[] buf = new byte[8192];
                    int len;
                    while ((len = in.read(buf)) > 0) fos.write(buf, 0, len);
                    fos.close();
                    in.close();
                    System.load(bhOut.getAbsolutePath());
                    Log.i(TAG, "Fallback: Loaded libbytehook from " + bhOut.getAbsolutePath());
                }

                // 提取 libnative-bypass.so
                java.util.zip.ZipEntry nbEntry = zf.getEntry("lib/arm64-v8a/libnative-bypass.so");
                if (nbEntry != null) {
                    java.io.File nbOut = new java.io.File(cacheDir, "libnative-bypass_bypass.so");
                    java.io.InputStream in = zf.getInputStream(nbEntry);
                    java.io.FileOutputStream fos = new java.io.FileOutputStream(nbOut);
                    byte[] buf = new byte[8192];
                    int len;
                    while ((len = in.read(buf)) > 0) fos.write(buf, 0, len);
                    fos.close();
                    in.close();
                    System.load(nbOut.getAbsolutePath());
                    libraryLoaded = true;
                    Log.i(TAG, "Fallback: Loaded libnative-bypass from " + nbOut.getAbsolutePath());
                }
                zf.close();
            }
        } catch (Throwable t) {
            Log.e(TAG, "Fallback extraction failed: " + t.getMessage(), t);
        }
    }

    /**
     * Check if native library is loaded
     */
    public static boolean isLibraryLoaded() {
        if (!libraryLoaded) {
            loadLibraries();
        }
        return libraryLoaded;
    }

    /**
     * Initialize native hooks
     * This should be called early in QQ's lifecycle
     */
    public static void initNativeHooks() {
        if (!libraryLoaded) {
            Log.e(TAG, "Native library not loaded, cannot init hooks");
            return;
        }

        try {
            initNativeHooksNative();
            Log.i(TAG, "Native hooks initialization started");
        } catch (Throwable t) {
            Log.e(TAG, "Failed to init native hooks", t);
        }
    }

    /**
     * Check if native hooks are installed
     */
    public static boolean isHooksInstalled() {
        if (!libraryLoaded) {
            return false;
        }

        try {
            return isHooksInstalledNative();
        } catch (Throwable t) {
            Log.e(TAG, "Failed to check hook status", t);
            return false;
        }
    }

    /**
     * Get hook status message
     */
    public static String getHookStatus() {
        if (!libraryLoaded) {
            return "Native library not loaded";
        }

        try {
            return getHookStatusNative();
        } catch (Throwable t) {
            return "Error getting hook status: " + t.getMessage();
        }
    }

    /**
     * Notify Native layer about Java detection event
     * This enables Java → Native communication
     */
    public static void notifyDetection(String event, String data) {
        if (!libraryLoaded) {
            return;
        }

        try {
            notifyDetectionNative(event, data);
        } catch (Throwable t) {
            Log.w(TAG, "Failed to notify native layer: " + t.getMessage());
        }
    }

    /**
     * Check if specific Native hook is active
     */
    public static boolean isHookActive(String hookName) {
        if (!libraryLoaded) {
            return false;
        }

        try {
            return isHookActiveNative(hookName);
        } catch (Throwable t) {
            return false;
        }
    }

    /**
     * Get detailed hook statistics
     */
    public static String getHookStatistics() {
        if (!libraryLoaded) {
            return "Native layer unavailable";
        }

        try {
            return getHookStatisticsNative();
        } catch (Throwable t) {
            return "Error: " + t.getMessage();
        }
    }

    // Native methods
    private static native void initNativeHooksNative();
    private static native boolean isHooksInstalledNative();
    private static native String getHookStatusNative();
    private static native void notifyDetectionNative(String event, String data);
    private static native boolean isHookActiveNative(String hookName);
    private static native String getHookStatisticsNative();
}
