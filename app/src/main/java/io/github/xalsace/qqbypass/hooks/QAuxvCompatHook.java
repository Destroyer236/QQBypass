package io.github.xalsace.qqbypass.hooks;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.Set;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.utils.HookUtils;

/**
 * QAuxv (QNotified) Compatibility & Crash Prevention Layer
 *
 * Resolves NPE in QAuxv BaseApk.lambda$initOnce$1$cc-ioctl-hook-file-BaseApk:
 * In QQ 9.3.70 NT, the hooked method for sending troop files is:
 * com.tencent.mobileqq.filemanager.uftwrapper.b.d(long, Item, Bundle)
 * The target Item is passed in args[1], but QAuxv erroneously searches for an Item field
 * on thisObject (uftwrapper.b), which has no such field, causing field == null and throwing:
 * java.lang.NullPointerException: Attempt to invoke virtual method 'Field.get(Object)' on null object reference.
 *
 * This hook:
 * 1. Safely intercepts QAuxv's BaseApk lambda and lambda wrapper, providing the correct Item from args[1].
 * 2. Implements the correct APK renaming logic without throwing NPE.
 * 3. Pre-emptively sanitizes Item in uftwrapper.b.d so both QAuxv and QQ process APK files smoothly.
 */
public class QAuxvCompatHook {

    private static final String TAG = "QAuxvCompat";
    private static volatile boolean sBaseApkPatched = false;

    public static void hook(final XC_LoadPackage.LoadPackageParam lpparam) {
        XposedEntry.log("[" + TAG + "] Initializing QAuxv compatibility and BaseApk crash prevention");

        // 1. Hook ClassLoader.loadClass to intercept cc.ioctl.hook.file.BaseApk when loaded by QAuxv
        try {
            HookUtils.hookAllMethods(ClassLoader.class, "loadClass", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args != null && p.args.length > 0 && "cc.ioctl.hook.file.BaseApk".equals(p.args[0])) {
                        Class<?> clazz = (Class<?>) p.getResult();
                        if (clazz != null) {
                            patchBaseApkClass(clazz);
                        }
                    }
                }
            });
        } catch (Throwable t) {
            XposedEntry.log("[" + TAG + "] Error hooking ClassLoader.loadClass: " + t.getMessage());
        }

        // 2. Also check if QAuxv was already loaded in existing ClassLoaders
        tryScanExistingClassLoaders();

        // 3. Pre-emptive hook on com.tencent.mobileqq.filemanager.uftwrapper.b.d
        hookUftwrapperBD(lpparam);
    }

    private static void tryScanExistingClassLoaders() {
        try {
            Map<Thread, StackTraceElement[]> traces = Thread.getAllStackTraces();
            Set<Thread> threads = traces.keySet();
            for (Thread t : threads) {
                ClassLoader cl = t.getContextClassLoader();
                if (cl != null) {
                    try {
                        Class<?> clazz = cl.loadClass("cc.ioctl.hook.file.BaseApk");
                        if (clazz != null) {
                            patchBaseApkClass(clazz);
                            return;
                        }
                    } catch (Throwable ignored) {}
                }
            }
        } catch (Throwable ignored) {}
    }

    private static synchronized void patchBaseApkClass(Class<?> baseApkClass) {
        if (sBaseApkPatched || baseApkClass == null) return;
        sBaseApkPatched = true;
        ClassLoader cl = baseApkClass.getClassLoader();

        // 1. Hook BaseApk's lambda$initOnce$1 method
        Method[] declaredMethods = baseApkClass.getDeclaredMethods();
        for (Method m : declaredMethods) {
            if (m.getName().contains("lambda$initOnce$1")) {
                m.setAccessible(true);
                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                        try {
                            if (p.args != null && p.args.length > 0 && p.args[0] != null) {
                                handleSafeBaseApkRename(p.args[0]);
                            }
                        } catch (Throwable t) {
                            XposedEntry.log("[" + TAG + "] Error in safe BaseApk lambda: " + t.getMessage());
                        }
                        // Set result to null to prevent QAuxv's buggy code from running and throwing NPE
                        p.setResult(null);
                    }
                });
                XposedEntry.log("[" + TAG + "] Successfully hooked " + m.getName() + " on BaseApk");
            }
        }

        // 2. Hook BaseApk$$ExternalSyntheticLambda0 if present
        Class<?> lambdaCls = XposedHelpers.findClassIfExists("cc.ioctl.hook.file.BaseApk$$ExternalSyntheticLambda0", cl);
        if (lambdaCls != null) {
            HookUtils.hookAllMethods(lambdaCls, "beforeHookedMethod", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    try {
                        if (p.args != null && p.args.length > 0 && p.args[0] != null) {
                            handleSafeBaseApkRename(p.args[0]);
                        }
                    } catch (Throwable t) {
                        XposedEntry.log("[" + TAG + "] Error in safe BaseApk ExternalSyntheticLambda0: " + t.getMessage());
                    }
                    p.setResult(null);
                }
            });
            XposedEntry.log("[" + TAG + "] Successfully hooked BaseApk$$ExternalSyntheticLambda0.beforeHookedMethod");
        }
    }

    private static void hookUftwrapperBD(XC_LoadPackage.LoadPackageParam lpparam) {
        final String uftBCls = "com.tencent.mobileqq.filemanager.uftwrapper.b";
        ClassLoader cl = lpparam != null && lpparam.classLoader != null ? lpparam.classLoader : HookUtils.class.getClassLoader();
        Class<?> clazz = XposedHelpers.findClassIfExists(uftBCls, cl);
        if (clazz != null) {
            hookBDMethod(clazz);
        } else if (cl != null) {
            try {
                XposedHelpers.findAndHookMethod(cl.getClass(), "loadClass", String.class, boolean.class, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                        if (uftBCls.equals(p.args[0])) {
                            Class<?> loaded = (Class<?>) p.getResult();
                            if (loaded != null) {
                                hookBDMethod(loaded);
                            }
                        }
                    }
                });
            } catch (Throwable ignored) {}
        }
    }

    private static void hookBDMethod(Class<?> clazz) {
        HookUtils.hookAllMethods(clazz, "d", new XC_MethodHook(XC_MethodHook.PRIORITY_HIGHEST) {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                // If QAuxv BaseApk hasn't been patched yet, try scanning classloaders now
                if (!sBaseApkPatched) {
                    tryScanExistingClassLoaders();
                }

                if (p.args != null && p.args.length > 1 && p.args[1] != null) {
                    safeRenameApkItem(p.args[1]);
                }
            }
        });
        XposedEntry.log("[" + TAG + "] Successfully hooked uftwrapper.b.d with PRIORITY_HIGHEST");
    }

    private static void handleSafeBaseApkRename(Object methodHookParamObj) {
        if (methodHookParamObj == null) return;
        try {
            Object[] args = (Object[]) XposedHelpers.getObjectField(methodHookParamObj, "args");
            if (args != null && args.length > 1 && args[1] != null) {
                safeRenameApkItem(args[1]);
                return;
            }

            // Fallback: check thisObject fields safely without throwing NPE
            Object thisObj = XposedHelpers.getObjectField(methodHookParamObj, "thisObject");
            if (thisObj != null) {
                Field[] fields = thisObj.getClass().getDeclaredFields();
                for (Field f : fields) {
                    f.setAccessible(true);
                    Object val = f.get(thisObj);
                    if (val != null && val.getClass().getName().contains("TroopFileTransferManager$Item")) {
                        safeRenameApkItem(val);
                        return;
                    }
                }
            }
        } catch (Throwable t) {
            XposedEntry.log("[" + TAG + "] handleSafeBaseApkRename exception: " + t.getMessage());
        }
    }

    private static void safeRenameApkItem(Object itemObj) {
        if (itemObj == null) return;
        try {
            Field fileNameField = findFieldInHierarchy(itemObj.getClass(), "FileName");
            Field localFileField = findFieldInHierarchy(itemObj.getClass(), "LocalFile");

            if (fileNameField == null) return;
            fileNameField.setAccessible(true);
            String fileName = (String) fileNameField.get(itemObj);
            if (fileName == null) return;

            // Check if APK file needs formatting (base.apk, base (1).apk, etc.)
            String lowerName = fileName.toLowerCase();
            boolean isBase = lowerName.startsWith("base") && lowerName.endsWith(".apk");
            boolean isApk1 = lowerName.endsWith(".apk.1") || lowerName.endsWith(".1");

            if (isBase || isApk1) {
                String localFile = null;
                if (localFileField != null) {
                    localFileField.setAccessible(true);
                    localFile = (String) localFileField.get(itemObj);
                }

                if (localFile != null && new File(localFile).exists()) {
                    Context ctx = getGlobalAppContext();
                    if (ctx != null) {
                        PackageManager pm = ctx.getPackageManager();
                        PackageInfo pi = pm.getPackageArchiveInfo(localFile, 0);
                        if (pi != null && pi.applicationInfo != null) {
                            pi.applicationInfo.sourceDir = localFile;
                            pi.applicationInfo.publicSourceDir = localFile;
                            CharSequence label = pm.getApplicationLabel(pi.applicationInfo);
                            String appName = (label != null && label.length() > 0) ? label.toString() : pi.packageName;
                            String newName = appName + "_" + (pi.versionName != null ? pi.versionName : "v" + pi.versionCode) + ".apk";
                            fileNameField.set(itemObj, newName);
                            XposedEntry.log("[" + TAG + "] Formatted troop APK filename: " + fileName + " -> " + newName);
                            return;
                        }
                    }
                }

                if (isApk1) {
                    String corrected = fileName.substring(0, fileName.lastIndexOf('.'));
                    if (!corrected.toLowerCase().endsWith(".apk")) {
                        corrected = corrected + ".apk";
                    }
                    fileNameField.set(itemObj, corrected);
                    XposedEntry.log("[" + TAG + "] Removed .1 suffix from APK: " + fileName + " -> " + corrected);
                }
            }
        } catch (Throwable t) {
            XposedEntry.log("[" + TAG + "] safeRenameApkItem error: " + t.getMessage());
        }
    }

    private static Field findFieldInHierarchy(Class<?> clazz, String fieldName) {
        Class<?> current = clazz;
        while (current != null && current != Object.class) {
            try {
                Field f = current.getDeclaredField(fieldName);
                if (f != null) return f;
            } catch (NoSuchFieldException ignored) {}
            current = current.getSuperclass();
        }
        return null;
    }

    private static Context getGlobalAppContext() {
        try {
            Class<?> baseAppCls = Class.forName("com.tencent.qphone.base.util.BaseApplication");
            Method getContextMethod = baseAppCls.getMethod("getContext");
            Context ctx = (Context) getContextMethod.invoke(null);
            if (ctx != null) return ctx;
        } catch (Throwable ignored) {}

        try {
            Class<?> atCls = Class.forName("android.app.ActivityThread");
            Method currentAppMethod = atCls.getMethod("currentApplication");
            Context ctx = (Context) currentAppMethod.invoke(null);
            if (ctx != null) return ctx;
        } catch (Throwable ignored) {}

        return null;
    }
}
