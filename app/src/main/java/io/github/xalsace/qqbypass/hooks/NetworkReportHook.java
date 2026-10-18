package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.detector.DexMethodData;

import java.lang.reflect.Member;
import java.util.List;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.detector.DexKitDetector;
import io.github.xalsace.qqbypass.utils.HookUtils;

/**
 * Network Report Interception Hook (Deep Non-intrusive Protocol Architecture)
 *
 * Provides a low-level, layered interception and synthetic response system:
 * - Layer 0: ChannelManager.sendMessage choke point (pre-proxy, avoids checkMethod anti-hook)
 * - Layer 1: ChannelProxyExt.sendMessage (synthesizes 5-arg onNativeReceive callback)
 * - Layer 2: MSFKernelBridge.CppProxy.sendPacket (native MSF packet choke point)
 * - Layer 3: MsfCore.sendSsoMsg (service layer, synthesizes FromServiceMsg for waiters)
 * - Layer 4: TuringFD /proc scanner neutralization
 * - Layer 5: Wlogin device report
 */
public class NetworkReportHook {

    // Strict Whitelist: never block or intercept critical protocol, session, and key-exchange commands
    private static final String[] SAFE_WHITELIST = {
        "trpc.o3.ecdh_access.",
        "trpc.o3.full_social_lock_punish.",
        "trpc.o3.mobile_security.",
        "Heartbeat.",
        "StatSvc.",
        "MessageSvc.",
        "RegPrxySvc."
    };

    // Targeted block: only pure telemetry and security report commands
    private static final String[] TELEMETRY_BLOCK_COMMANDS = {
        "trpc.o3.report.Report.SsoReport",
        "trpc.o3.report.Report.SsoEventReport",
        "trpc.ilive_cdn.report",
        "trpc.qq_security.",
        "OidbSvc.0xd79",
        "trpc.login.ecdh.report",
        "QQProtect.SecReport",
        "SecCheck.Report",
        "DevLockAuth.SecReport",
        "0ac00056535",
        "LOAD_RESULT_PATCH_LOADER_FAIL",
        "trpc.atta."
    };

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        XposedEntry.log("NetworkReportHook: Initializing targeted network telemetry and inspection hooks");
        // Layer 0: Targeted ChannelManager report interception with synthetic 1000 ACK
        if (HookConfig.ENABLE_NETWORK_INTERCEPT) {
            hookChannelManager(lpparam);
        }

        // Layer 1-3: Deep network/packet interception. Strictly guarded by ENABLE_NETWORK_INTERCEPT.
        // Disabled by default so business traffic (message sending/receiving) remains completely unimpeded.
        if (HookConfig.ENABLE_NETWORK_INTERCEPT) {
            // Layer 1: ChannelProxyExt fallback
            hookChannelProxyExt(lpparam);
            // Layer 2: MSFKernelBridge native packet choke point
            hookMSFKernelBridge(lpparam);
            // Layer 3: MsfCore SSO dispatcher
            hookMsfCore(lpparam);
        }

        // Inspection checks (TuringFD /proc scanner neutralization)
        hookTuringFD(lpparam);
        hookTuringEridanus(lpparam.classLoader != null ? lpparam.classLoader : HookConfig.getClassLoader());
    }

    /**
     * Synthesize clean success response to FEKit / ChannelManager native engine.
     * In QQ NT / 9.3.x, onNativeReceive expects 5 parameters:
     * (String cmd, byte[] data, boolean isSuccess, int resultCode, long callbackId)
     * Passing 1000 indicates SUCCESS and cleanly finishes the native async request.
     */
    public static void injectNativeReceiveSuccess(ClassLoader cl, String command, long callbackId) {
        try {
            Class<?> cmClass = XposedHelpers.findClassIfExists("com.tencent.mobileqq.channel.ChannelManager", cl);
            if (cmClass == null) return;
            Object cmInstance = XposedHelpers.callStaticMethod(cmClass, "getInstance");
            if (cmInstance == null) return;

            // 1. Try 5-arg onNativeReceive(String, byte[], boolean, int, long)
            try {
                XposedHelpers.callMethod(cmInstance, "onNativeReceive",
                    command, new byte[0], true, 1000, callbackId);
                return;
            } catch (Throwable ignored) { }

            // 2. Try 5-arg onReceive(String, byte[], boolean, int, long)
            try {
                XposedHelpers.callMethod(cmInstance, "onReceive",
                    command, new byte[0], true, 1000, callbackId);
                return;
            } catch (Throwable ignored) { }

            // 3. Fallback for older overloads
            try {
                XposedHelpers.callMethod(cmInstance, "onNativeReceive",
                    command, new byte[0], callbackId);
            } catch (Throwable ignored) { }
        } catch (Throwable t) {
            XposedEntry.log("[NetworkReport] injectNativeReceive error: " + t.getMessage());
        }
    }

    /**
     * Layer 0: Hook ChannelManager.sendMessage directly.
     * This intercepts before the proxy call and before checkMethod(this.mChannelProxy)
     * anti-hook inspection runs.
     */
    private static void hookChannelManager(XC_LoadPackage.LoadPackageParam lpparam) {
        HookUtils.hookAllMethods("com.tencent.mobileqq.channel.ChannelManager", "sendMessage",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length < 1 || !(param.args[0] instanceof String)) return;

                    String command = (String) param.args[0];
                    if (shouldBlock(command)) {
                        long callbackId = 0L;
                        if (param.args.length >= 3 && param.args[2] instanceof Number) {
                            callbackId = ((Number) param.args[2]).longValue();
                        }
                        injectNativeReceiveSuccess(lpparam.classLoader, command, callbackId);
                        param.setResult(null);
                        XposedEntry.log("Intercepted & fulfilled ChannelManager.sendMessage: "
                            + command + " (callbackId=" + callbackId + ")");
                    }
                }
            });
    }

    /**
     * Layer 1: ChannelProxyExt.sendMessage fallback.
     */
    private static void hookChannelProxyExt(XC_LoadPackage.LoadPackageParam lpparam) {
        String[] methodNames = {"sendMessage", "sendMessageInner", "send"};

        for (String methodName : methodNames) {
            HookUtils.hookAllMethods("com.tencent.mobileqq.channel.ChannelProxyExt", methodName,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args == null || param.args.length < 1 || !(param.args[0] instanceof String)) return;

                        String command = (String) param.args[0];
                        if (shouldBlock(command)) {
                            Class<?> returnType = ((java.lang.reflect.Method) param.method).getReturnType();
                            if (returnType.isPrimitive() && returnType != void.class) {
                                return;
                            }

                            long callbackId = 0L;
                            for (int i = param.args.length - 1; i >= 1; i--) {
                                if (param.args[i] instanceof Number) {
                                    callbackId = ((Number) param.args[i]).longValue();
                                    break;
                                }
                            }

                            injectNativeReceiveSuccess(lpparam.classLoader, command, callbackId);
                            param.setResult(null);
                            XposedEntry.log("Intercepted & fulfilled ChannelProxyExt: "
                                + command + " (callbackId=" + callbackId + ")");
                        }
                    }
                });
        }
    }

    /**
     * Layer 2: MSFKernelBridge$CppProxy.sendPacket.
     * Low-level choke point where packets are submitted to libMSFKernel.so native engine.
     */
    private static void hookMSFKernelBridge(XC_LoadPackage.LoadPackageParam lpparam) {
        HookUtils.hookAllMethods("com.tencent.mobileqq.msfcore.MSFKernelBridge$CppProxy", "sendPacket",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length < 1 || param.args[0] == null) return;
                    Object adapter = param.args[0];
                    try {
                        String cmd = (String) XposedHelpers.callMethod(adapter, "getCmd");
                        if (shouldBlock(cmd)) {
                            int seq = 0;
                            try {
                                seq = ((Number) XposedHelpers.callMethod(adapter, "getSeq")).intValue();
                            } catch (Throwable ignored) { }
                            param.setResult(seq);
                            XposedEntry.log("Neutralized MSFKernelBridge.sendPacket: " + cmd + " (seq=" + seq + ")");
                        }
                    } catch (Throwable ignored) { }
                }
            });
    }

    /**
     * Layer 3: MsfCore.sendSsoMsg.
     * Service layer SSO dispatcher. If the ToServiceMsg expects a response, synthesizes
     * a clean FromServiceMsg with resultCode 1000 so the caller's future/callback resolves.
     */
    private static void hookMsfCore(XC_LoadPackage.LoadPackageParam lpparam) {
        HookUtils.hookAllMethods("com.tencent.mobileqq.msf.core.MsfCore", "sendSsoMsg",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length < 1 || param.args[0] == null) return;

                    Object toServiceMsg = param.args[0];
                    Object cmdObj = XposedHelpers.callMethod(toServiceMsg, "getServiceCmd");
                    String command = cmdObj == null ? null : cmdObj.toString();

                    if (shouldBlock(command)) {
                        // Check if it's a FEKit security message with security callback id
                        try {
                            Object cbObj = XposedHelpers.callMethod(toServiceMsg, "getAttribute", "attr_key_security_callback_id");
                            if (cbObj instanceof Number) {
                                long cbId = ((Number) cbObj).longValue();
                                injectNativeReceiveSuccess(lpparam.classLoader, command, cbId);
                            }
                        } catch (Throwable ignored) { }

                        // If caller needs a response, synthesize FromServiceMsg
                        try {
                            boolean needResp = (boolean) XposedHelpers.callMethod(toServiceMsg, "isNeedResp");
                            if (needResp) {
                                String uin = (String) XposedHelpers.callMethod(toServiceMsg, "getUin");
                                int ssoSeq = (int) XposedHelpers.callMethod(toServiceMsg, "getRequestSsoSeq");
                                int appSeq = (int) XposedHelpers.callMethod(toServiceMsg, "getAppSeq");
                                int appId = (int) XposedHelpers.callMethod(toServiceMsg, "getAppId");
                                Object msfCmd = XposedHelpers.callMethod(toServiceMsg, "getMsfCommand");

                                Class<?> fromMsgClass = XposedHelpers.findClassIfExists(
                                    "com.tencent.qphone.base.remote.FromServiceMsg", lpparam.classLoader);
                                if (fromMsgClass != null) {
                                    Object fromMsg = XposedHelpers.newInstance(fromMsgClass, uin != null ? uin : "0", command);
                                    XposedHelpers.callMethod(fromMsg, "setMsgSuccess");
                                    XposedHelpers.callMethod(fromMsg, "setBusinessFailCode", 1000);
                                    XposedHelpers.callMethod(fromMsg, "setRequestSsoSeq", ssoSeq);
                                    XposedHelpers.callMethod(fromMsg, "setAppSeq", appSeq);
                                    XposedHelpers.callMethod(fromMsg, "setAppId", appId);
                                    XposedHelpers.callMethod(fromMsg, "setMsfCommand", msfCmd);
                                    XposedHelpers.callMethod(fromMsg, "putWupBuffer", new byte[0]);

                                    try {
                                        XposedHelpers.callMethod(param.thisObject, "addRespToQuque", toServiceMsg, fromMsg);
                                    } catch (Throwable ignored) { }
                                }
                            }
                        } catch (Throwable ignored) { }

                        Class<?> returnType = ((java.lang.reflect.Method) param.method).getReturnType();
                        if (returnType == int.class) {
                            int seq = 0;
                            try {
                                seq = (int) XposedHelpers.callMethod(toServiceMsg, "getRequestSsoSeq");
                            } catch (Throwable ignored) { }
                            param.setResult(seq);
                            XposedEntry.log("Neutralized MsfCore: " + command);
                        } else if (returnType == long.class) {
                            long seq = 0L;
                            try {
                                seq = ((Number) XposedHelpers.callMethod(toServiceMsg, "getRequestSsoSeq")).longValue();
                            } catch (Throwable ignored) { }
                            param.setResult(seq);
                            XposedEntry.log("Neutralized MsfCore: " + command);
                        } else if (returnType == void.class) {
                            param.setResult(null);
                            XposedEntry.log("Neutralized MsfCore: " + command);
                        }
                    }
                }
            });
    }

    /**
     * Block TuringFD's process-enumeration readers (/proc scanners).
     */
    private static void hookTuringFD(XC_LoadPackage.LoadPackageParam lpparam) {
        new Thread(() -> {
            try {
                if (!DexKitDetector.awaitReady(30000)) {
                    XposedEntry.log("[TuringFD] DexKit not available, skip proc-reader hook");
                    return;
                }

                List<DexMethodData> procReaders = DexKitDetector.findTuringFdProcReaders();
                XposedEntry.log("[TuringFD] found " + procReaders.size() + " proc readers by fingerprint");

                for (DexMethodData md : procReaders) {
                    try {
                        Member method = md.getMethodInstance(lpparam.classLoader);
                        if (!(method instanceof java.lang.reflect.Method)) continue;
                        Class<?> ret = ((java.lang.reflect.Method) method).getReturnType();
                        if (ret != String.class) continue;

                        XposedBridge.hookMethod(method, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                                param.setResult("");
                            }
                        });
                        XposedEntry.log("[TuringFD] neutralized proc reader: "
                            + md.getClassName() + "." + md.getMethodName());
                    } catch (Throwable t) {
                        XposedEntry.log("[TuringFD] failed to hook proc reader: " + t.getMessage());
                    }
                }
            } catch (Throwable t) {
                XposedEntry.log("[TuringFD] proc-reader lookup failed: " + t.getMessage());
            }
        }).start();
    }

    private static boolean isSensitiveTuringPath(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase();
        return lower.contains("/system/bin/su") || lower.contains("/system/xbin/su") ||
               lower.contains("/sbin/su") || lower.contains("/data/local/su") ||
               lower.contains("/data/adb") || lower.contains("magisk") ||
               lower.contains("kernelsu") || lower.contains("apatch") ||
               lower.contains("xposed") || lower.contains("lsposed") ||
               lower.contains("qauxv") || lower.contains("busybox") ||
               lower.contains("mountify") || lower.contains("tricky_store") ||
               lower.contains("zygisksu") || lower.contains("metamodule") ||
               lower.contains("frida") || lower.contains("bin.mt") || lower.contains("daemonsu") ||
               lower.contains("qa_mmkv") || lower.contains("tmp_qa_") ||
               lower.contains("qa_dyn_lib") || lower.contains("qa_misc") ||
               lower.contains("ono_mmkv") || lower.contains("ono_hcb_") || lower.contains("moe.ono") ||
               lower.contains("sesearchcache");
    }

    private static void hookTuringEridanus(ClassLoader cl) {
        if (cl == null) return;
        String[] eridanusClasses = {
            "com.tencent.turingfd.sdk.xq.Eridanus",
            "com.tencent.tfd.sdk.wxa.Eridanus"
        };
        for (String clsName : eridanusClasses) {
            Class<?> clazz = XposedHelpers.findClassIfExists(clsName, cl);
            if (clazz != null) {
                XC_MethodHook byteReaderHook = new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args == null || param.args.length < 1 || !(param.args[0] instanceof String)) {
                            return;
                        }
                        String path = (String) param.args[0];
                        if (path == null) return;

                        if (isSensitiveTuringPath(path)) {
                            XposedEntry.log("[TuringEridanus] Blocked sensitive file read: " + path);
                            param.setResult(null);
                            return;
                        }

                        byte[] fakeBytes = null;
                        if (path.contains("/status") && path.startsWith("/proc/")) {
                            XposedEntry.log("[TuringEridanus] Sanitized status read: " + path);
                            String fakeStatus = "Name:\tcom.tencent.mobileqq\nState:\tS (sleeping)\nTgid:\t" 
                                + android.os.Process.myPid() + "\nPid:\t" + android.os.Process.myPid() 
                                + "\nPPid:\t1\nTracerPid:\t0\nUid:\t10361\t10361\t10361\t10361\nGid:\t10361\t10361\t10361\t10361\n";
                            fakeBytes = fakeStatus.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        } else if (path.contains("/cmdline") && path.startsWith("/proc/")) {
                            fakeBytes = "com.tencent.mobileqq\0".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        } else if (path.contains("selinux/enforce")) {
                            fakeBytes = "1".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        } else if (path.contains("net/unix")) {
                            fakeBytes = "".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        }

                        if (fakeBytes != null) {
                            int maxLen = -1;
                            if (param.args.length >= 2 && param.args[1] instanceof Number) {
                                maxLen = ((Number) param.args[1]).intValue();
                            }
                            if (maxLen > 0 && fakeBytes.length > maxLen) {
                                fakeBytes = java.util.Arrays.copyOf(fakeBytes, maxLen);
                            }
                            if (param.method instanceof java.lang.reflect.Method) {
                                Class<?> ret = ((java.lang.reflect.Method) param.method).getReturnType();
                                if (ret == byte[].class) {
                                    param.setResult(fakeBytes);
                                } else if (ret == String.class) {
                                    param.setResult(new String(fakeBytes, java.nio.charset.StandardCharsets.UTF_8));
                                } else if (ret == void.class) {
                                    param.setResult(null);
                                } else {
                                    param.setResult(fakeBytes);
                                }
                            } else {
                                param.setResult(fakeBytes);
                            }
                            return;
                        }
                    }
                };
                HookUtils.hookAllMethods(clazz, "a", byteReaderHook);
                HookUtils.hookAllMethods(clazz, "b", byteReaderHook);
                XposedEntry.log("[TuringFD] Hooked Eridanus byte readers on " + clsName);
            }
        }
    }

    private static void hookWlogin(XC_LoadPackage.LoadPackageParam lpparam) {
        HookUtils.hookAllMethods("oicq.wlogin_sdk.request.w", "h",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    XposedEntry.log("Intercepted Wlogin device fingerprint");
                }
            });
    }

    public static boolean shouldBlock(String command) {
        if (command == null) return false;

        // Whitelist check: strictly pass-through critical protocol and key-exchange commands
        for (String whiteCmd : SAFE_WHITELIST) {
            if (command.contains(whiteCmd)) {
                return false;
            }
        }

        // Targeted block: only pure telemetry and risk detection reports
        for (String blockCmd : TELEMETRY_BLOCK_COMMANDS) {
            if (command.contains(blockCmd)) {
                return true;
            }
        }
        return false;
    }
}
