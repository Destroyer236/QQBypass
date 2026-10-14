package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.utils.HookUtils;

/**
 * Detection & Risk Mitigation Patch (Enhanced for QQ 9.3.50 - 9.3.70)
 *
 * Targets real risk-control and forced kick mechanisms:
 * - NTKickProcessor: Suppress account de-registration and kick popups at entry point 'a'
 * - TuringRiskService: Returns safe dynamic proxy (never null to avoid NPE in turingfd callers)
 * - TuringIDService: Returns safe dynamic proxy (never null to avoid NPE on getOpenIdTicket)
 * - QQ 9.3.70 Turing Bridge (com.tencent.mobileqq.turingfd.i): Intercepts deviceToken and tickets
 * - ChannelManager / ChannelReport: Neutralize environment reflection and telemetry
 */
public class QQ950PatchHook {

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_QQ950_PATCH) return;

        XposedEntry.log("Initializing QQ 9.3.70 detection & kick patch");

        // Tier 1: void-return, crash-safe backstops
        hookKickBackstop();
        hookMsfTelemetry();
        hookTuringWrapper();
        hookChannelReport();
        hookTuringFDBridge();
        hookSignatureAndIntegrity();

        // Tier 2: object-return risk-detection blocks (Dynamic Proxy safe, zero NPE risk)
        hookTuringRiskDetect();
        hookTuringDID();
    }

    // ==================== Tier 1: void-return, crash-safe ====================

    /**
     * Enhanced Kick Prevention:
     * In QQ 9.3.70, NTKickProcessor.a(AppRuntime, KickedInfo) is the public entry point.
     * Before calling the internal worker 'b', method 'a' calls MsfSdkUtils.updateSimpleAccount(uin, false)
     * and reportClearLoginData, which invalidates the login state!
     * Hooking method 'a' directly suppresses the entire kick sequence.
     */
    private static void hookKickBackstop() {
        final String cls = "com.tencent.mobileqq.kick.NTKickProcessor";
        Class<?> clazz = XposedHelpers.findClassIfExists(cls, HookConfig.getClassLoader());
        if (clazz == null) {
            XposedEntry.log("[KickPatch] NTKickProcessor not present, skip kick hook");
            return;
        }

        // Hook public entry a(AppRuntime, KickedInfo)
        HookUtils.hookAllMethods(cls, "a", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length >= 2 && p.args[1] != null) {
                    p.setResult(null); // void - crash-safe! Prevents kick, token invalidation, and notification
                    XposedEntry.log("[KickPatch] Suppressed NTKickProcessor.a kick event");
                }
            }
        });

        // Hook internal worker 'b' by signature (void + LogoutReason) as second-line backstop
        int hooked = 0;
        for (Method m : clazz.getDeclaredMethods()) {
            if (m.getReturnType() != void.class) continue;
            boolean hasLogoutReason = false;
            for (Class<?> pt : m.getParameterTypes()) {
                if (pt.getName().contains("LogoutReason")) {
                    hasLogoutReason = true;
                    break;
                }
            }
            if (!hasLogoutReason) continue;
            XposedBridge.hookMethod(m, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(null);
                    XposedEntry.log("[KickPatch] Suppressed NTKickProcessor logout worker (b)");
                }
            });
            hooked++;
        }
        XposedEntry.log("[KickPatch] NTKickProcessor hooks installed (entry + " + hooked + " workers)");
    }

    /**
     * MSF telemetry: all void, pure reporting.
     */
    private static void hookMsfTelemetry() {
        final String cls = "com.tencent.mobileqq.msf.core.MsfCore";
        if (!HookUtils.classExists(cls)) return;
        String[] reportMethods = {
            "doReportOnInitComplete", "reportMsfCoreInit",
            "tryReportJobAlive", "tryReportLoadCfgTempFile",
            "tryReportMSFAlive", "tryReportSoLoadUseTxlib"
        };
        for (String m : reportMethods) {
            HookUtils.hookAllMethods(cls, m, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(null);
                }
            });
        }
    }

    /**
     * Turing cache writers: TuringWrapper.b()/c() : void.
     */
    private static void hookTuringWrapper() {
        final String cls = "com.tencent.mobileqq.dt.model.TuringWrapper";
        Class<?> clazz = XposedHelpers.findClassIfExists(cls, HookConfig.getClassLoader());
        if (clazz == null) return;

        for (Method m : clazz.getDeclaredMethods()) {
            if (!Modifier.isStatic(m.getModifiers())) continue;
            if (m.getReturnType() != void.class) continue;
            if (m.getParameterTypes().length != 0) continue;
            XposedBridge.hookMethod(m, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(null);
                }
            });
            XposedEntry.log("[TuringPatch] Hooked TuringWrapper switch: " + m.getName());
        }
    }

    /**
     * ChannelManager checkMethod & ChannelReport telemetry.
     */
    private static void hookChannelReport() {
        // Suppress ChannelManager.checkMethod anti-hook reflection
        HookUtils.hookAllMethods("com.tencent.mobileqq.channel.ChannelManager", "checkMethod",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(null);
                    XposedEntry.log("[ChannelPatch] Neutralized ChannelManager.checkMethod");
                }
            });

        // Suppress ChannelManagerImpl telemetry reports
        HookUtils.hookAllMethods("com.tencent.mobileqq.channel.ChannelManagerImpl", "onChannelReadyReport",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(null);
                }
            });

        // Suppress ChannelReport methods
        final String crCls = "com.tencent.mobileqq.channel.ChannelReport";
        if (HookUtils.classExists(crCls)) {
            String[] reportMethods = {"reportInitTime", "reportTZ", "reportLoadFixedSo"};
            for (String rm : reportMethods) {
                HookUtils.hookAllMethods(crCls, rm, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                        p.setResult(null);
                    }
                });
            }
        }
    }

    /**
     * QQ 9.3.70 specific: com.tencent.mobileqq.turingfd.i singleton.
     * Method f(boolean) generates deviceToken; method d(boolean) generates OpenIdTicket.
     */
    private static void hookTuringFDBridge() {
        final String cls = "com.tencent.mobileqq.turingfd.i";
        if (!HookUtils.classExists(cls)) return;

        // Neutralize deviceToken query
        HookUtils.hookAllMethods(cls, "f", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult("");
                XposedEntry.log("[TuringPatch] Neutralized com.tencent.mobileqq.turingfd.i.f");
            }
        });

        // Neutralize openIdTicket query
        HookUtils.hookAllMethods(cls, "d", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult("");
                XposedEntry.log("[TuringPatch] Neutralized com.tencent.mobileqq.turingfd.i.d");
            }
        });
    }

    /**
     * QQ 9.3.70 APK signature and integrity checks.
     * Hooks:
     * - ApkSignatureSchemeV2Verifier.g(String): returns true (verifies V2 signature)
     * - ApkExternalInfoTool (com.tencent.securitysdk.utils.a.f(File)): getSecurityCodeV1
     */
    private static void hookSignatureAndIntegrity() {
        // ApkSignatureSchemeV2Verifier.g(String apkPath)
        final String v2Cls = "com.tencent.securitysdk.utils.ApkSignatureSchemeV2Verifier";
        if (HookUtils.classExists(v2Cls)) {
            HookUtils.hookAllMethods(v2Cls, "g", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(true);
                    XposedEntry.log("[SignaturePatch] Neutralized ApkSignatureSchemeV2Verifier.g");
                }
            });
        }

        // ApkExternalInfoTool: getSecurityCodeV1(File)
        final String extCls = "com.tencent.securitysdk.utils.a";
        if (HookUtils.classExists(extCls)) {
            HookUtils.hookAllMethods(extCls, "f", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.getResult() == null) {
                        p.setResult("qq_security_verified");
                        XposedEntry.log("[SignaturePatch] Fallback ApkExternalInfoTool security code");
                    }
                }
            });
        }
    }

    // ============ Tier 2: object-return risk detection (Safe Dynamic Proxies) ============

    /**
     * TuringRiskService.reqRiskDetectV2(...) : RiskDetectResp.
     * Returning null causes NullPointerException in callers (e.g. turingfd.i.f calls .getErrorCode()).
     * Here we return a Dynamic Proxy implementing RiskDetectResp that returns errorCode=0L and empty token.
     */
    private static void hookTuringRiskDetect() {
        if (!HookConfig.ENABLE_QQ950_RISK_BLOCK) return;
        String[] classes = {
            "com.tencent.tfd.sdk.wxa.TuringRiskService",
            "com.tencent.turingfd.sdk.xq.TuringRiskService"
        };
        for (final String cls : classes) {
            if (!HookUtils.classExists(cls)) continue;
            HookUtils.hookAllMethods(cls, "reqRiskDetectV2", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    Object proxy = createSafeRiskDetectRespProxy();
                    if (proxy != null) {
                        p.setResult(proxy);
                    } else {
                        p.setResult(null);
                    }
                    XposedEntry.log("[TuringPatch] Fulfilled reqRiskDetectV2 with safe proxy @ " + cls);
                }
            });
        }
    }

    private static Object createSafeRiskDetectRespProxy() {
        ClassLoader cl = HookConfig.getClassLoader();
        Class<?> iface = XposedHelpers.findClassIfExists("com.tencent.turingfd.sdk.xq.RiskDetectResp", cl);
        if (iface == null) {
            iface = XposedHelpers.findClassIfExists("com.tencent.tfd.sdk.wxa.RiskDetectResp", cl);
        }
        if (iface == null) return null;

        try {
            return Proxy.newProxyInstance(cl, new Class<?>[]{iface}, new InvocationHandler() {
                @Override
                public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                    String name = method.getName();
                    if ("getErrorCode".equals(name)) return 0L;
                    if ("getDeviceToken".equals(name)) return "";
                    if ("isDowngrade".equals(name)) return false;
                    if ("getStagePackTimeMillis".equals(name) || "getStageReqTimeMillis".equals(name)) return 0L;

                    Class<?> ret = method.getReturnType();
                    if (ret == boolean.class) return false;
                    if (ret == int.class) return 0;
                    if (ret == long.class) return 0L;
                    if (ret == String.class) return "";
                    return null;
                }
            });
        } catch (Throwable t) {
            return null;
        }
    }

    /**
     * TuringIDService.getTuringDID / getTuringDIDCached : ITuringDID.
     * Returning null causes NullPointerException in callers (e.g. turingfd.i.d calls .getOpenIdTicket()).
     * Here we return a Dynamic Proxy implementing ITuringDID.
     */
    private static void hookTuringDID() {
        if (!HookConfig.ENABLE_QQ950_RISK_BLOCK) return;
        String[] classes = {
            "com.tencent.tfd.sdk.wxa.TuringIDService",
            "com.tencent.turingfd.sdk.xq.TuringIDService"
        };
        for (final String cls : classes) {
            if (!HookUtils.classExists(cls)) continue;
            for (String m : new String[]{"getTuringDID", "getTuringDIDCached"}) {
                HookUtils.hookAllMethods(cls, m, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                        Object proxy = createSafeTuringDIDProxy();
                        if (proxy != null) {
                            p.setResult(proxy);
                        } else {
                            p.setResult(null);
                        }
                    }
                });
            }
            HookUtils.hookAllMethods(cls, "getTuringDIDAsync", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(null); // void return
                }
            });
        }
    }

    private static Object createSafeTuringDIDProxy() {
        ClassLoader cl = HookConfig.getClassLoader();
        Class<?> iface = XposedHelpers.findClassIfExists("com.tencent.turingfd.sdk.xq.ITuringDID", cl);
        if (iface == null) {
            iface = XposedHelpers.findClassIfExists("com.tencent.tfd.sdk.wxa.ITuringDID", cl);
        }
        if (iface == null) return null;

        try {
            return Proxy.newProxyInstance(cl, new Class<?>[]{iface}, new InvocationHandler() {
                @Override
                public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                    String name = method.getName();
                    if ("getErrorCode".equals(name)) return 0;
                    if ("getOpenIdTicket".equals(name) || "getAIDCode".equals(name)
                        || "getAIDTicket".equals(name) || "getTAIDTicket".equals(name)) return "";
                    if ("getExpiredTimestamp".equals(name)) return System.currentTimeMillis() + 86400000L;

                    Class<?> ret = method.getReturnType();
                    if (ret == boolean.class) return false;
                    if (ret == int.class) return 0;
                    if (ret == long.class) return 0L;
                    if (ret == String.class) return "";
                    return null;
                }
            });
        } catch (Throwable t) {
            return null;
        }
    }
}
