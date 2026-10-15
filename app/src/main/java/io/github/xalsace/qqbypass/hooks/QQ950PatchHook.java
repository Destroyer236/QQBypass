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
        hookTroopSecurityTipsBannerCrash(lpparam);

        // Tier 2: object-return risk-detection blocks (Dynamic Proxy safe, zero NPE risk)
        hookTuringRiskDetect();
        hookTuringDID();

        // Tier 3: Face ID & Multi-Factor Authentication (HuiYan SDK & TuringFaceDefender)
        hookFaceRecognitionAndMFA(lpparam);

        // Tier 4: trpc.o3.* telemetry & security detection targeted sanitization
        hookO3SecurityAndTelemetry(lpparam);
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
            String[] reportMethods = {
                "reportInitTime", "reportTZ", "reportLoadFixedSo",
                "reportGoogleAttestation", "reportStep"
            };
            for (String rm : reportMethods) {
                HookUtils.hookAllMethods(crCls, rm, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                        p.setResult(null);
                    }
                });
            }

            // Suppress eventReport (0df00071646 SsoEventReport)
            HookUtils.hookAllMethods(crCls, "eventReport", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(null);
                    XposedEntry.log("[ChannelPatch] Neutralized ChannelReport.eventReport");
                }
            });

            // Neutralize commonReport and batchCommonReport for sensitive telemetry attaIds
            XC_MethodHook attaFilterHook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args != null && p.args.length >= 1 && p.args[0] instanceof String) {
                        String attaId = (String) p.args[0];
                        if ("0df00071646".equals(attaId) || "00e00075618".equals(attaId) ||
                            "02f00075617".equals(attaId) || "0b500076578".equals(attaId)) {
                            p.setResult(null);
                            XposedEntry.log("[ChannelPatch] Suppressed ChannelReport for attaId: " + attaId);
                        }
                    }
                }
            };
            HookUtils.hookAllMethods(crCls, "commonReport", attaFilterHook);
            HookUtils.hookAllMethods(crCls, "batchCommonReport", attaFilterHook);
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

    /**
     * Suppress TroopSecurityTipsBanner crash caused by uninitialized lateinit property aioContext.
     * When top banner notifications arrive while AIO is not active or closing,
     * accessing aioContext or curTroopUin throws kotlin.UninitializedPropertyAccessException.
     */
    private static void hookTroopSecurityTipsBannerCrash(XC_LoadPackage.LoadPackageParam lpparam) {
        ClassLoader cl = lpparam != null && lpparam.classLoader != null ? lpparam.classLoader : HookConfig.getClassLoader();
        if (cl == null) return;

        // 1. Guard TroopSecurityTipsBanner methods
        final String bannerCls = "com.tencent.mobileqq.troop.tipsbar.TroopSecurityTipsBanner";
        Class<?> bannerClass = XposedHelpers.findClassIfExists(bannerCls, cl);
        if (bannerClass != null) {
            // Hook method 'm' directly
            HookUtils.hookAllMethods(bannerClass, "m", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    try {
                        Object aioContext = XposedHelpers.getObjectField(param.thisObject, "e");
                        Object curTroopUin = XposedHelpers.getObjectField(param.thisObject, "d");
                        if (aioContext == null || curTroopUin == null) {
                            param.setResult(null);
                            XposedEntry.log("[CrashFix] Preempted TroopSecurityTipsBanner.m (uninitialized aioContext/curTroopUin)");
                        }
                    } catch (Throwable t) {
                        param.setResult(null);
                    }
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.getThrowable() != null) {
                        XposedEntry.log("[CrashFix] Caught exception in TroopSecurityTipsBanner.m: " + param.getThrowable().getMessage());
                        param.setResult(null);
                    }
                }
            });

            // Guard all other methods in TroopSecurityTipsBanner against UninitializedPropertyAccessException
            for (Method method : bannerClass.getDeclaredMethods()) {
                if ("m".equals(method.getName())) continue;
                XposedBridge.hookMethod(method, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Throwable t = param.getThrowable();
                        if (t != null && (t.getClass().getName().contains("UninitializedPropertyAccessException")
                                || (t.getMessage() != null && (t.getMessage().contains("aioContext") || t.getMessage().contains("curTroopUin"))))) {
                            XposedEntry.log("[CrashFix] Suppressed " + t.getClass().getSimpleName() + " in " + param.method.getName());
                            Class<?> ret = ((Method) param.method).getReturnType();
                            if (ret == void.class) {
                                param.setResult(null);
                            } else if (ret == boolean.class) {
                                param.setResult(false);
                            } else if (ret == int.class) {
                                param.setResult(0);
                            } else if (ret == long.class) {
                                param.setResult(0L);
                            } else {
                                param.setResult(null);
                            }
                        }
                    }
                });
            }
            XposedEntry.log("[CrashFix] Hooked TroopSecurityTipsBanner for aioContext crash protection");
        }

        // 2. Guard the calling notification listener lambda
        final String lambdaCls = "com.tencent.mobileqq.aio.notification.impl.AIONotificationManager$groupListener$1$onGroupTopBannerDataNotify$4$uiModel$1";
        Class<?> lambdaClass = XposedHelpers.findClassIfExists(lambdaCls, cl);
        if (lambdaClass != null) {
            HookUtils.hookAllMethods(lambdaClass, "invoke", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.getThrowable() != null) {
                        XposedEntry.log("[CrashFix] Suppressed exception in onGroupTopBannerDataNotify lambda: " + param.getThrowable().getMessage());
                        param.setResult(null);
                    }
                }
            });
            XposedEntry.log("[CrashFix] Hooked AIONotificationManager banner lambda for exception isolation");
        }
    }

    /**
     * QQ 人脸识别核身与多因子认证（HuiYan SDK & TuringFaceDefender）专项防护：
     *
     * 1. TuringFaceDefender (com.tencent.turingcam.TuringFaceDefender):
     *    - init(TuringFaceBuilder): 确保初始化返回 0（成功）；
     *    - signData(String): 挂钩返回值，确保 SignResult.code == 0（成功验签，无环境异常码）；
     *
     * 2. TuringSdkImp 回调分发 (com.tencent.could.huiyansdk.turingmodule.TuringSdkImp$a):
     *    - onException(Throwable): 静默抑制异常，防止触发 GetTuringTokenError 错误埋点与环境污染；
     *
     * 3. Turing 结果消费与状态机 (com.tencent.could.huiyansdk.turing.d):
     *    - a(long j, byte[] bArr): 若底层由于环境波动传出非 0 状态码，前置修正 j = 0L，并确保 bArr 有效，使核身状态机无缝跃迁至 START_GET_LIVE_TYPE；
     *
     * 4. Turing 结果缓存实体 (com.tencent.could.huiyansdk.entity.TuringResultCacheEntity):
     *    - setTuringEnvErrorStr(String): 过滤错误特征字符串，防止上报环境异常至人脸核验服务端。
     */
    private static void hookFaceRecognitionAndMFA(XC_LoadPackage.LoadPackageParam lpparam) {
        ClassLoader cl = lpparam != null && lpparam.classLoader != null ? lpparam.classLoader : HookConfig.getClassLoader();
        if (cl == null) return;

        // 1. TuringFaceDefender: init & signData
        final String tfdCls = "com.tencent.turingcam.TuringFaceDefender";
        Class<?> tfdClass = XposedHelpers.findClassIfExists(tfdCls, cl);
        if (tfdClass != null) {
            HookUtils.hookAllMethods(tfdClass, "init", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(0);
                    XposedEntry.log("[FacePatch] Preempted TuringFaceDefender.init -> 0");
                }
            });

            HookUtils.hookAllMethods(tfdClass, "signData", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object result = param.getResult();
                    if (result != null) {
                        try {
                            long code = XposedHelpers.getLongField(result, "code");
                            if (code != 0) {
                                XposedHelpers.setLongField(result, "code", 0L);
                                XposedEntry.log("[FacePatch] Sanitized TuringFaceDefender.signData code: " + code + " -> 0");
                            }
                        } catch (Throwable t) {
                            try {
                                int codeInt = XposedHelpers.getIntField(result, "code");
                                if (codeInt != 0) {
                                    XposedHelpers.setIntField(result, "code", 0);
                                    XposedEntry.log("[FacePatch] Sanitized TuringFaceDefender.signData code: " + codeInt + " -> 0");
                                }
                            } catch (Throwable ignored) {}
                        }
                    }
                }
            });
            XposedEntry.log("[FacePatch] Hooked TuringFaceDefender for face recognition safety");
        }

        // 2. TuringSdkImp$a: onException
        final String callbackCls = "com.tencent.could.huiyansdk.turingmodule.TuringSdkImp$a";
        Class<?> cbClass = XposedHelpers.findClassIfExists(callbackCls, cl);
        if (cbClass != null) {
            HookUtils.hookAllMethods(cbClass, "onException", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(null); // void, suppress exception
                    XposedEntry.log("[FacePatch] Suppressed TuringSdkImp onException callback");
                }
            });
        }

        // 3. Turing helper: com.tencent.could.huiyansdk.turing.d.a(long, byte[])
        final String dCls = "com.tencent.could.huiyansdk.turing.d";
        Class<?> dClass = XposedHelpers.findClassIfExists(dCls, cl);
        if (dClass != null) {
            HookUtils.hookAllMethods(dClass, "a", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length >= 2) {
                        if (param.args[0] instanceof Number) {
                            long code = ((Number) param.args[0]).longValue();
                            if (code != 0) {
                                param.args[0] = 0L;
                                XposedEntry.log("[FacePatch] Sanitized HuiYan Turing retCode: " + code + " -> 0");
                            }
                        }
                        if (param.args[1] == null) {
                            param.args[1] = new byte[32];
                            XposedEntry.log("[FacePatch] Provided fallback non-null Turing face token buffer");
                        }
                    }
                }
            });
            XposedEntry.log("[FacePatch] Hooked HuiYan turing.d result consumer");
        }

        // 4. TuringResultCacheEntity: setTuringEnvErrorStr
        final String cacheCls = "com.tencent.could.huiyansdk.entity.TuringResultCacheEntity";
        Class<?> cacheClass = XposedHelpers.findClassIfExists(cacheCls, cl);
        if (cacheClass != null) {
            HookUtils.hookAllMethods(cacheClass, "setTuringEnvErrorStr", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.args[0] = ""; // Neutralize environment error string
                }
            });
            XposedEntry.log("[FacePatch] Hooked TuringResultCacheEntity.setTuringEnvErrorStr");
        }
    }

    // ============ Tier 4: trpc.o3.* telemetry & security detection targeted sanitization ============

    /**
     * Tier 4: Targeted Sanitization for trpc.o3.* Telemetry & QQProtect QSec Detection.
     *
     * Reverse engineering findings:
     * 1. trpc.o3.ecdh_access.* is MSF's core ECDH key-exchange protocol (MUST NOT BE BLOCKED).
     * 2. trpc.o3.full_social_lock_punish.* is the account verification/unlock channel (MUST NOT BE BLOCKED).
     * 3. trpc.o3.report.Report.SsoReport & SsoEventReport carry telemetry:
     *    - "0df00071646" (sign_report): reports signature mismatch, hook detection, and runtime tampering.
     *    - "00e00075618" (env_detect): reports fake location, mock provider, time zone anomalies.
     *    - "02f00075617" (google_attestation): reports Google Play integrity/attestation checks.
     *    - "0b500076578" (sdk_init): reports FEKit load times and sleepCheckResult.
     * 4. qqprotect.qsec.a.e gathers 33 system parameters into a JSON dictionary (adb, accessibility, sensors).
     * 5. MainProcess2Fe.b checks display refresh rate <= 30fps, displayId > 0, scrcpy, minicap and sends display_report.
     * 6. QSecChannelImpl sends feEnvReport ("face_detect"), feCameraActionReport ("camera_detect"), and collectReport.
     */
    private static void hookO3SecurityAndTelemetry(XC_LoadPackage.LoadPackageParam lpparam) {
        // 1. Hook com.tencent.qqprotect.report.O3Report
        final String o3ReportCls = "com.tencent.qqprotect.report.O3Report";
        if (HookUtils.classExists(o3ReportCls)) {
            // Neutralize O3Report.d(String, String, String) - sign_report (attaId = "0df00071646")
            HookUtils.hookAllMethods(o3ReportCls, "d", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(null);
                    XposedEntry.log("[O3Patch] Neutralized O3Report.d (sign_report / integrity telemetry)");
                }
            });

            // Neutralize O3Report.b(String, List, String) - env_detect (attaId = "00e00075618")
            HookUtils.hookAllMethods(o3ReportCls, "b", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(null);
                    XposedEntry.log("[O3Patch] Neutralized O3Report.b (env_detect telemetry)");
                }
            });

            // Neutralize O3Report.c(String, List) - fakeLocationReport / nearLocationReport
            HookUtils.hookAllMethods(o3ReportCls, "c", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(null);
                    XposedEntry.log("[O3Patch] Neutralized O3Report.c (location anomaly report)");
                }
            });

            // Sanitize / Fulfill O3Report.a(String, ArrayList, ProtoUtils.TroopProtocolObserver)
            HookUtils.hookAllMethods(o3ReportCls, "a", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args != null && p.args.length >= 3 && p.args[2] != null) {
                        try {
                            XposedHelpers.callMethod(p.args[2], "onResult", 0, true, new byte[0]);
                        } catch (Throwable ignored) {
                            try {
                                XposedHelpers.callMethod(p.args[2], "onResult", 0, new byte[0]);
                            } catch (Throwable ignored2) { }
                        }
                    }
                    p.setResult(null);
                    String attaId = (p.args != null && p.args.length > 0 && p.args[0] != null) ? p.args[0].toString() : "unknown";
                    XposedEntry.log("[O3Patch] Intercepted and fulfilled O3Report.a (attaId=" + attaId + ")");
                }
            });
        }

        // 2. Hook O3ReportApiImpl & O3NotifySecApiImpl
        HookUtils.hookAllMethods("com.tencent.qqprotect.qsec.api.impl.O3ReportApiImpl", "report", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
            }
        });
        HookUtils.hookAllMethods("com.tencent.qqprotect.qsec.api.impl.O3ReportApiImpl", "reportCommon", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
            }
        });
        HookUtils.hookAllMethods("com.tencent.qqprotect.qsec.api.impl.O3NotifySecApiImpl", "sendMessage", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
            }
        });

        // 3. Hook com.tencent.qqprotect.qsec.a (Device profile collector)
        final String qsecACls = "com.tencent.qqprotect.qsec.a";
        if (HookUtils.classExists(qsecACls)) {
            // Sanitize collectInfo JSON: a.e(Context, ArrayList, ArrayList, ArrayList)
            HookUtils.hookAllMethods(qsecACls, "e", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.getResult() instanceof String) {
                        String raw = (String) p.getResult();
                        try {
                            org.json.JSONObject json = new org.json.JSONObject(raw);
                            json.put("10", "none"); // sys.usb.config: hide adb
                            json.put("30", 0);      // accessibility enabled: false
                            json.put("31", "[]");   // installed accessibility services: empty
                            json.put("32", "[]");   // enabled accessibility services: empty
                            json.put("14", "CK_N"); // clean indicator
                            p.setResult(json.toString());
                            XposedEntry.log("[O3Patch] Sanitized qqprotect.qsec.a.e device profile JSON");
                        } catch (Throwable ignored) { }
                    }
                }
            });

            // a.n(): returns sys.usb.config
            HookUtils.hookAllMethods(qsecACls, "n", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult("none");
                }
            });

            // a.f(Context): enabled accessibility services
            HookUtils.hookAllMethods(qsecACls, "f", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult("[]");
                }
            });

            // a.g(Context): installed accessibility services
            HookUtils.hookAllMethods(qsecACls, "g", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult("[]");
                }
            });
        }

        // 4. Hook com.tencent.mobileqq.dt.app.MainProcess2Fe (Remote control / scrcpy / minicap / face_detect)
        final String mp2feCls = "com.tencent.mobileqq.dt.app.MainProcess2Fe";
        if (HookUtils.classExists(mp2feCls)) {
            // MainProcess2Fe.b(AppInterface, dt.api.a): display_report detecting scrcpy/minicap/fps<=30
            HookUtils.hookAllMethods(mp2feCls, "b", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args != null && p.args.length >= 2 && p.args[1] != null) {
                        try {
                            XposedHelpers.callMethod(p.args[1], "onResult", 0, new byte[0]);
                        } catch (Throwable ignored) { }
                    }
                    p.setResult(null);
                    XposedEntry.log("[O3Patch] Neutralized MainProcess2Fe.b display_report");
                }
            });

            // MainProcess2Fe.k(AppInterface, String cmd, JSONObject data, dt.api.a callback)
            HookUtils.hookAllMethods(mp2feCls, "k", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args != null && p.args.length >= 2 && p.args[1] instanceof String) {
                        String cmd = (String) p.args[1];
                        if ("face_detect".equals(cmd) || "camera_detect".equals(cmd) || "display_report".equals(cmd)) {
                            if (p.args.length >= 4 && p.args[3] != null) {
                                try {
                                    XposedHelpers.callMethod(p.args[3], "onResult", 0, new byte[0]);
                                } catch (Throwable ignored) { }
                            }
                            if (p.args.length >= 3 && p.args[2] instanceof org.json.JSONObject) {
                                org.json.JSONObject data = (org.json.JSONObject) p.args[2];
                                if (data.has("content")) {
                                    String c = data.optString("content", "");
                                    if (c.contains("risk") || c.contains("hook") || c.contains("root") || c.contains("fail")) {
                                        data.put("content", "{}");
                                    }
                                }
                            }
                            XposedEntry.log("[O3Patch] Sanitized MainProcess2Fe.k (" + cmd + ")");
                        }
                    }
                }
            });
        }

        // 5. Hook com.tencent.mobileqq.dt.api.impl.QSecChannelImpl
        final String qsecChannelCls = "com.tencent.mobileqq.dt.api.impl.QSecChannelImpl";
        if (HookUtils.classExists(qsecChannelCls)) {
            // feEnvReport(AppInterface, String key, String content, dt.api.a callback)
            HookUtils.hookAllMethods(qsecChannelCls, "feEnvReport", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args != null && p.args.length >= 3) {
                        String content = p.args[2] != null ? p.args[2].toString() : null;
                        if (content != null && (content.contains("risk") || content.contains("hook") || content.contains("root") || content.contains("fail"))) {
                            p.args[2] = "{}";
                        }
                    }
                    if (p.args != null && p.args.length >= 4 && p.args[3] != null) {
                        try {
                            XposedHelpers.callMethod(p.args[3], "onResult", 0, new byte[0]);
                        } catch (Throwable ignored) { }
                    }
                }
            });

            // feCameraActionReport
            HookUtils.hookAllMethods(qsecChannelCls, "feCameraActionReport", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args != null && p.args.length >= 8 && p.args[7] != null) {
                        try {
                            XposedHelpers.callMethod(p.args[7], "onResult", 0, new byte[0]);
                        } catch (Throwable ignored) { }
                    }
                }
            });

            // collectReport
            HookUtils.hookAllMethods(qsecChannelCls, "collectReport", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args != null && p.args.length >= 3 && p.args[2] instanceof String) {
                        try {
                            org.json.JSONObject json = new org.json.JSONObject((String) p.args[2]);
                            json.put("10", "none");
                            json.put("30", 0);
                            json.put("31", "[]");
                            json.put("32", "[]");
                            json.put("14", "CK_N");
                            p.args[2] = json.toString();
                        } catch (Throwable ignored) { }
                    }
                    if (p.args != null && p.args.length >= 4 && p.args[3] != null) {
                        try {
                            XposedHelpers.callMethod(p.args[3], "onResult", 0, new byte[0]);
                        } catch (Throwable ignored) { }
                    }
                }
            });
        }
    }
}
