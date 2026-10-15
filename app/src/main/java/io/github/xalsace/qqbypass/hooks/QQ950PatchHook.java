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
        hookKickBackstop(lpparam);
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

        // Tier 5: Clean detection sources at the origin (Location, Sensors, Screen/Display, ADB/Accessibility)
        hookDetectionSourcesAtOrigin(lpparam);

        // Tier 6: Dynamic SO (txlib / txPttlib) and MQP Integrity Strike Protection
        hookTxlibAndPttProtection(lpparam);

        // Tier 7: RFix & Hotfix Failure Sanitization and Telemetry Drop
        hookRFixFailureSanitization(lpparam);
    }

    // ==================== Tier 1: void-return, crash-safe ====================

    /**
     * Enhanced Multi-Process Kick Prevention & Session Defense:
     *
     * Tackles the root cause of kick/force-offline at all protocol & UI levels:
     * 1. MSF Process (com.tencent.mobileqq:MSF):
     *    - SSORespHandler (t.a): drops MessageSvc.PushForceOffline, StatSvc.ReqMSFOffline, KickNT;
     *      neutralizes fatal failCodes (-10103, -10104, -10105, -10005, -10106, -10135, -10136, 210, etc.)
     *    - AccountCenter.p (b.p): blocks setAccountNoLogin to prevent deleting session key from memory.
     *    - PushManager.d (h.d): blocks unregistering push listeners for kicked UIN.
     *    - MsfSdkUtils.updateSimpleAccount: prevents writing logged-out status (_f) to disk.
     *    - MsfSdkUtils.killProcess: blocks killing main or MSF processes.
     * 2. Main Process (com.tencent.mobileqq):
     *    - MainService$MyErrorHandler: suppresses onKicked, onKickedAndClearToken, onKickedInternal, popupNotification.
     *    - MainService.kick: suppresses AppRuntime.KickParams dispatch.
     *    - KickApiImpl: neutralizes NT kernel kick and forces shouldIgnoreNotifyMsfStatusChanged to true.
     *    - NTKickProcessor: suppresses entry a, worker b, and notification launch unconditionally.
     *    - UidServiceImpl: blocks kickToLoginPage and logoutWhenReqUidFail.
     *    - AppRuntime: blocks ntTriggerLogout, setKickIntent, setAutoLogin(false), and marks onReceiveUnhandledKickedMsg true.
     */
    private static void hookKickBackstop(XC_LoadPackage.LoadPackageParam lpparam) {
        XposedEntry.log("[KickPatch] Initializing multi-process kick & session preservation hooks");

        // === Layer 1: MSF Network Protocol & Token Protection ===

        // 1.1 MSF SSORespHandler (com.tencent.mobileqq.msf.core.t.a)
        hookSafe("com.tencent.mobileqq.msf.core.t", "a", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args == null || p.args.length < 2) return;
                Object fromServiceMsg = null;
                for (Object arg : p.args) {
                    if (arg != null && "com.tencent.qphone.base.remote.FromServiceMsg".equals(arg.getClass().getName())) {
                        fromServiceMsg = arg;
                        break;
                    }
                }
                if (fromServiceMsg == null) return;
                try {
                    String cmd = (String) XposedHelpers.callMethod(fromServiceMsg, "getServiceCmd");
                    int failCode = ((Number) XposedHelpers.callMethod(fromServiceMsg, "getBusinessFailCode")).intValue();

                    // Drop push kicks completely
                    if ("MessageSvc.PushForceOffline".equals(cmd) ||
                        "StatSvc.ReqMSFOffline".equals(cmd) ||
                        "trpc.qq_new_tech.status_svc.StatusService.KickNT".equals(cmd)) {
                        p.setResult(true);
                        XposedEntry.log("[MSFKickPatch] Dropped server push force-offline: " + cmd);
                        return;
                    }

                    // Neutralize fatal SSO failCodes that purge credentials or trigger killProcess
                    if (failCode == -10103 || failCode == -10104 || failCode == -10105 ||
                        failCode == -10005 || failCode == -10106 || failCode == -10135 ||
                        failCode == -10136 || failCode == -10001 || failCode == -10003 ||
                        failCode == -10004 || failCode == -10006 || failCode == -12003 || failCode == 210) {
                        XposedHelpers.callMethod(fromServiceMsg, "setBusinessFailCode", 1000);
                        XposedHelpers.callMethod(fromServiceMsg, "setMsgSuccess");
                        XposedEntry.log("[MSFKickPatch] Neutralized fatal SSO failCode " + failCode + " for cmd: " + cmd);
                    }
                } catch (Throwable t) {
                    XposedEntry.log("[MSFKickPatch] Error inspecting MSF message: " + t.getMessage());
                }
            }
        });

        // 1.2 MSF AccountCenter.p(String) (setAccountNoLogin)
        hookSafe("com.tencent.mobileqq.msf.core.auth.b", "p", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length == 1 && p.args[0] instanceof String) {
                    p.setResult(null);
                    XposedEntry.log("[MSFKickPatch] Suppressed AccountCenter.p(setAccountNoLogin) for UIN: " + p.args[0]);
                }
            }
        });

        // 1.3 MSF PushManager.d(String) (unregister push on kick)
        hookSafe("com.tencent.mobileqq.msf.core.push.h", "d", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length == 1 && p.args[0] instanceof String) {
                    p.setResult(null);
                    XposedEntry.log("[MSFKickPatch] Suppressed PushManager.d(unregister on kick) for UIN: " + p.args[0]);
                }
            }
        });

        // 1.4 MSF NetAdapt kick alert
        hookSafe("com.tencent.mobileqq.msf.core.net.adapt.a", "a", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length > 0 && "kicked".equals(p.args[0])) {
                    p.setResult(null);
                    XposedEntry.log("[MSFKickPatch] Suppressed net adaptation kick alert");
                }
            }
        });

        // 1.5 MsfSdkUtils: Prevent writing logged-out status (_f) to disk
        hookSafe("com.tencent.mobileqq.msf.sdk.MsfSdkUtils", "updateSimpleAccount", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length >= 2 && Boolean.FALSE.equals(p.args[1])) {
                    p.args[1] = Boolean.TRUE;
                    XposedEntry.log("[KickPatch] MsfSdkUtils.updateSimpleAccount: forced isLogined=true for " + p.args[0]);
                }
            }
        });
        hookSafe("com.tencent.mobileqq.msf.sdk.MsfSdkUtils", "updateSimpleAccountNotCreate", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length >= 2 && Boolean.FALSE.equals(p.args[1])) {
                    p.args[1] = Boolean.TRUE;
                }
            }
        });

        // 1.6 MsfSdkUtils.killProcess: Prevent terminating any process
        hookSafe("com.tencent.mobileqq.msf.sdk.MsfSdkUtils", "killProcess", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(false);
                XposedEntry.log("[KickPatch] Blocked MsfSdkUtils.killProcess for: " + (p.args != null && p.args.length > 1 ? p.args[1] : "target"));
            }
        });

        // === Layer 2: Main Process & NT Kernel Protection ===

        // 2.1 MainService$MyErrorHandler: Suppress all kick dispatch handlers
        String errorHandlerCls = "mqq.app.MainService$MyErrorHandler";
        String[] errHandlerMethods = {
            "onKicked", "onKickedAndClearToken", "onKickedInternal",
            "onInterceptKicked", "popupNotification", "popupNotificationEx"
        };
        for (String mName : errHandlerMethods) {
            hookSafe(errorHandlerCls, mName, lpparam, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(null);
                    XposedEntry.log("[KickPatch] Suppressed MainService.MyErrorHandler." + p.method.getName());
                }
            });
        }

        // 2.2 MainService.kick(AppRuntime.KickParams)
        hookSafe("mqq.app.MainService", "kick", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
                XposedEntry.log("[KickPatch] Suppressed MainService.kick");
            }
        });

        // 2.3 KickApiImpl: Suppress NT Kernel kick listener and ignore MSF status offline changes
        final String kickApiCls = "com.tencent.qqnt.kernel.api.impl.KickApiImpl";
        hookSafe(kickApiCls, "kick", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
                XposedEntry.log("[KickPatch] Suppressed KickApiImpl.kick");
            }
        });
        hookSafe(kickApiCls, "shouldIgnoreNotifyMsfStatusChanged", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(true);
            }
        });
        hookSafe(kickApiCls, "isOpenIgnoreNotifyMsfStatusChanged", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(true);
            }
        });

        // 2.4 NTKickProcessor: Suppress public entry a, internal worker b, and showNotification
        final String ntKickCls = "com.tencent.mobileqq.kick.NTKickProcessor";
        hookSafe(ntKickCls, "a", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
                XposedEntry.log("[KickPatch] Suppressed NTKickProcessor.a kick event");
            }
        });
        hookSafe(ntKickCls, "b", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
                XposedEntry.log("[KickPatch] Suppressed NTKickProcessor.b worker");
            }
        });

        // 2.5 UidServiceImpl: Suppress kickToLoginPage & logoutWhenReqUidFail
        final String uidServiceCls = "com.tencent.mobileqq.login.api.impl.UidServiceImpl";
        hookSafe(uidServiceCls, "kickToLoginPage", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
                XposedEntry.log("[KickPatch] Suppressed UidServiceImpl.kickToLoginPage");
            }
        });
        hookSafe(uidServiceCls, "logoutWhenReqUidFail", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
                XposedEntry.log("[KickPatch] Suppressed UidServiceImpl.logoutWhenReqUidFail");
            }
        });

        // 2.6 AppRuntime: Suppress ntTriggerLogout, setKickIntent, setAutoLogin(false), onReceiveUnhandledKickedMsg
        final String appRuntimeCls = "mqq.app.AppRuntime";
        hookSafe(appRuntimeCls, "ntTriggerLogout", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
                XposedEntry.log("[KickPatch] Suppressed AppRuntime.ntTriggerLogout");
            }
        });
        hookSafe(appRuntimeCls, "setKickIntent", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
                XposedEntry.log("[KickPatch] Suppressed AppRuntime.setKickIntent");
            }
        });
        hookSafe(appRuntimeCls, "setAutoLogin", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length > 0 && Boolean.FALSE.equals(p.args[0])) {
                    p.setResult(null);
                    XposedEntry.log("[KickPatch] Suppressed AppRuntime.setAutoLogin(false)");
                }
            }
        });
        hookSafe(appRuntimeCls, "onReceiveUnhandledKickedMsg", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(true);
            }
        });
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

    // ============ Tier 5: Clean detection sources at the origin ============

    /**
     * Tier 5: Direct Sanitization at the Detection Source.
     *
     * Cleans data at the moment of generation so that all downstream consumers,
     * UI components, and telemetry collectors observe authentic, healthy values:
     * 1. Location detection source:
     *    - TencentLocation.getFakeReason() & isMockGps() forced to 0 (genuine).
     *    - SosoLocation.fakeReason forced to 0 in constructors & clone.
     *    - LbsManagerService.notifySec ensures fakeReason = 0 (prevents O3Report.c 10002/10003 triggers).
     *    - android.location.Location.isFromMockProvider() & isMock() forced to false.
     * 2. Sensor detection source:
     *    - qqprotect.qsec.b.b() (accelerometer): synthesizes realistic gravity vector if missing/unregistered.
     *    - qqprotect.qsec.c.b() (gyroscope): synthesizes realistic micro-tremor reading if missing/unregistered.
     *    - qqprotect.qsec.d.b() (light sensor): synthesizes 150.0 lux indoor ambient reading if <= 0.
     * 3. Screen/Display & Remote Control detection source:
     *    - Display.getOwnerPackageName(): returns null (hides screen capture apps).
     *    - Display.getName(): sanitizes scrcpy/minicap/virtual screen names to "Built-in Screen".
     *    - Display.getRefreshRate(): normalizes <= 30fps emulator rates to 60.0f.
     *    - Ganliang.g(): neutralizes forced FLAG_SECURE (8192) to eliminate black screen issues.
     *    - Ganliang.f(): suppresses Cmd0x9747Req display package reporting.
     * 4. APK lastModified detection source:
     *    - qqprotect.qsec.a.o(): guarantees valid baseline APK timestamp.
     */
    private static void hookDetectionSourcesAtOrigin(XC_LoadPackage.LoadPackageParam lpparam) {
        // 1. Location Detection Source: TencentLocation & SosoLocation
        String[] tencentLocClasses = {
            "com.tencent.map.geolocation.TencentLocation",
            "com.tencent.map.geolocation.internal.TencentExtraKeys"
        };
        for (String cls : tencentLocClasses) {
            if (!HookUtils.classExists(cls)) continue;
            HookUtils.hookAllMethods(cls, "getFakeReason", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(0); // 0 = genuine, zero anomaly
                }
            });
            HookUtils.hookAllMethods(cls, "isMockGps", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(0);
                }
            });
        }

        final String sosoLocCls = "com.tencent.mobileqq.soso.location.data.SosoLocation";
        if (HookUtils.classExists(sosoLocCls)) {
            HookUtils.hookAllConstructors(sosoLocCls, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    try {
                        XposedHelpers.setIntField(p.thisObject, "fakeReason", 0);
                    } catch (Throwable ignored) { }
                }
            });

            HookUtils.hookAllMethods(sosoLocCls, "clone", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.getResult() != null) {
                        try {
                            XposedHelpers.setIntField(p.getResult(), "fakeReason", 0);
                        } catch (Throwable ignored) { }
                    }
                }
            });
        }

        final String lbsMgrCls = "com.tencent.mobileqq.soso.location.LbsManagerService";
        if (HookUtils.classExists(lbsMgrCls)) {
            HookUtils.hookAllMethods(lbsMgrCls, "notifySec", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args != null && p.args.length >= 2 && p.args[1] != null) {
                        try {
                            Object sosoLbsInfo = p.args[1];
                            Object sosoLocation = XposedHelpers.getObjectField(sosoLbsInfo, "mLocation");
                            if (sosoLocation != null) {
                                XposedHelpers.setIntField(sosoLocation, "fakeReason", 0);
                            }
                        } catch (Throwable ignored) { }
                    }
                }
            });
        }

        // Framework Location: isFromMockProvider & isMock
        HookUtils.hookAllMethods("android.location.Location", "isFromMockProvider", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(false);
            }
        });
        HookUtils.hookAllMethods("android.location.Location", "isMock", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(false);
            }
        });

        // 2. Physical Sensor Detection Source: qqprotect.qsec.b, c, d
        final String qsecBCls = "com.tencent.qqprotect.qsec.b";
        if (HookUtils.classExists(qsecBCls)) {
            HookUtils.hookAllMethods(qsecBCls, "b", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    Object res = p.getResult();
                    if (res == null || "-1".equals(res) || "".equals(res) || "null".equals(res)) {
                        p.setResult("{x=0.231, y=9.765, z=0.412}");
                        XposedEntry.log("[DetectionSource] Cleaned qsec.b accelerometer -> realistic reading");
                    }
                }
            });
        }

        final String qsecCCls = "com.tencent.qqprotect.qsec.c";
        if (HookUtils.classExists(qsecCCls)) {
            HookUtils.hookAllMethods(qsecCCls, "b", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    Object res = p.getResult();
                    if (res == null || "-1".equals(res) || "".equals(res) || "null".equals(res)) {
                        p.setResult("{x=0.001, y=0.002, z=0.001}");
                        XposedEntry.log("[DetectionSource] Cleaned qsec.c gyroscope -> realistic reading");
                    }
                }
            });
        }

        final String qsecDCls = "com.tencent.qqprotect.qsec.d";
        if (HookUtils.classExists(qsecDCls)) {
            HookUtils.hookAllMethods(qsecDCls, "b", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    Object res = p.getResult();
                    if (res instanceof Number && ((Number) res).floatValue() <= 0.0f) {
                        p.setResult(150.0f);
                        XposedEntry.log("[DetectionSource] Cleaned qsec.d light sensor -> 150.0 lux");
                    }
                }
            });
        }

        // 3. Screen / Display & Remote Control Detection Source: Display & Ganliang
        HookUtils.hookAllMethods("android.view.Display", "getOwnerPackageName", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
            }
        });

        HookUtils.hookAllMethods("android.view.Display", "getName", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (p.getResult() instanceof String) {
                    String name = (String) p.getResult();
                    if (name.contains("scrcpy") || name.contains("minicap") || name.contains("virtual") || name.contains("overlay")) {
                        p.setResult("Built-in Screen");
                    }
                }
            }
        });

        HookUtils.hookAllMethods("android.view.Display", "getRefreshRate", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (p.getResult() instanceof Number && ((Number) p.getResult()).floatValue() <= 30.0f) {
                    p.setResult(60.0f);
                }
            }
        });

        final String ganliangCls = "com.tencent.qqprotect.ganliang.Ganliang";
        if (HookUtils.classExists(ganliangCls)) {
            // Prevent imposing FLAG_SECURE (8192) on activity window
            HookUtils.hookAllMethods(ganliangCls, "g", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(null);
                    XposedEntry.log("[DetectionSource] Neutralized Ganliang.g (prevented FLAG_SECURE)");
                }
            });

            // Suppress Cmd0x9747Req display package report
            HookUtils.hookAllMethods(ganliangCls, "f", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(null);
                    XposedEntry.log("[DetectionSource] Suppressed Ganliang.f (Cmd0x9747Req report)");
                }
            });
        }

        // 4. SourceDir LastModified Detection Source
        final String qsecACls = "com.tencent.qqprotect.qsec.a";
        if (HookUtils.classExists(qsecACls)) {
            HookUtils.hookAllMethods(qsecACls, "o", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.getResult() instanceof Number && ((Number) p.getResult()).longValue() <= 0L) {
                        p.setResult(1727000000000L);
                    }
                }
            });
        }
    }

    /**
     * Tier 6: Dynamic SO (txlib / txPttlib) and MQP Integrity Strike Protection.
     *
     * Addresses runtime telemetry and security integrity verification across:
     * 1. txlib & Dynamic Native Library Verification / Telemetry:
     *    - com.tencent.mobileqq.msf.core.report.j.a: suppresses reportMsfLoadSoError when isLoaded=false or resultCode!=0.
     *    - MsfCore.tryReportSoLoadUseTxlib: suppresses msf_core_EvtLoadUseTxlib telemetry.
     *    - SoLoadCore.reportThrowable: suppresses SO loading exception reporting.
     * 2. MQPSecUtil & Integrity Check Strike (txlib/libmqpintchk.so):
     *    - MQPSecUtil.memchk: forced true (clean memory integrity).
     *    - MQPSecUtil.antitrace / do_report: neutralized.
     *    - MSFIntChkStrike.exec: neutralized (prevents punishment dialog & forced logout).
     * 3. txPttlib Audio Codec Telemetry:
     *    - StatisticCollector.collectPerformance: sanitizes actPttSoUpdate to param_FailCode=0 and success=true;
     *      suppresses msf_core_EvtMsfLoadSoError and msf_core_EvtLoadUseTxlib.
     */
    private static void hookTxlibAndPttProtection(XC_LoadPackage.LoadPackageParam lpparam) {
        XposedEntry.log("[Tier6] Initializing txlib, txPttlib & MQP integrity protection");

        // --- 1. txlib & Dynamic SO Integrity Telemetry ---
        final String msfReportJCls = "com.tencent.mobileqq.msf.core.report.j";
        hookSafe(msfReportJCls, "a", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length == 4 && p.args[0] instanceof String && p.args[1] instanceof Boolean && p.args[2] instanceof Integer) {
                    boolean isLoaded = (Boolean) p.args[1];
                    int resultCode = (Integer) p.args[2];
                    if (!isLoaded || resultCode != 0) {
                        p.setResult(null);
                        XposedEntry.log("[TxLibPatch] Suppressed reportMsfLoadSoError for lib: " + p.args[0]);
                    }
                }
            }
        });

        final String msfCoreCls = "com.tencent.mobileqq.msf.core.MsfCore";
        hookSafe(msfCoreCls, "tryReportSoLoadUseTxlib", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
                XposedEntry.log("[TxLibPatch] Suppressed MsfCore.tryReportSoLoadUseTxlib");
            }
        });

        final String soLoadCoreCls = "com.tencent.commonsdk.soload.SoLoadCore";
        hookSafe(soLoadCoreCls, "reportThrowable", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
                XposedEntry.log("[TxLibPatch] Suppressed SoLoadCore.reportThrowable");
            }
        });

        // --- 2. MQPSecUtil & Integrity Strike (txlib/libmqpintchk.so) ---
        final String mqpSecUtilCls = "com.tencent.mqp.app.sec.MQPSecUtil";
        hookSafe(mqpSecUtilCls, "memchk", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(true);
                XposedEntry.log("[MQPPatch] MQPSecUtil.memchk -> forced true (clean memory integrity)");
            }
        });

        hookSafe(mqpSecUtilCls, "antitrace", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
                XposedEntry.log("[MQPPatch] Neutralized MQPSecUtil.antitrace");
            }
        });

        hookSafe(mqpSecUtilCls, "do_report", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
                XposedEntry.log("[MQPPatch] Suppressed MQPSecUtil.do_report");
            }
        });

        final String intChkStrikeCls = "com.tencent.msfmqpsdkbridge.MSFIntChkStrike";
        hookSafe(intChkStrikeCls, "exec", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
                XposedEntry.log("[MQPPatch] Suppressed MSFIntChkStrike.exec (prevented strike popup/logout)");
            }
        });

        // --- 3. txPttlib Audio Codec Telemetry ---
        final String statCollectorCls = "com.tencent.mobileqq.statistics.StatisticCollector";
        hookSafe(statCollectorCls, "collectPerformance", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length >= 2 && p.args[1] instanceof String) {
                    String tag = (String) p.args[1];
                    if ("actPttSoUpdate".equals(tag)) {
                        if (p.args.length > 2 && p.args[2] instanceof Boolean) {
                            p.args[2] = true;
                        }
                        for (int i = 3; i < p.args.length; i++) {
                            if (p.args[i] instanceof java.util.Map) {
                                ((java.util.Map) p.args[i]).put("param_FailCode", "0");
                                break;
                            }
                        }
                        XposedEntry.log("[PttPatch] Sanitized actPttSoUpdate telemetry to success (0)");
                    } else if ("msf_core_EvtMsfLoadSoError".equals(tag) || "msf_core_EvtLoadUseTxlib".equals(tag)) {
                        p.setResult(null);
                        XposedEntry.log("[TxLibPatch] Suppressed SO load telemetry: " + tag);
                    }
                }
            }
        });
    }

    /**
     * Tier 7: RFix & Hotfix Failure Sanitization and Telemetry Drop.
     *
     * Directly addresses the root-cause of account kick / force-offline:
     * When bytecode/signature verification on hotfix fails with ERROR_LOAD_PATCH_VERSION_DEX_MD5_MISMATCH (-8),
     * RFix quality reporter sends LOAD_RESULT_PATCH_LOADER_FAIL with event_code_ext=-8 to ATTA (attaid=0ac00056535)
     * and WeData (groupId=gwe0003255039a, streamId=swe000017406d5), directly triggering server-side forced kick!
     *
     * Defenses implemented:
     * 1. RFixLoadResult: force isLoaderSuccess() and isSuccess() to true.
     * 2. PatchLoadEngineBase: in tryLoadPatchInternal/loadPatch, if result is LOAD_RESULT_PATCH_LOADER_FAIL,
     *    rewrite result to LOAD_RESULT_SUCCESS and subResult to 0.
     * 3. com.tencent.rfix.lib.reporter.e:
     *    - method d & e: drop any report where eventSuccess is false or eventCode contains "FAIL" or eventCodeExt is "-8".
     *    - method a, b, c: drop if rFixLoadResult failed.
     * 4. com.tencent.rfix.lib.atta.RFixATTASwitch:
     *    - method a(): return false (turns off ATTA/WeData network delivery for RFix).
     * 5. com.tencent.rfix.lib.atta.e:
     *    - method d(Map): drop any map where event_code contains "FAIL" or attaid is "0ac00056535" with failure.
     * 6. com.tencent.rfix.lib.wedata.base.d:
     *    - method c(Map, String[]): drop failure maps.
     * 7. com.tencent.rfix.lib.bugly.a:
     *    - method a: ensure D4 is never set to "0" and patch_tag_flag_0_ is never written.
     * 8. com.tencent.rfix.loader.safemode.RFixSafeModeKeeper:
     *    - checkSafeMode: return 0 (RESULT_OK).
     *    - reachP1Limit, reachP2Limit, reachP3Limit: return false.
     *    - writeLastCrashFile: drop.
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    private static void hookRFixFailureSanitization(XC_LoadPackage.LoadPackageParam lpparam) {
        XposedEntry.log("[Tier7] Initializing RFix & Hotfix failure sanitization and telemetry drop");

        // 1. RFixLoadResult: Force isLoaderSuccess and isSuccess to true
        hookSafe("com.tencent.rfix.loader.entity.RFixLoadResult", "isLoaderSuccess", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(true);
            }
        });
        hookSafe("com.tencent.rfix.loader.entity.RFixLoadResult", "isSuccess", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(true);
            }
        });

        // 2. PatchLoadEngineBase: neutralize LOAD_RESULT_PATCH_LOADER_FAIL in tryLoadPatchInternal
        hookSafe("com.tencent.rfix.loader.engine.PatchLoadEngineBase", "tryLoadPatchInternal", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length > 0 && p.args[0] != null) {
                    Object loadResult = p.args[0];
                    try {
                        Object resultObj = XposedHelpers.getObjectField(loadResult, "result");
                        if (resultObj != null && resultObj.toString().contains("FAIL")) {
                            Class enumCls = resultObj.getClass();
                            Object successEnum = Enum.valueOf(enumCls, "LOAD_RESULT_SUCCESS");
                            XposedHelpers.setObjectField(loadResult, "result", successEnum);
                            XposedHelpers.setIntField(loadResult, "subResult", 0);
                            XposedEntry.log("[RFixPatch] Neutralized PatchLoadEngineBase failure result -> LOAD_RESULT_SUCCESS");
                        }
                    } catch (Throwable t) {
                        XposedEntry.log("[RFixPatch] Error neutralizing loadResult: " + t.getMessage());
                    }
                }
            }
        });

        // 3. RFix Quality Reporter: Drop failure reports in com.tencent.rfix.lib.reporter.e
        XC_MethodHook dropFailureReportHook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args == null || p.args.length < 9) return;
                try {
                    // Check z (eventSuccess) at index 6
                    boolean eventSuccess = true;
                    if (p.args[6] instanceof Boolean) {
                        eventSuccess = (Boolean) p.args[6];
                    }
                    // Check str6 (eventCode) at index 7
                    String eventCode = p.args[7] != null ? p.args[7].toString() : null;
                    // Check str7 (eventCodeExt) at index 8
                    String eventCodeExt = p.args[8] != null ? p.args[8].toString() : null;

                    if (!eventSuccess || (eventCode != null && eventCode.contains("FAIL")) ||
                        "-8".equals(eventCodeExt) || "LOAD_RESULT_PATCH_LOADER_FAIL".equals(eventCode)) {
                        p.setResult(true);
                        XposedEntry.log("[RFixPatch] Dropped RFix failure telemetry report: eventCode=" + eventCode + ", codeExt=" + eventCodeExt);
                    }
                } catch (Throwable t) {
                    XposedEntry.log("[RFixPatch] Error filtering RFix reporter: " + t.getMessage());
                }
            }
        };
        hookSafe("com.tencent.rfix.lib.reporter.e", "d", lpparam, dropFailureReportHook);
        hookSafe("com.tencent.rfix.lib.reporter.e", "e", lpparam, dropFailureReportHook);

        // Drop caller methods in e: a, b
        hookSafe("com.tencent.rfix.lib.reporter.e", "a", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length > 1 && p.args[1] != null) {
                    try {
                        boolean isSuccess = (Boolean) XposedHelpers.callMethod(p.args[1], "isLoaderSuccess");
                        if (!isSuccess) {
                            p.setResult(null);
                            XposedEntry.log("[RFixPatch] Dropped com.tencent.rfix.lib.reporter.e.a failure report");
                        }
                    } catch (Throwable ignored) {}
                }
            }
        });
        hookSafe("com.tencent.rfix.lib.reporter.e", "b", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length > 1 && p.args[1] != null) {
                    try {
                        boolean isSuccess = (Boolean) XposedHelpers.callMethod(p.args[1], "isLoaderSuccess");
                        if (!isSuccess) {
                            p.setResult(true);
                            XposedEntry.log("[RFixPatch] Dropped com.tencent.rfix.lib.reporter.e.b failure report");
                        }
                    } catch (Throwable ignored) {}
                }
            }
        });

        // 4. RFix ATTASwitch: Force disable RFix ATTA/WeData network reporting
        hookSafe("com.tencent.rfix.lib.atta.RFixATTASwitch", "a", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(false);
            }
        });

        // 5. RFix ATTA Database & Upload Helper (com.tencent.rfix.lib.atta.e)
        hookSafe("com.tencent.rfix.lib.atta.e", "d", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length > 0 && p.args[0] instanceof java.util.Map) {
                    java.util.Map map = (java.util.Map) p.args[0];
                    Object eventCode = map.get("event_code");
                    Object eventSuccess = map.get("event_success");
                    Object attaid = map.get("attaid");
                    if ("0ac00056535".equals(attaid) && ("0".equals(eventSuccess) || (eventCode != null && eventCode.toString().contains("FAIL")))) {
                        p.setResult(true);
                        XposedEntry.log("[RFixPatch] Dropped ATTA poison failure record from atta.e.d");
                    }
                }
            }
        });

        // 6. WeData Reporter (com.tencent.rfix.lib.wedata.base.d)
        hookSafe("com.tencent.rfix.lib.wedata.base.d", "c", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length > 0 && p.args[0] instanceof java.util.Map) {
                    java.util.Map map = (java.util.Map) p.args[0];
                    Object eventCode = map.get("event_code");
                    Object eventSuccess = map.get("event_success");
                    if ("0".equals(eventSuccess) || (eventCode != null && eventCode.toString().contains("FAIL"))) {
                        p.setResult(true);
                        XposedEntry.log("[RFixPatch] Dropped WeData failure report in wedata.base.d.c");
                    }
                }
            }
        });

        // 7. RFix Bugly tag initializer (com.tencent.rfix.lib.bugly.a)
        hookSafe("com.tencent.rfix.lib.bugly.a", "a", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length > 1 && p.args[1] != null) {
                    try {
                        boolean isSuccess = (Boolean) XposedHelpers.callMethod(p.args[1], "isLoaderSuccess");
                        if (!isSuccess) {
                            p.setResult(null);
                            XposedEntry.log("[RFixPatch] Suppressed Bugly updatePatchTag for failed hotfix");
                        }
                    } catch (Throwable ignored) {}
                }
            }
        });

        // 8. RFix SafeMode Keeper (com.tencent.rfix.loader.safemode.RFixSafeModeKeeper)
        final String safeModeKeeperCls = "com.tencent.rfix.loader.safemode.RFixSafeModeKeeper";
        hookSafe(safeModeKeeperCls, "checkSafeMode", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(0); // RESULT_OK
            }
        });
        hookSafe(safeModeKeeperCls, "reachP1Limit", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(false);
            }
        });
        hookSafe(safeModeKeeperCls, "reachP2Limit", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(false);
            }
        });
        hookSafe(safeModeKeeperCls, "reachP3Limit", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(false);
            }
        });
        hookSafe(safeModeKeeperCls, "writeLastCrashFile", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
            }
        });
        hookSafe(safeModeKeeperCls, "handlePatchCrash", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
            }
        });
    }

    private static void hookSafe(final String className, final String methodName, XC_LoadPackage.LoadPackageParam lpparam, final XC_MethodHook callback) {
        ClassLoader cl = lpparam != null && lpparam.classLoader != null ? lpparam.classLoader : HookConfig.getClassLoader();
        Class<?> clazz = XposedHelpers.findClassIfExists(className, cl);
        if (clazz != null) {
            HookUtils.hookAllMethods(clazz, methodName, callback);
        } else if (cl != null) {
            try {
                XposedHelpers.findAndHookMethod(cl.getClass(), "loadClass", String.class, boolean.class, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                        if (className.equals(p.args[0])) {
                            Class<?> loadedClass = (Class<?>) p.getResult();
                            if (loadedClass != null) {
                                HookUtils.hookAllMethods(loadedClass, methodName, callback);
                            }
                        }
                    }
                });
            } catch (Throwable ignored) {
                try {
                    XposedHelpers.findAndHookMethod(cl.getClass(), "loadClass", String.class, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                            if (className.equals(p.args[0])) {
                                Class<?> loadedClass = (Class<?>) p.getResult();
                                if (loadedClass != null) {
                                    HookUtils.hookAllMethods(loadedClass, methodName, callback);
                                }
                            }
                        }
                    });
                } catch (Throwable ignored2) {}
            }
        }
    }
}

