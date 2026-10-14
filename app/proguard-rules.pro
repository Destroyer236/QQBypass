# ========================================================
# Xposed 模块入口与核心类保留规则
# ========================================================

# 1. 保留 Xposed 模块入口类（由 Xposed/LSPosed 框架动态反射加载）
-keep class io.github.xalsace.qqbypass.XposedEntry {
    public *;
    <init>(...);
}

# 2. 保留整个模块包下的所有类、方法和字段（包括 hooks, detector, config, utils 及根包）
# 防止 Hook 逻辑、DexKit 动态探测、配置项、反射工具类在 Release 优化阶段被 R8 裁剪、内联或混淆
-keep class io.github.xalsace.qqbypass.** {
    *;
}

# 3. 保留 Native 方法及其声明类（防止 JNI 方法签名不一致）
-keepclasseswithmembernames class * {
    native <methods>;
}

# 4. 保留 ByteHook 相关类
-keep class com.bytedance.android.bytehook.** { *; }
-dontwarn com.bytedance.android.bytehook.**

# 5. 保留 DexKit 相关类及原生方法
-keep class org.luckypray.dexkit.** { *; }
-keepclasseswithmembers,includedescriptorclasses class org.luckypray.dexkit.** {
    native <methods>;
    long token;
}
-dontwarn org.luckypray.dexkit.**

# 6. 保留 Kotlin 相关类及抑制警告
-dontwarn kotlin.**
-keep class kotlin.** { *; }

# 7. Xposed API（由运行时的 Xposed/LSPosed 宿主环境提供，仅编译期依赖）
-dontwarn de.robv.android.xposed.**
-keep class de.robv.android.xposed.** { *; }

# 8. 保留反射相关注解与调试信息
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod,SourceFile,LineNumberTable

