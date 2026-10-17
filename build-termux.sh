#!/data/data/com.termux/files/usr/bin/bash
# ==============================================================================
# QQBypass Termux 本地构建脚本 (支持基础版与 DexKit 版)
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_DIR="$HOME/android-sdk"
PLATFORM_JAR="$SDK_DIR/platforms/android-34/android.jar"
LIBS_DIR="$SDK_DIR/libs"
API_JAR="$LIBS_DIR/api-82.jar"
BYTEHOOK_JAR="$LIBS_DIR/bytehook-classes.jar"
KEYSTORE="$SDK_DIR/debug.keystore"
ZIPALIGN="$SDK_DIR/zipalign.py"

# DexKit 选配依赖
DEXKIT_JAR="$LIBS_DIR/dexkit-classes.jar"
DEXKIT_AAR="$LIBS_DIR/dexkit-2.0.0.aar"
KOTLIN_JAR="$LIBS_DIR/kotlin-stdlib-1.8.22.jar"
FLATBUFFERS_JAR="$LIBS_DIR/flatbuffers-java-23.5.26.jar"

BUILD_DIR="$SCRIPT_DIR/build/termux"
OUT_APK_DIR="$SCRIPT_DIR/app/build/outputs/apk/release"
TARGET_APK="$OUT_APK_DIR/app-release.apk"

echo "=================================================="
echo "  QQ Enhanced Bypass - Termux 本地构建"
echo "=================================================="

# 检查依赖环境
if [ ! -f "$PLATFORM_JAR" ]; then
    echo "[错误] 缺少 android.jar: $PLATFORM_JAR"
    exit 1
fi

if [ ! -f "$API_JAR" ] || [ ! -f "$BYTEHOOK_JAR" ]; then
    echo "[错误] 缺少基础依赖库，请检查 $LIBS_DIR"
    exit 1
fi

mkdir -p "$BUILD_DIR"
mkdir -p "$OUT_APK_DIR"

# 检测是否包含 DexKit 特性
HAS_DEXKIT=false
if [ -d "$SCRIPT_DIR/app/src/main/java/io/github/xalsace/qqbypass/detector" ]; then
    HAS_DEXKIT=true
    echo "[特性检测] 启用 DexKit 动态探测支持"
    if [ ! -f "$FLATBUFFERS_JAR" ]; then
        echo "  -> 自动下载 DexKit 运行时依赖 flatbuffers-java-23.5.26.jar..."
        curl -sSL -o "$FLATBUFFERS_JAR" "https://repo1.maven.org/maven2/com/google/flatbuffers/flatbuffers-java/23.5.26/flatbuffers-java-23.5.26.jar"
    fi
    if [ ! -f "$DEXKIT_JAR" ] || [ ! -f "$KOTLIN_JAR" ] || [ ! -f "$FLATBUFFERS_JAR" ]; then
        echo "[错误] 缺少 DexKit 或 Kotlin/FlatBuffers 依赖库"
        exit 1
    fi
fi

# 1. 编译资源
echo "[1/6] 编译资源文件 (aapt2 compile)..."
rm -rf "$BUILD_DIR/res.zip" "$BUILD_DIR/gen" "$BUILD_DIR/classes" "$BUILD_DIR/dex" "$BUILD_DIR/apk_root"
mkdir -p "$BUILD_DIR/gen" "$BUILD_DIR/classes" "$BUILD_DIR/dex" "$BUILD_DIR/apk_root"
aapt2 compile --dir "$SCRIPT_DIR/app/src/main/res" -o "$BUILD_DIR/res.zip"

# 2. 链接资源并生成 R.java
echo "[2/6] 链接资源与 Manifest (aapt2 link)..."
aapt2 link -I "$PLATFORM_JAR" \
    --min-sdk-version 26 \
    --target-sdk-version 34 \
    --version-code 47 \
    --version-name "1.0.47" \
    --manifest "$SCRIPT_DIR/app/src/main/AndroidManifest.xml" \
    --java "$BUILD_DIR/gen" \
    -o "$BUILD_DIR/base.apk" \
    "$BUILD_DIR/res.zip"

# 3. 编译 Java 源码
echo "[3/6] 编译 Java 源码 (javac)..."
JAVA_FILES=$(find "$SCRIPT_DIR/app/src/main/java" -name "*.java")
R_JAVA=$(find "$BUILD_DIR/gen" -name "R.java")

JAVAC_CP="$PLATFORM_JAR:$API_JAR:$BYTEHOOK_JAR"
if [ "$HAS_DEXKIT" = true ]; then
    JAVAC_CP="$JAVAC_CP:$DEXKIT_JAR:$KOTLIN_JAR:$FLATBUFFERS_JAR"
fi

javac -source 8 -target 8 -Xlint:-options \
    -cp "$JAVAC_CP" \
    -d "$BUILD_DIR/classes" \
    $JAVA_FILES $R_JAVA

# 4. 执行 R8 混淆/裁剪优化
echo "[4/6] 执行 R8 混淆与裁剪 (proguard-rules.pro)..."
CLASS_FILES=$(find "$BUILD_DIR/classes" -name "*.class")

R8_EXTRA_INPUTS="$BYTEHOOK_JAR"
if [ "$HAS_DEXKIT" = true ]; then
    R8_EXTRA_INPUTS="$R8_EXTRA_INPUTS $DEXKIT_JAR $KOTLIN_JAR $FLATBUFFERS_JAR"
fi

java -cp /data/data/com.termux/files/usr/share/java/d8.jar com.android.tools.r8.R8 \
    --release \
    --min-api 26 \
    --lib "$PLATFORM_JAR" \
    --classpath "$API_JAR" \
    --pg-conf "$SCRIPT_DIR/app/proguard-rules.pro" \
    --output "$BUILD_DIR/dex" \
    $CLASS_FILES $R8_EXTRA_INPUTS

# 5. 组装 APK 目录结构与 Native 库
echo "[5/6] 组装 APK 结构与 Native .so 库..."
# 解包 base.apk 中的 AndroidManifest.xml 与 resources.arsc
unzip -q -o "$BUILD_DIR/base.apk" -d "$BUILD_DIR/apk_root/"
# 注入 classes.dex 与 xposed_init
cp "$BUILD_DIR/dex/classes.dex" "$BUILD_DIR/apk_root/"
mkdir -p "$BUILD_DIR/apk_root/assets"
cp -f "$SCRIPT_DIR/app/src/main/assets/"* "$BUILD_DIR/apk_root/assets/"

# 检查 native 库
EXISTING_APK="/storage/emulated/0/0_TM/apks/QQ Enhanced Bypass_1.0.7.apk"
if [ -f "$EXISTING_APK" ]; then
    echo "  -> 提取 native .so 库基础依赖: $EXISTING_APK"
    unzip -q -o "$EXISTING_APK" "lib/*" -d "$BUILD_DIR/apk_root/"
fi

# 编译最新的 native-bypass 源码 (arm64-v8a)
if command -v clang++ >/dev/null 2>&1; then
    echo "  -> 本地源码编译 libnative-bypass.so (clang++ arm64-v8a)..."
    mkdir -p "$BUILD_DIR/bytehook_include" "$BUILD_DIR/apk_root/lib/arm64-v8a"
    BYTEHOOK_AAR="$LIBS_DIR/bytehook-1.0.2.aar"
    if [ -f "$BYTEHOOK_AAR" ]; then
        unzip -p "$BYTEHOOK_AAR" prefab/modules/bytehook/include/bytehook.h > "$BUILD_DIR/bytehook_include/bytehook.h"
        unzip -p "$BYTEHOOK_AAR" jni/arm64-v8a/libbytehook.so > "$BUILD_DIR/apk_root/lib/arm64-v8a/libbytehook.so"
    fi
    clang++ -shared -fPIC -std=c++17 -fno-exceptions -fno-rtti -fno-sized-deallocation -fno-threadsafe-statics -Wall -Wextra \
        -nostdlib++ -lc -lm -ldl \
        -I"$BUILD_DIR/bytehook_include" \
        -I"$SCRIPT_DIR/app/src/main/cpp" \
        "$SCRIPT_DIR/app/src/main/cpp/native-bypass.cpp" \
        "$SCRIPT_DIR/app/src/main/cpp/hooks/hook_libc.cpp" \
        "$SCRIPT_DIR/app/src/main/cpp/hooks/hook_libfekit.cpp" \
        "$SCRIPT_DIR/app/src/main/cpp/hooks/hook_libturingxq.cpp" \
        "$SCRIPT_DIR/app/src/main/cpp/hooks/hook_libmsf.cpp" \
        "$SCRIPT_DIR/app/src/main/cpp/hooks/hook_libqsec.cpp" \
        "$SCRIPT_DIR/app/src/main/cpp/hooks/hook_libmsfkernel.cpp" \
        "$SCRIPT_DIR/app/src/main/cpp/hooks/hook_libturingmfa.cpp" \
        "$SCRIPT_DIR/app/src/main/cpp/hooks/hook_libqimei.cpp" \
        "$SCRIPT_DIR/app/src/main/cpp/utils/log.cpp" \
        -L"$BUILD_DIR/apk_root/lib/arm64-v8a" -lbytehook \
        -llog -landroid -O2 \
        -o "$BUILD_DIR/apk_root/lib/arm64-v8a/libnative-bypass.so"
    if command -v llvm-strip >/dev/null 2>&1; then
        llvm-strip -s "$BUILD_DIR/apk_root/lib/arm64-v8a/libnative-bypass.so"
    fi
    if [ -f "/data/data/com.termux/files/usr/lib/libc++_shared.so" ]; then
        cp -f "/data/data/com.termux/files/usr/lib/libc++_shared.so" "$BUILD_DIR/apk_root/lib/arm64-v8a/libc++_shared.so"
    fi
    echo "  -> libnative-bypass.so 编译并瘦身成功"
fi

# 若为 DexKit 版本，注入 libdexkit.so
if [ "$HAS_DEXKIT" = true ] && [ -f "$DEXKIT_AAR" ]; then
    echo "  -> 注入 DexKit native 库 (libdexkit.so)"
    mkdir -p "$BUILD_DIR/apk_root/lib/arm64-v8a" "$BUILD_DIR/apk_root/lib/armeabi-v7a"
    unzip -p "$DEXKIT_AAR" jni/arm64-v8a/libdexkit.so > "$BUILD_DIR/apk_root/lib/arm64-v8a/libdexkit.so"
    unzip -p "$DEXKIT_AAR" jni/armeabi-v7a/libdexkit.so > "$BUILD_DIR/apk_root/lib/armeabi-v7a/libdexkit.so"
fi

# 6. 打包、对齐与签名
echo "[6/6] 打包、对齐与签名 APK (apksigner)..."
rm -f "$BUILD_DIR/unaligned.apk" "$BUILD_DIR/aligned.apk" "$TARGET_APK"
(cd "$BUILD_DIR/apk_root" && zip -r -q -0 -D "$BUILD_DIR/unaligned.apk" .)
python3 "$ZIPALIGN" "$BUILD_DIR/unaligned.apk" "$BUILD_DIR/aligned.apk"

apksigner sign \
    --ks "$KEYSTORE" \
    --ks-pass pass:android \
    --key-pass pass:android \
    --min-sdk-version 26 \
    --v1-signing-enabled true \
    --alignment-preserved true \
    --out "$TARGET_APK" \
    "$BUILD_DIR/aligned.apk"

echo "验证 APK 签名:"
apksigner verify --min-sdk-version 23 -v "$TARGET_APK" | grep -E "Verifies|scheme"

DEST_APK="/storage/emulated/0/0_TM/apks/QQ_Enhanced_Bypass_1.0.47_no_kick.apk"
if [ -d "$(dirname "$DEST_APK")" ]; then
    cp -f "$TARGET_APK" "$DEST_APK"
    echo "同步产物至存储空间: $DEST_APK"
fi
cp -f "$TARGET_APK" "/sdcard/QQ_Enhanced_Bypass_1.0.47_no_kick.apk"
echo "同步产物至 sdcard 根目录: /sdcard/QQ_Enhanced_Bypass_1.0.47_no_kick.apk"

echo
echo "=================================================="
echo "  构建成功！"
echo "  输出位置: $TARGET_APK"
echo "  文件大小: $(du -h "$TARGET_APK" | cut -f1)"
echo "=================================================="
