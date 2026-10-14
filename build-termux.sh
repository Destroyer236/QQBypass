#!/data/data/com.termux/files/usr/bin/bash
# ==============================================================================
# QQBypass Termux 本地构建脚本
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
    echo "[错误] 缺少依赖库，请检查 $LIBS_DIR"
    exit 1
fi

mkdir -p "$BUILD_DIR"
mkdir -p "$OUT_APK_DIR"

# 1. 编译资源
echo "[1/6] 编译资源文件 (aapt2 compile)..."
rm -rf "$BUILD_DIR/res.zip" "$BUILD_DIR/gen" "$BUILD_DIR/classes" "$BUILD_DIR/dex" "$BUILD_DIR/apk_root"
mkdir -p "$BUILD_DIR/gen" "$BUILD_DIR/classes" "$BUILD_DIR/dex" "$BUILD_DIR/apk_root"
aapt2 compile --dir "$SCRIPT_DIR/app/src/main/res" -o "$BUILD_DIR/res.zip"

# 2. 链接资源并生成 R.java
echo "[2/6] 链接资源与 Manifest (aapt2 link)..."
aapt2 link -I "$PLATFORM_JAR" \
    --manifest "$SCRIPT_DIR/app/src/main/AndroidManifest.xml" \
    --java "$BUILD_DIR/gen" \
    -o "$BUILD_DIR/base.apk" \
    "$BUILD_DIR/res.zip"

# 3. 编译 Java 源码
echo "[3/6] 编译 Java 源码 (javac)..."
JAVA_FILES=$(find "$SCRIPT_DIR/app/src/main/java" -name "*.java")
R_JAVA=$(find "$BUILD_DIR/gen" -name "R.java")
javac -source 8 -target 8 \
    -cp "$PLATFORM_JAR:$API_JAR:$BYTEHOOK_JAR" \
    -d "$BUILD_DIR/classes" \
    $JAVA_FILES $R_JAVA

# 4. 执行 R8 混淆/裁剪优化
echo "[4/6] 执行 R8 混淆与裁剪 (proguard-rules.pro)..."
CLASS_FILES=$(find "$BUILD_DIR/classes" -name "*.class")
java -cp /data/data/com.termux/files/usr/share/java/d8.jar com.android.tools.r8.R8 \
    --release \
    --min-api 26 \
    --lib "$PLATFORM_JAR" \
    --classpath "$API_JAR" \
    --pg-conf "$SCRIPT_DIR/app/proguard-rules.pro" \
    --output "$BUILD_DIR/dex" \
    $CLASS_FILES "$BYTEHOOK_JAR"

# 5. 组装 APK 目录结构与 Native 库
echo "[5/6] 组装 APK 结构与 Native .so 库..."
# 解包 base.apk 中的 AndroidManifest.xml 与 resources.arsc
unzip -q -o "$BUILD_DIR/base.apk" -d "$BUILD_DIR/apk_root/"
# 注入 classes.dex 与 xposed_init
cp "$BUILD_DIR/dex/classes.dex" "$BUILD_DIR/apk_root/"
mkdir -p "$BUILD_DIR/apk_root/assets"
cp "$SCRIPT_DIR/app/src/main/assets/xposed_init" "$BUILD_DIR/apk_root/assets/"

# 检查 native 库
if [ -d "$SCRIPT_DIR/build/termux/apk_root/lib" ]; then
    echo "  -> 继承已有 Native .so 库"
else
    # 提取预构建 APK 中的 .so 库
    EXISTING_APK="/storage/emulated/0/0_TM/apks/QQ Enhanced Bypass_1.0.7.apk"
    if [ -f "$EXISTING_APK" ]; then
        echo "  -> 从已有 APK 提取 native .so 库: $EXISTING_APK"
        unzip -q -o "$EXISTING_APK" "lib/*" -d "$BUILD_DIR/apk_root/"
    fi
fi

# 6. 打包、对齐与签名
echo "[6/6] 打包、对齐与签名 APK (apksigner)..."
rm -f "$BUILD_DIR/unaligned.apk" "$BUILD_DIR/aligned.apk" "$TARGET_APK"
(cd "$BUILD_DIR/apk_root" && zip -r -q -0 "$BUILD_DIR/unaligned.apk" .)
python3 "$ZIPALIGN" "$BUILD_DIR/unaligned.apk" "$BUILD_DIR/aligned.apk"

apksigner sign \
    --ks "$KEYSTORE" \
    --ks-pass pass:android \
    --key-pass pass:android \
    --out "$TARGET_APK" \
    "$BUILD_DIR/aligned.apk"

echo "验证 APK 签名:"
apksigner verify -v "$TARGET_APK" | grep -E "Verifies|scheme"

echo
echo "=================================================="
echo "  构建成功！"
echo "  输出位置: $TARGET_APK"
echo "  文件大小: $(du -h "$TARGET_APK" | cut -f1)"
echo "=================================================="
