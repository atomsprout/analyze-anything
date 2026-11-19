#!/bin/sh
# Rebuilds the fixtures in this folder. Needs: aapt, dalvik-exchange (dx), dexdump, apksigner,
# zipalign, keytool, javac, gcc, zip, python3 and an android.jar (Debian: apt-get install aapt
# apksigner zipalign dalvik-exchange dexdump android-sdk-platform-23 default-jdk-headless).
#
# Keys are generated on the spot and thrown away, so every run gives different signatures; the
# expected results in expected.tsv are what `apksigner verify` said for the files of that run.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ANDROID_JAR=${ANDROID_JAR:-/usr/lib/android-sdk/platforms/android-23/android.jar}
WORK=$(mktemp -d)
cd "$WORK"

# ---- the app -------------------------------------------------------------------------------
mkdir -p src/com/example/aafixture res/values res/values-zh res/xml assets lib/x86_64 lib/arm64-v8a
cat > AndroidManifest.xml <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.aafixture" android:versionCode="42" android:versionName="1.2.3">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="23" />
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.READ_CONTACTS" android:maxSdkVersion="22" />
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
    <uses-permission android:name="android.permission.INSTALL_PACKAGES" />
    <uses-permission android:name="com.example.aafixture.permission.OPEN" />
    <permission android:name="com.example.aafixture.permission.OPEN" android:protectionLevel="normal" />
    <permission android:name="com.example.aafixture.permission.SIGNED" android:protectionLevel="signature" />
    <uses-feature android:name="android.hardware.camera" android:required="true" />
    <application android:label="@string/app_name" android:name=".App" android:debuggable="true"
        android:allowBackup="true" android:usesCleartextTraffic="true"
        android:banner="@xml/network_security_config">
        <meta-data android:name="com.google.android.geo.API_KEY" android:value="AIzaSyD-FIXTURE-not-a-real-key-0123456789" />
        <meta-data android:name="com.facebook.sdk.ApplicationId" android:value="fb1234567890" />
        <activity android:name=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <activity android:name=".LinkActivity" android:exported="true">
            <intent-filter android:autoVerify="true">
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="https" android:host="fixture.example.com" android:pathPrefix="/open" />
                <data android:scheme="aafixture" />
            </intent-filter>
        </activity>
        <activity android:name=".HiddenActivity" android:exported="false" />
        <service android:name=".SyncService">
            <intent-filter><action android:name="com.example.aafixture.SYNC" /></intent-filter>
        </service>
        <service android:name=".A11yService" android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE" android:exported="true">
            <intent-filter><action android:name="android.accessibilityservice.AccessibilityService" /></intent-filter>
        </service>
        <receiver android:name=".BootReceiver" android:exported="true" android:permission="com.example.aafixture.permission.SIGNED" />
        <provider android:name=".OpenProvider" android:authorities="com.example.aafixture.open;com.example.aafixture.alt"
            android:exported="true" android:grantUriPermissions="true" />
        <provider android:name=".ClosedProvider" android:authorities="com.example.aafixture.closed" />
    </application>
</manifest>
XML
cat > res/values/strings.xml <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">AA Fixture</string>
    <string name="google_app_id">1:1234567890:android:abcdef0123456789</string>
    <string name="google_api_key">AIzaSyD-FIXTURE-resource-key-0123456789ab</string>
    <string name="firebase_database_url">https://aa-fixture.firebaseio.example</string>
</resources>
XML
cat > res/values-zh/strings.xml <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<resources><string name="app_name">分析样例</string></resources>
XML
cat > res/xml/network_security_config.xml <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors><certificates src="system" /><certificates src="user" /></trust-anchors>
    </base-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">legacy.example.com</domain>
    </domain-config>
    <domain-config>
        <domain>pinned.example.com</domain>
        <pin-set expiration="2030-01-01"><pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin></pin-set>
    </domain-config>
    <debug-overrides><trust-anchors><certificates src="user" /></trust-anchors></debug-overrides>
</network-security-config>
XML
cat > src/com/example/aafixture/App.java <<'JAVA'
package com.example.aafixture;

import java.security.cert.X509Certificate;
import javax.crypto.Cipher;
import javax.net.ssl.X509TrustManager;

public class App extends android.app.Application implements X509TrustManager {
    public native int nativeAnswer();

    public Object load(String path, ClassLoader parent) throws Exception {
        Cipher.getInstance("AES/ECB/PKCS5Padding");
        java.security.MessageDigest.getInstance("MD5");
        Runtime.getRuntime().exec("id");
        return new dalvik.system.DexClassLoader(path, null, null, parent);
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType) {}
    public void checkServerTrusted(X509Certificate[] chain, String authType) {}
    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
}
JAVA
cat > src/com/example/aafixture/MainActivity.java <<'JAVA'
package com.example.aafixture;

public class MainActivity extends android.app.Activity {
    public void web(android.webkit.WebView view) {
        view.getSettings().setJavaScriptEnabled(true);
        view.addJavascriptInterface(this, "fixture");
    }
}
JAVA
mkdir classes
javac -nowarn -source 8 -target 8 -bootclasspath "$ANDROID_JAR" -d classes src/com/example/aafixture/*.java 2>/dev/null
dalvik-exchange --dex --output=classes.dex classes
cp classes.dex assets/payload.dex
printf '\306\037\274\003\301\003\031\037\140\000\000\000fixture' > assets/index.android.bundle
# Two native libraries: one aligned for 16 KB pages, one for 4 KB only.
printf 'int fixture(void) { return 42; }\n' > lib.c
gcc -shared -nostdlib -o lib/x86_64/libfixture.so lib.c -Wl,-z,max-page-size=0x4000 -Wl,--build-id=none
gcc -shared -nostdlib -o lib/x86_64/libsmallpage.so lib.c -Wl,-z,max-page-size=0x1000 -Wl,--build-id=none
cp lib/x86_64/libfixture.so lib/arm64-v8a/libfixture.so

aapt package -f -M AndroidManifest.xml -S res -A assets -I "$ANDROID_JAR" -F base.apk
# aapt of platform 23 does not know android:networkSecurityConfig (API 24). The manifest was
# written with android:banner, another reference attribute, and its resource id is now
# replaced: banner is 0x010103f2, networkSecurityConfig is 0x01010527.
python3 - <<'PY'
import copy, zipfile, struct
src = zipfile.ZipFile('base.apk')
open('resources.arsc', 'wb').write(src.read('resources.arsc'))
open('network_security_config.bin', 'wb').write(src.read('res/xml/network_security_config.xml'))
out = zipfile.ZipFile('patched.apk', 'w')
for item in src.infolist():
    data = src.read(item.filename)
    if item.filename == 'AndroidManifest.xml':
        old, new = struct.pack('<I', 0x010103f2), struct.pack('<I', 0x01010527)
        assert data.count(old) == 1
        data = data.replace(old, new)
        open('AndroidManifest.bin', 'wb').write(data)
    out.writestr(copy.copy(item), data, compress_type=item.compress_type)
out.close()
PY
mv patched.apk base.apk
# The signed variants are made from a small package without native libraries; full.apk adds them.
zip -q -0 base.apk classes.dex
zipalign -f 4 base.apk unsigned.apk
zip -q -0 base.apk lib/x86_64/libfixture.so lib/x86_64/libsmallpage.so lib/arm64-v8a/libfixture.so
zipalign -f 4 base.apk full-unsigned.apk

# ---- keys ----------------------------------------------------------------------------------
key() { # name, keyalg, keysize, dname, sigalg
    keytool -genkeypair -keystore "$1.jks" -storepass password -keypass password -alias key -keyalg "$2" -keysize "$3" \
        -sigalg "$5" -dname "$4" -validity 10000 >/dev/null 2>&1
}
key rsa RSA 2048 "CN=AA Fixture, O=Analyze Anything, C=XX" SHA256withRSA
key ec EC 256 "CN=AA Fixture EC, O=Analyze Anything, C=XX" SHA256withECDSA
key debug RSA 2048 "CN=Android Debug, O=Android, C=US" SHA256withRSA
key weak RSA 1024 "CN=AA Weak Key, C=XX" SHA1withRSA
key dsa DSA 2048 "CN=AA Fixture DSA, C=XX" SHA256withDSA
key ec384 EC 384 "CN=AA Fixture P-384, C=XX" SHA384withECDSA
key rsa4096 RSA 4096 "CN=AA Fixture RSA 4096, C=XX" SHA512withRSA
KS="--ks-pass pass:password --key-pass pass:password --ks-key-alias key"
sign() { # output, keystore, extra flags...
    out=$1; ks=$2; shift 2
    apksigner sign --ks "$ks.jks" $KS "$@" --out "$out" unsigned.apk
}
sign v1.apk rsa --min-sdk-version 21 --v1-signing-enabled true --v2-signing-enabled false --v3-signing-enabled false
sign v1v2.apk rsa --min-sdk-version 21 --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled false
sign v1v2v3.apk rsa --min-sdk-version 21 --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true
sign v2-ec.apk ec --min-sdk-version 24 --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled false
sign v3-ec.apk ec --min-sdk-version 28 --v1-signing-enabled false --v2-signing-enabled false --v3-signing-enabled true
sign debug.apk debug --min-sdk-version 21 --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled false
sign weak.apk weak --min-sdk-version 21 --v1-signing-enabled true --v2-signing-enabled false --v3-signing-enabled false
# Other key types: DSA, EC P-384 and RSA 4096 (the last two make apksigner use SHA-512 digests).
sign dsa.apk dsa --min-sdk-version 21 --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled false
sign ec384.apk ec384 --min-sdk-version 21 --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true
sign rsa4096.apk rsa4096 --min-sdk-version 21 --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true
# Key rotation: rsa is the old key, ec the new one.
apksigner rotate --out lineage --old-signer --ks rsa.jks $KS --new-signer --ks ec.jks $KS
apksigner sign --ks rsa.jks $KS --next-signer --ks ec.jks $KS --lineage lineage --min-sdk-version 21 \
    --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true --out rotated.apk unsigned.apk
apksigner sign --ks rsa.jks $KS --min-sdk-version 21 --v1-signing-enabled true --v2-signing-enabled true \
    --v3-signing-enabled true --out full.apk full-unsigned.apk

# A split APK of the same app and signer, and an XAPK-style container holding base and split.
mkdir split
cat > split/AndroidManifest.xml <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.aafixture" android:versionCode="42" split="config.fixture">
    <application android:hasCode="false" />
</manifest>
XML
aapt package -f -M split/AndroidManifest.xml -I "$ANDROID_JAR" -F split/unsigned.apk
apksigner sign --ks rsa.jks $KS --min-sdk-version 21 --v1-signing-enabled true --v2-signing-enabled true \
    --v3-signing-enabled false --out split/config.fixture.apk split/unsigned.apk
mkdir xapk
cp v1v2.apk xapk/com.example.aafixture.apk
cp split/config.fixture.apk xapk/config.fixture.apk
printf '{"xapk_version":2,"package_name":"com.example.aafixture","version_code":"42","split_apks":[{"file":"com.example.aafixture.apk","id":"base"},{"file":"config.fixture.apk","id":"config.fixture"}]}\n' > xapk/manifest.json
(cd xapk && zip -q -0 ../set.xapk manifest.json com.example.aafixture.apk config.fixture.apk)

# ---- tampered copies -----------------------------------------------------------------------
python3 - <<'PY'
import struct, zipfile, warnings

def read(p): return bytearray(open(p, 'rb').read())
def write(p, d): open(p, 'wb').write(bytes(d))

def eocd(d):
    at = d.rfind(b'PK\x05\x06')
    return at, struct.unpack_from('<I', d, at + 16)[0]

def data_offset(d, name):
    """Offset of the data of entry `name`."""
    at, cd = eocd(d)
    pos = cd
    while d[pos:pos + 4] == b'PK\x01\x02':
        n, e, c = struct.unpack_from('<HHH', d, pos + 28)
        lfh = struct.unpack_from('<I', d, pos + 42)[0]
        if d[pos + 46:pos + 46 + n] == name:
            ln, le = struct.unpack_from('<HH', d, lfh + 26)
            return lfh + 30 + ln + le
        pos += 46 + n + e + c
    raise KeyError(name)

# One byte of an entry's data changed (classes.dex is stored, not compressed).
for src in ('v1', 'v1v2', 'v1v2v3', 'v3-ec'):
    d = read(src + '.apk')
    d[data_offset(d, b'classes.dex') + 0x40] ^= 0xff
    write(src + '-entry-modified.apk', d)

# Data appended after the end record.
d = read('v1v2.apk'); d += b'appended'; write('v1v2-appended.apk', d)
d = read('v1.apk'); d += b'appended'; write('v1-appended.apk', d)

# One byte inside the signing block changed.
d = read('v1v2.apk')
at, cd = eocd(d)
size = struct.unpack_from('<Q', d, cd - 24)[0]
start = cd - size - 8
d[start + 200] ^= 0x01
write('v1v2-block-modified.apk', d)

# The signing block removed: a v1+v2 file made to look v1-only.
d = read('v1v2.apk')
at, cd = eocd(d)
size = struct.unpack_from('<Q', d, cd - 24)[0]
start = cd - size - 8
stripped = d[:start] + d[cd:]
struct.pack_into('<I', stripped, at - (cd - start) + 16, start)
write('v1v2-stripped.apk', stripped)

# Janus: a DEX in front of a v1-signed APK, with every offset moved accordingly.
d = read('v1.apk')
dex = open('classes.dex', 'rb').read()
shift = len(dex)
at, cd = eocd(d)
pos = cd
while d[pos:pos + 4] == b'PK\x01\x02':
    n, e, c = struct.unpack_from('<HHH', d, pos + 28)
    struct.pack_into('<I', d, pos + 42, struct.unpack_from('<I', d, pos + 42)[0] + shift)
    pos += 46 + n + e + c
struct.pack_into('<I', d, at + 16, cd + shift)
write('v1-janus.apk', dex + bytes(d))

# Duplicate entry names and a local header that disagrees with the central directory (unsigned).
warnings.simplefilter('ignore')
z = zipfile.ZipFile('zip-tricks.apk', 'w')
src = zipfile.ZipFile('unsigned.apk')
z.writestr('AndroidManifest.xml', src.read('AndroidManifest.xml'))
z.writestr('resources.arsc', src.read('resources.arsc'))
z.writestr('classes.dex', b'not the real one')
z.writestr('classes.dex', src.read('classes.dex'))
z.writestr('assets/renamed.txt', b'hello')
z.close()
d = read('zip-tricks.apk')
lfh = d.find(b'assets/renamed.txt')
d[lfh:lfh + 6] = b'ASSETS'
write('zip-tricks.apk', d)
PY

# ---- expected results, from the reference tools --------------------------------------------
# file <TAB> apksigner verify succeeded (yes/no) <TAB> v1 <TAB> v2 <TAB> v3 <TAB> signer #1 certificate SHA-256
# v2-ec and v3-ec have no v1 signature, so they verify only for the Android versions that know
# their scheme; the manifest's minSdkVersion 21 is overridden for them.
SIGNED="v1 v1v2 v1v2v3 v2-ec v3-ec debug weak dsa ec384 rsa4096 rotated full v1-entry-modified v1v2-entry-modified v1v2v3-entry-modified
 v3-ec-entry-modified v1v2-appended v1-appended v1v2-block-modified v1v2-stripped v1-janus"
: > expected.tsv
for f in $SIGNED; do
    case $f in v2-ec*) min="--min-sdk-version 24" ;; v3-ec*) min="--min-sdk-version 28" ;; *) min="" ;; esac
    if out=$(apksigner verify $min --verbose --print-certs "$f.apk" 2>&1); then ok=yes; else ok=no; fi
    field() { printf '%s\n' "$out" | sed -n "s/^Verified using $1 scheme ([^)]*): //p" | head -1; }
    sha=$(printf '%s\n' "$out" | sed -n 's/^Signer #1 certificate SHA-256 digest: //p' | head -1)
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$f.apk" "$ok" "$(field v1)" "$(field v2)" "$(field v3)" "$sha" >> expected.tsv
    printf '%s\n' "$out" | grep -v '^Picked up\|^WARNING: META-INF' > "$f.apksigner.txt" || true
done
aapt dump badging full.apk > badging.txt
aapt dump xmltree full.apk AndroidManifest.xml > xmltree.txt
dexdump -f classes.dex | sed -n '/^DEX file header/,/^$/p' > dexdump-header.txt

for f in $SIGNED unsigned zip-tricks; do cp "$f.apk" "$HERE/"; done
cp set.xapk "$HERE/"
for f in $SIGNED; do cp "$f.apksigner.txt" "$HERE/"; done
cp expected.tsv badging.txt xmltree.txt dexdump-header.txt AndroidManifest.bin resources.arsc network_security_config.bin classes.dex "$HERE/"
echo "fixtures written to $HERE; scratch files are in $WORK"
