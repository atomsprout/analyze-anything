#!/bin/sh
# Rebuilds every fixture in this folder. Needs: mingw-w64, osslsigncode (>= 2.6), openssl, nsis,
# wixl + msitools, gcab, p7zip-full, cabextract, python3.
#
#   apt-get install -y mingw-w64 osslsigncode nsis wixl msitools gcab p7zip-full cabextract
#
# Keys and certificates are generated on the spot and thrown away, so every run produces
# different signatures. The reference tools' output is stored next to each fixture (*.ref.txt)
# and the tests compare the analyzer's results with those files.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
cp "$here"/src/* .

# --- a small PE with a version resource and a manifest -------------------------------------
x86_64-w64-mingw32-windres hello.rc -O coff -o hello.res
x86_64-w64-mingw32-gcc -Os -s -o hello.exe hello.c hello.res -lws2_32 -ladvapi32
cp hello.exe "$here/hello.exe"

# --- a throwaway PKI: root, RSA and ECDSA code-signing leaves, a timestamp authority ---------
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 7300 \
  -subj "/C=XX/O=Fixture Works/CN=Fixture Test Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
leaf() { # name keyspec subject eku
  openssl req -newkey "$2" -nodes -keyout "$1.key" -out "$1.csr" -subj "$3" 2>/dev/null
  printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%s\n' "$4" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -out "$1.crt" -days 3650 -sha256 -extfile "$1.ext" 2>/dev/null
  cat "$1.crt" ca.crt > "$1-chain.pem"
}
leaf leaf rsa:2048 "/C=XX/O=Fixture Works/CN=Fixture Code Signing" codeSigning
openssl ecparam -name prime256v1 -out p256.param
leaf ecleaf ec:p256.param "/C=XX/O=Fixture Works/CN=Fixture EC Signing" codeSigning
leaf tsa rsa:2048 "/C=XX/O=Fixture Works/CN=Fixture Timestamp Authority" critical,timeStamping
openssl req -x509 -newkey rsa:2048 -nodes -keyout self.key -out self.crt -days 3650 \
  -subj "/CN=Fixture Self Signed" -addext "extendedKeyUsage=codeSigning" 2>/dev/null

# Signing happens "one day from now", inside the certificates' validity.
when=$(( $(date +%s) + 86400 ))
tsa="-TSA-certs tsa-chain.pem -TSA-key tsa.key -TSA-time $when"
sign() { osslsigncode sign -time "$when" "$@" >/dev/null; }
sign -certs leaf-chain.pem -key leaf.key -h sha256 -n "Hello Fixture" -i https://example.invalid/hello $tsa -in hello.exe -out hello-signed.exe
sign -certs leaf-chain.pem -key leaf.key -h sha1 -in hello.exe -out hello-sha1.exe
sign -certs leaf-chain.pem -key leaf.key -h sha256 -nest $tsa -in hello-sha1.exe -out hello-dual.exe
sign -certs ecleaf-chain.pem -key ecleaf.key -h sha384 -in hello.exe -out hello-ecdsa.exe
sign -certs self.crt -key self.key -h sha256 -in hello.exe -out hello-selfsigned.exe
for name in hello-signed hello-sha1 hello-dual hello-ecdsa hello-selfsigned; do
  cp "$name.exe" "$here/$name.exe"
  osslsigncode verify -CAfile ca.crt -TSA-CAfile ca.crt -in "$name.exe" > "$here/$name.ref.txt" 2>&1 || true
done

# --- installers -----------------------------------------------------------------------------
printf 'Fixture readme.\n' > readme.txt
python3 -c "import sys; sys.stdout.buffer.write(bytes((i * 7 + i // 256) % 256 for i in range(20000)))" > payload.bin
nsis() { # output compressor solid unicode
  makensis -V1 -DOUT="$1" -DCOMPRESSOR="$2" -DSOLID="$3" -DUNICODE_TARGET="$4" installer.nsi
  cp "$1" "$here/$1"
  7z l -slt "$1" > "$here/${1%.exe}.ref.txt"
  mkdir "x-$1" && (cd "x-$1" && 7z x -y "../$1" >/dev/null && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum) >> "$here/${1%.exe}.ref.txt"
}
nsis nsis-zlib.exe zlib 0 true
nsis nsis-lzma-solid.exe lzma 1 true
nsis nsis-bzip2-ansi.exe bzip2 1 false

wixl -o fixture.msi product.wxs
cp fixture.msi "$here/fixture.msi"
{
  for table in Property File Component Directory Registry ServiceInstall CustomAction Shortcut Environment LaunchCondition; do
    echo "== $table"; msiinfo export fixture.msi "$table" 2>/dev/null || true
  done
  echo "== files"
  mkdir x-msi && (cd x-msi && msiextract ../fixture.msi >/dev/null && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum)
} > "$here/fixture.msi.ref.txt"

mkdir cabsrc && cp readme.txt payload.bin hello.exe cabsrc/
(cd cabsrc && gcab -c -z ../fixture.cab readme.txt payload.bin hello.exe)
cp fixture.cab "$here/fixture.cab"
(mkdir x-cab && cd x-cab && cabextract -q ../fixture.cab && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum) > "$here/fixture.cab.ref.txt"

python3 make-asar.py "$here/fixture.asar"

# A self-extracting archive in shape only: a PE stub with a 7z archive appended.
7z a -bso0 inner.7z readme.txt payload.bin
cat hello.exe inner.7z > "$here/sfx-7z.exe"
sha256sum readme.txt payload.bin > "$here/sfx-7z.ref.txt"
