#!/usr/bin/env python3
"""Build preload.so for OPPO Find X8 Ultra using NDK clang."""
import subprocess
import sys
import os
import hashlib

NDK = r"F:\Develop\android-ndk-r27d"
CLANG = os.path.join(NDK, r"toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe")
SYSROOT = os.path.join(NDK, r"toolchains\llvm\prebuilt\windows-x86_64\sysroot")
RESDIR = os.path.join(NDK, r"toolchains\llvm\prebuilt\windows-x86_64\lib\clang\18")
SRCDIR = r"G:\Develop\CVE-2026-43499\CyberMeowfia-src\IonStack\CVE-2026-43499\exploit"
OUT = os.path.join(SRCDIR, r"build\oppo-findx8ultra\bin\preload.so")

os.makedirs(os.path.dirname(OUT), exist_ok=True)

srcs = [
    os.path.join(SRCDIR, "src", "main.c"),
    os.path.join(SRCDIR, "src", "util.c"),
    os.path.join(SRCDIR, "src", "slide.c"),
    os.path.join(SRCDIR, "src", "fops.c"),
    os.path.join(SRCDIR, "src", "pipe.c"),
    os.path.join(SRCDIR, "src", "root.c"),
    os.path.join(SRCDIR, "src", "magica.c"),
    os.path.join(SRCDIR, "src", "umh_root.c"),
    os.path.join(SRCDIR, "src", "secureguard.c"),
    os.path.join(SRCDIR, "src", "perf_leak.c"),
    os.path.join(SRCDIR, "src", "preload.c"),
    os.path.join(SRCDIR, "src", "su_blob.S"),
    os.path.join(SRCDIR, "src", "wallpaper_blob.S"),
]

lib_aarch = os.path.join(SYSROOT, r"usr\lib\aarch64-linux-android\35")
lib_android = os.path.join(SYSROOT, r"usr\lib\aarch64-linux-android")

cmd = [
    CLANG,
    "-target", "aarch64-linux-android35",
    "--sysroot", SYSROOT,
    "-resource-dir", RESDIR,
    "--rtlib=compiler-rt",
    "--unwindlib=none",
    "-fPIC", "-O2", "-g0",
    "-Wall", "-Wextra",
    "-I" + os.path.join(SRCDIR, "src"),
    "-DTARGET_CONFIG_H=targets/oppo-findx8ultra/target.h",
    "-Wno-unused-parameter", "-Wno-sign-compare", "-Wno-unused-function",
    "-fuse-ld=lld",
    "-Wl,-rpath-link," + lib_aarch,
    "-L" + lib_aarch,
    "-L" + lib_android,
    "-shared", "-o", OUT, "-pthread",
] + srcs

print("CLANG:", CLANG)
print("CMD:", " ".join(cmd[:8]) + " ...")
print()

result = subprocess.run(cmd, capture_output=True, text=True)
print("STDOUT:", result.stdout[:2000] if result.stdout else "(empty)")
print("STDERR:", result.stderr[:4000] if result.stderr else "(empty)")
print("RC:", result.returncode)

if result.returncode == 0 and os.path.exists(OUT):
    sha = hashlib.sha256(open(OUT, "rb").read()).hexdigest()
    size = os.path.getsize(OUT)
    print(f"BUILD SUCCESS: {OUT}")
    print(f"Size: {size} bytes")
    print(f"SHA256: {sha}")
else:
    print("BUILD FAILED")
    sys.exit(1)
