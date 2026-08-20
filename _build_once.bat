@echo off
setlocal
set NDK=F:\Develop\android-ndk-r27d
set CC=%NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android35-clang.cmd
set SYSROOT=%NDK%\toolchains\llvm\prebuilt\windows-x86_64\sysroot
set RESDIR=%NDK%\toolchains\llvm\prebuilt\windows-x86_64\lib\clang\18
set OUT=build\oppo-findx8ultra\bin\preload.so
cd /d "G:\Develop\CVE-2026-43499\CyberMeowfia-src\IonStack\CVE-2026-43499\exploit"
if not exist build\oppo-findx8ultra\bin mkdir build\oppo-findx8ultra\bin
echo BUILDING...
"%CC%" --target=aarch64-linux-android35 --sysroot="%SYSROOT%" -resource-dir "%RESDIR%" --rtlib=compiler-rt --unwindlib=none -fPIC -O2 -g0 -Wall -Wextra -Isrc -DTARGET_CONFIG_H=\"targets/oppo-findx8ultra/target.h\" -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function src\main.c src\util.c src\slide.c src\fops.c src\pipe.c src\root.c src\umh_root.c src\secureguard.c src\perf_leak.c src\preload.c src\su_blob.S src\wallpaper_blob.S -fuse-ld=lld -Wl,-rpath-link,"%SYSROOT%\usr\lib\aarch64-linux-android\35" -L"%SYSROOT%\usr\lib\aarch64-linux-android\35" -L"%SYSROOT%\usr\lib\aarch64-linux-android" -shared -o %OUT% -pthread
echo EXIT=%ERRORLEVEL%
if errorlevel 1 exit /b 1
echo BUILD SUCCESS
certutil -hashfile %OUT% SHA256
dir %OUT%
