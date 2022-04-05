#!/bin/bash
# Source: https://frida.re/docs/android/

pip install frida==14.2.18 frida-tools==9.2.5

wget https://github.com/frida/frida/releases/download/14.2.18/frida-server-14.2.18-android-x86.xz
mv frida-server-14.2.18-android-x86.xz frida-server.xz
unxz frida-server.xz

adb root
sleep 5
adb push frida-server /data/local/tmp
adb shell "chmod 755 /data/local/tmp/frida-server"
