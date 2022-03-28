#!/bin/bash
# Source: https://frida.re/docs/android/

adb root
adb shell 'kill -9 $(pidof frida-server)'  # Clean up any previous processes
adb shell "/data/local/tmp/frida-server &" &