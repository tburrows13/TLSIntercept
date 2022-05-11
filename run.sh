#!/bin/bash
# Source: https://frida.re/docs/android/

adb root

if adb shell "pidof frida-server" ; then
  # Clean up any previous processes
  adb shell 'kill -9 $(pidof frida-server)'
fi

while true; do
  if ! adb shell "pidof frida-server" > /dev/null ; then
    echo "Restarting frida-server"
    adb shell "/data/local/tmp/frida-server &"
  fi
  sleep 5
done