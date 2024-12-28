# TLS Intercept for Android messaging apps
### Tom Burrows

A tool for intercepting TLS-encrypted traffic originating from messaging apps on Android phones. Uses [Frida](https://frida.re/) to overwrite system TLS libraries so that when an app encrypts a TLS communication using these system libraries, this tool can intercept and log/process the communication as well. This can be used to discover privacy leaks in these messaging apps.

Demonstrations of the tool's output can be viewed [here](https://github.com/tburrows13/TLSIntercept/tree/master/logs).

Created as part of my Part II (final year) dissertation for the Cambridge Computer Science Tripos. The complete dissertation can be viewed [here](https://github.com/tburrows13/TLSIntercept/blob/master/Dissertation.pdf).

## To use

Install and run Android Studio. From 'Device Manager' create and emulator.

I'm using emulated Pixel 3 with Android 10 Q (API 29), x86, 'Google APIs'. Do not use 'Google Play' images because they do not allow root access.

Continue once the emulator is running. Also works with a physical phone, once rooted.

One-time setup: (installs frida 14.2.18 because I found 15.1.14 to be very unstable)

`$ ./install.sh`

After each device reboot:

`$ ./run.sh`

Run injection:

`$ python inject.py <process> <script>`

`<process>` can be the full name (e.g. `'org.thoughtcrime.securesms'`) or a shorthand (e.g. `'signal'`)

`<script>` defaults to `'conscrypt'`
