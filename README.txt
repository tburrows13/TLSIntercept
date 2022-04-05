To use:

Install and run Android Studio. From 'Device Manager' create and emulator.
I'm using emulated Pixel 3 with Android 10 Q (API 29), x86, 'Google APIs'. Do not use 'Google Play' images because they do not allow root access.

Continue once the emulator is running. Should also work with a connected and rooted phone, but I've not yet tested this.

One-time setup: (installs frida 14.2.18 because I found 15.1.14 to be very unstable)
$ ./install.sh

After each device reboot:
$ ./run.sh

Modify constants in inject.py, then run injection:
$ python inject.py <process> <script>

<script> defaults to 'conscrypt'