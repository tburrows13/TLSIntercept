#! /usr/local/Caskroom/miniconda/base/bin/python
"""
python inject.py <process> <script>
Default script is 'conscrypt'.

Example usage:
python inject.py signal
python inject.py whatsapp
python inject.py messenger
python inject.py telegram
python inject.py tpmb4

Or use full process name:
python inject.py org.thoughtcrime.securesms

`frida-ps -U` outputs all process names.
Frida 15 seems to use 'titles' instead of process names (e.g. Signal instead of org.thoughtcrime.securesms).
"""

import time
import os
import datetime
import sys
import json
from pathlib import Path

import frida


PROCESS_NAME = sys.argv[1]
SCRIPT_FILE = (sys.argv[2] if len(sys.argv) > 2 else 'conscrypt') + '.js'

processes = {
    'signal': 'org.thoughtcrime.securesms',
    'whatsapp': 'com.whatsapp',
    'messenger': 'com.facebook.orca',
    'telegram': 'org.telegram.messenger.web',
    'tpmb4': 'com.tpmb4.partiiproject',
}

if PROCESS_NAME in processes.keys():
    PROCESS_NAME = processes[PROCESS_NAME]

print(PROCESS_NAME, SCRIPT_FILE)
def current_time(ms=False):
    now = datetime.datetime.now()
    if not ms:
        now = now.replace(microsecond=0)
    return now.isoformat()

log_folder = Path('logs') / f"{current_time()}-{PROCESS_NAME}"
os.makedirs(log_folder)

log_file_name = current_time() + '.log'
log_file = log_folder / log_file_name
with open(log_file, 'w') as file:
    file.write(f'{PROCESS_NAME}, {SCRIPT_FILE}\n')


device = frida.get_usb_device()
pid = device.spawn([PROCESS_NAME])
time.sleep(1)  # Without it Java.perform silently fails
session = device.attach(pid)
#session = device.attach("org.telegram.messenger.web")


with open(SCRIPT_FILE) as f:
    script = session.create_script(f.read())


def decode(bytes):
    print("=" * 100)
    print(f"{len(bytes)} bytes")
    s = ""
    for byte in bytes:
        s += chr(byte)
    print(s)
    print("=" * 100)


def write_log(message):
    with open(log_file, 'a') as file:
        file.write('-' * 120 + '\n' + current_time() + '\n' + message + '\n')


def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        #payload = json.loads(payload)
        write_log(str(payload))
        if payload['type'] == 'data':
            with open(log_folder / f"{current_time(ms=True)}-{payload['hashCode']}-{payload['direction']}.hex", 'w+b') as file:
                file.write(data)
        elif payload['type'] == 'combined-data':
            with open(log_folder / f"combined-{payload['hashCode']}-{payload['direction']}.hex", 'w+b') as file:
                file.write(data)

        #decode(payload)
        #print("[*] {0}".format(message['payload']))
    elif message['type'] == 'error':
        #print(message['description'])
        write_log(message['stack'])
        #print('JavaScript Error:' + '\n' + message['stack'])
        #print(message['stack'])
        #print(message['fileName'])
        #print(f"{message['lineNumber']}:{message['columnNumber']}")
    else:
        write_log(str(message))

script.on('message', on_message)

script.load()
device.resume(pid)
print("Script loaded")

try:
    input()
except KeyboardInterrupt:
    pass
print('Exiting...')