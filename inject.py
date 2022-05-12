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

from process_data import process_data


PROCESS_NAME = sys.argv[1].lower() if len(sys.argv) > 1 else 'test'
SCRIPT_FILE = (sys.argv[2].lower() if len(sys.argv) > 2 else 'conscrypt') + '.js'
TEST_NAME = sys.argv[3] if len(sys.argv) > 3 else 'test'

processes = {
    'signal': 'org.thoughtcrime.securesms',
    'whatsapp': 'com.whatsapp',
    'messenger': 'com.facebook.orca',
    'telegram': 'org.telegram.messenger.web',
    'wire': 'com.wire',
    'test': 'com.interceptiontest',
}

if PROCESS_NAME in processes.keys():
    PROCESS_NAME = processes[PROCESS_NAME]

print(PROCESS_NAME, SCRIPT_FILE)
def current_time(ms=False):
    now = datetime.datetime.now()
    if not ms:
        now = now.replace(microsecond=0)
    return now.isoformat()

log_folder = Path('logs') / f"{TEST_NAME}-{current_time()}-{PROCESS_NAME}"
os.makedirs(log_folder)

log_file_name = current_time() + '-timeline.log'
log_file = log_folder / log_file_name
with open(log_file, 'w') as file:
    file.write(f'{PROCESS_NAME}, {SCRIPT_FILE}\n')


device = frida.get_usb_device()
try:
    pid = device.spawn([PROCESS_NAME])
except frida.NotSupportedError:
    # Give run.sh a chance to restart the frida server
    time.sleep(3)
    pid = device.spawn([PROCESS_NAME])

time.sleep(1)  # Without it Java.perform silently fails
session = device.attach(pid)
#session = device.attach("Signal")


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


def write_log(message, time=None):
    if not time:
        time = current_time(ms=True)
    with open(log_file, 'a') as file:
        file.write('-' * 120 + '\n' + time + '\n' + message + '\n')


def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        if payload['TYPE'] == 'data':
            time = current_time(ms=True)
            with open(log_folder / f"{time}-{payload['STREAM_ID']}-{payload['DIRECTION']}-raw.hex", 'w+b') as file:
                file.write(data)
            info, processed_data = process_data(data)
            if processed_data:
                with open(log_folder / f"{time}-{payload['STREAM_ID']}-{payload['DIRECTION']}-processed.txt", 'w+') as file:
                    file.write(str(processed_data))
            
            write_log(str({**payload, **info}), time=time)

        elif payload['TYPE'] == 'combined-data':
            with open(log_folder / f"combined-{payload['STREAM_ID']}-{payload['DIRECTION']}.hex", 'w+b') as file:
                file.write(data)
            info, processed_data = process_data(data)
            if processed_data:
                with open(log_folder / f"combined-{payload['STREAM_ID']}-{payload['DIRECTION']}-processed.txt", 'w+') as file:
                    file.write(str(processed_data))

            write_log(str({**payload, **info}))
        
        else:
            write_log(str(payload))

    elif message['type'] == 'error':
        write_log(message['stack'])
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