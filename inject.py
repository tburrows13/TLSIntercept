#! /usr/local/Caskroom/miniconda/base/bin/python

import time
import datetime
import sys
from pathlib import Path

import frida

PROCESS_NAME = sys.argv[1]
SCRIPT_FILE = sys.argv[2] + '.js'

"""
python inject.py com.tpmb4.partiiproject conscrypt
python inject.py org.thoughtcrime.securesms conscrypt
python inject.py org.telegram.messenger.web conscrypt
python inject.py com.whatsapp conscrypt
python inject.py com.facebook.orca conscrypt
"""

def current_time():
    return datetime.datetime.now().replace(microsecond=0).isoformat()

log_file_name = current_time() + '.log'
log_file = Path('logs') / log_file_name
with open(log_file, 'w') as file:
    file.write(PROCESS_NAME + '\n')


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


def on_message(message, data):
    with open(log_file, 'a') as file:
        file.write('-' * 120 + '\n' + current_time() + '\n')
        if message['type'] == 'send':
            payload = message['payload']
            file.write(str(payload) + '\n')

            #decode(payload)
            #print("[*] {0}".format(message['payload']))
        elif message['type'] == 'error':
            #print(message['description'])
            file.write('ERROR' + '\n' + message['stack'] + '\n')
            #print(message['stack'])
            #print(message['fileName'])
            #print(f"{message['lineNumber']}:{message['columnNumber']}")
        else:
            file.write(str(message) + '\n')

script.on('message', on_message)

script.load()
device.resume(pid)
print("Script loaded")

input()