import json
import base64, binascii

import blackboxprotobuf

with open('wordlist.txt') as file:
    WORDLIST = file.read().split()

def detect_http(data, info):
    for method in ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH']:
        if method in data:
            info['HTTP_METHOD'] = method

def decode_as_json(data):
    try:
        json_data = json.loads(data)
    except json.decoder.JSONDecodeError:
        return
    for key, value in json_data.items():
        b64_value = decode_as_b64(str(value))
        if b64_value:
            json_data[key] = b64_value
    return json_data

def decode_as_b64(data):
    try:
        b64_data = base64.b64decode(data, validate=True).decode()
    except (binascii.Error, UnicodeDecodeError):
        return
    return b64_data

def decode_as_protobuf(data):
    try:
        protobuf_data, typedef = blackboxprotobuf.protobuf_to_json(data)
    except:
        # Decoding can raise many different types of exceptions when the data is invalid
        return

    return str(protobuf_data) + '\n' + str(typedef)

def decode_data(data):
    info = {}

    # Attempt to decode the raw data as a ProtoBuf
    protobuf_data = decode_as_protobuf(data)
    if protobuf_data:
        info["PROTOBUF"] = True
        return info, protobuf_data

    # Remove null bytes from the end
    for i in range(len(data)):
        if data[len(data) - i - 1] != 0:
            data = data[:len(data) - i]
            break

    protobuf_data = decode_as_protobuf(data)
    if protobuf_data:
        info["PROTOBUF"] = True
        return info, protobuf_data

    # Decode the data as UTF-8 before further attempts
    first_decoding = None
    for i in range(len(data) // 2):
        sub_data = data[i:]
        try:
            decoded_data = sub_data.decode()
        except UnicodeDecodeError:
            continue

        first_decoding = first_decoding or decoded_data
        detect_http(decoded_data, info)

        b64_data = decode_as_b64(decoded_data)
        if b64_data:
            info['BASE64'] = True
            b64_info, b64_data = decode_data(b64_data)
            info = {**b64_info, **info}
            return info, b64_data

        json_data = decode_as_json(decoded_data)
        if json_data:
            info['JSON'] = True
            return info, json_data

    return info, first_decoding

def process_data(data):
    count = {'PRINTABLE': 0, 'NULL': 0, 'OTHER': 0}
    for char in data:
        if 32 <= char < 127 or char == 10 or char == 13:
            count['PRINTABLE'] = count['PRINTABLE'] + 1
        elif char == 0:
            count['NULL'] = count['NULL'] + 1
        else:
            count['OTHER'] = count['OTHER'] + 1
    info, decoded_data = decode_data(data)

    info['COUNT'] = count

    data_alerts = []
    if decoded_data:
        # Search for interesting strings
        decoded_string = str(decoded_data).lower()
        for string in WORDLIST:
            if string in decoded_string:
                data_alerts.append(string)
                print('Found string:', string)

    if data_alerts:
        info['DATA_ALERTS'] = data_alerts
    return info, decoded_data