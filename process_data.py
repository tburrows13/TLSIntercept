def process_data(data):
    info = {}
    for i in range(len(data) // 2):
        sub_data = data[i:]
        try:
            decoded_data = sub_data.decode()
        except UnicodeDecodeError:
            continue
        for method in ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH']:
            if method in decoded_data:
                info['HTTP_METHOD'] = method
        return info, decoded_data
