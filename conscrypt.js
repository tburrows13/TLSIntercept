var data = {};

function saveData(byteArray, offset, byteCount, hashCode, direction) {
  var intArray = byteArrayToIntArray(byteArray, offset, byteCount);
  if (hashCode in data) {
    data[hashCode] = data[hashCode].concat(intArray);
  } else {
    data[hashCode] = intArray;
  };
  send(
    {
      type: 'data',
      direction: direction,
      hashCode: hashCode,
      byteCount: byteCount,
    },
    intArray
  );

  send(
    {
      type: 'combined-data',
      direction: direction,
      hashCode: hashCode,
    },
    data[hashCode]
  );
}

function byteArrayToIntArray(array, offset, length) {
  var result = [];
  for (var i = offset; i < offset + length; ++i) {
      result.push(
          parseInt(
              ('0' + (array[i] & 0xFF).toString(16)).slice(-2), // binary2hex part
              16
          )
      );
  }
  return result;
}

function binaryToHexToAscii(array, length) {
  var result = [];
  for (var i = 0; i < length; ++i) {
      result.push(String.fromCharCode( // hex2ascii part
          parseInt(
              ('0' + (array[i] & 0xFF).toString(16)).slice(-2), // binary2hex part
              16
          )
      ));
  }
  return result.join('');
}


function processData(byteArray, offset, byteCount, outputStream, direction) {
  var decoded = binaryToHexToAscii(byteArray, byteCount);
  //console.log(`OutputStream-${outputStream.hashCode()} writing ${decoded.length}:\n${'-'.repeat(100)}\n${decoded}\n${'-'.repeat(100)}`);

  // Perform analysis
  var info = {}
  info['type'] = 'info'
  info['direction'] = direction
  info['STREAM_ID'] = outputStream.hashCode();

  var ascii = 0;
  var notAscii = 0;
  var nullChar = 0;
  for (var i=0; i < decoded.length; i++) {
    var charCode = decoded.charCodeAt(i);
    if ((32 <= charCode && charCode < 127) || charCode === 10 || charCode === 13) {
      // Checks if character is a printable ASCII character, or LF/CR
      ascii++;
    } else if (charCode === 0) {
      nullChar++;
    } else {
      notAscii++;
    }
  }
  info['ASCII_COUNT'] = ascii;
  info['NOT_ASCII_COUNT'] = notAscii;
  info['NULL_COUNT'] = nullChar;

  for (let method of ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH']) {
    if (decoded.startsWith(method)) {
      info['HTTP_METHOD'] = method;
    }
  }

  Java.perform(function() {
    info['STACK_TRACE'] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())
  });

  //var message = JSON.stringify(info) + '\n' + decoded;

  send(info);

  saveData(byteArray, offset, byteCount, outputStream.hashCode(), direction);
  //send("Outputstream to python!")
}


Java.perform(() => {
  //Java.deoptimizeEverything();

  console.log("Starting javascript");
  console.log(`Android version: ${Java.androidVersion}`);

  const ActivityThread = Java.use('android.app.ActivityThread');
  const processName = ActivityThread.currentProcessName();

  if (processName === 'org.thoughtcrime.securesms') {
    // Signal refers to conscrypt by a different name
    var conscrypt_id = 'org.conscrypt';
  } else {
    var conscrypt_id = 'com.android.org.conscrypt';
  }

  /*
  "$init(java.lang.String, int, java.net.InetAddress, int, org.conscrypt.SSLParametersImpl): void",
  "$init(java.lang.String, int, org.conscrypt.SSLParametersImpl): void",
  "$init(java.net.InetAddress, int, java.net.InetAddress, int, org.conscrypt.SSLParametersImpl): void",
  "$init(java.net.InetAddress, int, org.conscrypt.SSLParametersImpl): void",
  "$init(java.net.Socket, java.lang.String, int, boolean, org.conscrypt.SSLParametersImpl): void",
  "$init(org.conscrypt.SSLParametersImpl): void",
  */
  
  /*const Socket = Java.use(conscrypt_id + '.ConscryptFileDescriptorSocket');

  for (const init of Socket.$init.overloads) {
    // Socket socket, String hostname, int port, boolean autoClose, SSLParametersImpl sslParameters
    init.implementation = function(a, b, c, d, e) {
      //console.log(`Socket-${this.hashCode()} created (${a})`);
      // Socket[address=chat.signal.org/76.223.92.165,port=443,localPort=38674] chat.signal.org 443 true org.conscrypt.SSLParametersImpl@11aaa25
      return this.$init(a, b, c, d, e);
    }
  }

  Socket.getOutputStream.implementation = function() {
    var outputStream = this.getOutputStream();
    //console.log(`Socket-${this.hashCode()} Getting output stream, hashCode=${outputStream.hashCode()}`);
    return outputStream;      
  }

  /*for (const init of OutputStream.$init.overloads) {
    init.implementation = function(a, b, c) {
      console.log(`OutputStream-${this.hashCode()} created`, a, b, c);
      return this.$init(a, b, c);
    }
  }*/

  const OutputStream = Java.use(conscrypt_id + '.ConscryptFileDescriptorSocket$SSLOutputStream');
  OutputStream.write.overload('[B', 'int', 'int').implementation = function(byteArray, offset, byteCount) {
    console.log('FileDescriptorSocket Output');
    processData(byteArray, offset, byteCount, this, 'sent');
    this.write(byteArray, offset, byteCount);
  }

  const InputStream = Java.use(conscrypt_id + '.ConscryptFileDescriptorSocket$SSLInputStream');
  InputStream.read.overload('[B', 'int', 'int').implementation = function(byteArray, offset, byteCount) {
    console.log('FileDescriptorSocket Input');
    var ret = this.read(byteArray, offset, byteCount);
    processData(byteArray, offset, byteCount, this, 'received');
    return ret;
  }

  const OutputStream2 = Java.use(conscrypt_id + '.ConscryptEngineSocket$SSLOutputStream');
  OutputStream2.write.overload('[B', 'int', 'int').implementation = function(byteArray, offset, byteCount) {
    console.log('EngineSocket Output');
    processData(byteArray, offset, byteCount, this, 'sent');
    this.write(byteArray, offset, byteCount);
  }

  const InputStream2 = Java.use(conscrypt_id + '.ConscryptEngineSocket$SSLInputStream');
  InputStream2.read.overload('[B', 'int', 'int').implementation = function(byteArray, offset, byteCount) {
    console.log('EngineSocket Input');
    var ret = this.read(byteArray, offset, byteCount);
    processData(byteArray, offset, byteCount, this, 'received');
    return ret;
  }

  const OutputStream3 = Java.use('java.net.SocketOutputStream');
  OutputStream3.socketWrite.overload('[B', 'int', 'int').implementation = function(byteArray, offset, byteCount) {
    console.log('SocketOutputStream Output');
    processData(byteArray, offset, byteCount, this, 'sent');
    this.socketWrite(byteArray, offset, byteCount);
  }

  const InputStream3 = Java.use('java.net.SocketInputStream');
  InputStream3.socketRead0.overload('java.io.FileDescriptor', '[B', 'int', 'int', 'int').implementation = function(fd, byteArray, offset, byteCount, timeout) {
    console.log('SocketInputStream Input');
    var ret = this.socketRead0(fd, byteArray, offset, byteCount, timeout);
    processData(byteArray, offset, byteCount, this, 'received');
    return ret;
  }


  /*const NativeSSL = Java.use('com.android.org.conscrypt.NativeSsl')
  NativeSSL.write.implementation = function(fd, byteArray, offset, byteCount, timeout) {
    console.log('NativeSSL Output');
    this.write(fd, byteArray, offset, byteCount, timeout);
    processData(byteArray, offset, byteCount, this, 'sent');
  }
  NativeSSL.read.implementation = function(fd, byteArray, offset, byteCount, timeout) {
    console.log('NativeSSL Input');
    var ret = this.read(fd, byteArray, offset, byteCount, timeout);
    processData(byteArray, offset, byteCount, this, 'received');
    return ret
  }*/

  console.log("Finished javascript");
});
