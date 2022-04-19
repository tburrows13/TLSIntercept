var data = {};

function saveData(byteArray, byteCount, hashCode) {
  var intArray = byteArrayToIntArray(byteArray, byteCount);
  if (hashCode in data) {
    data[hashCode] = data[hashCode].concat(intArray);
  } else {
    data[hashCode] = intArray;
  };
  send(
    {
      type: 'data',
      hashCode: hashCode,
    },
    intArray
  );

  send(
    {
      type: 'combined-data',
      hashCode: hashCode,
    },
    data[hashCode]
  );
}

function byteArrayToIntArray(array, length) {
  var result = [];
  for (var i = 0; i < length; ++i) {
      result.push(
          parseInt(
              ('0' + (array[i] & 0xFF).toString(16)).slice(-2), // binary2hex part
              16
          )
      );
  }
  if (parseInt(('0' + (array[length] & 0xFF).toString(16)).slice(-2), 16) != 0) {
    console.log('ByteCount wrong')
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


function processData(byteArray, byteCount, outputStream) {
  var decoded = binaryToHexToAscii(byteArray, byteCount);
  //console.log(`OutputStream-${outputStream.hashCode()} writing ${decoded.length}:\n${'-'.repeat(100)}\n${decoded}\n${'-'.repeat(100)}`);

  // Perform analysis
  var info = {}
  info['type'] = 'info'
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

  //var message = JSON.stringify(info) + '\n' + decoded;

  send(info);

  saveData(byteArray, byteCount, outputStream.hashCode());
  //send("Outputstream to python!")
}


Java.perform(() => {
  Java.deoptimizeEverything();

  console.log("Starting javascript");
  console.log(`Android version: ${Java.androidVersion}`);

  const ActivityThread = Java.use('android.app.ActivityThread');
  const processName = ActivityThread.currentProcessName();

  if (processName === 'org.thoughtcrime.securesms') {
    // Signal referes to conscrypt by a different name
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
    processData(byteArray, byteCount, this);
    this.write(byteArray, offset, byteCount);
  }

  console.log("Finished javascript");
});
