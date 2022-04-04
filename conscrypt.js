function binaryToHexToAscii(array) {
  var result = [];
  for (var i = 0; i < array.length; ++i) {
      result.push(String.fromCharCode( // hex2ascii part
          parseInt(
              ('0' + (array[i] & 0xFF).toString(16)).slice(-2), // binary2hex part
              16
          )
      ));
  }
  return result.join('');
}


function processData(byteArray, outputStream) {
  var decoded = binaryToHexToAscii(byteArray);
  //console.log(`OutputStream-${outputStream.hashCode()} writing ${decoded.length}:\n${'-'.repeat(100)}\n${decoded}\n${'-'.repeat(100)}`);

  // Perform analysis
  var info = {}
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



  var message = JSON.stringify(info) + '\n' + decoded;

  send(message);
  //send("Outputstream to python!")
}


Java.perform(() => {
  Java.deoptimizeEverything();
  const Socket = Java.use('org.conscrypt.ConscryptFileDescriptorSocket');

  let classNames = Java.enumerateLoadedClassesSync()
  for (let conscrypt_id of ['org.conscrypt', 'com.android.org.conscrypt']) {
    //console.log("Starting javascript");
    //console.log(`Android version: ${Java.androidVersion}`);

    /*
    "$init(java.lang.String, int, java.net.InetAddress, int, org.conscrypt.SSLParametersImpl): void",
    "$init(java.lang.String, int, org.conscrypt.SSLParametersImpl): void",
    "$init(java.net.InetAddress, int, java.net.InetAddress, int, org.conscrypt.SSLParametersImpl): void",
    "$init(java.net.InetAddress, int, org.conscrypt.SSLParametersImpl): void",
    "$init(java.net.Socket, java.lang.String, int, boolean, org.conscrypt.SSLParametersImpl): void",
    "$init(org.conscrypt.SSLParametersImpl): void",
    */
    //console.log("Skipping " + conscrypt_id)

    if (!classNames.includes(conscrypt_id + '.ConscryptFileDescriptorSocket')) {
      console.log("Skipping " + conscrypt_id)
      //continue
    }
    const Socket = Java.use(conscrypt_id + '.ConscryptFileDescriptorSocket');

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

    const OutputStream = Java.use(conscrypt_id + '.ConscryptFileDescriptorSocket$SSLOutputStream');
    /*for (const init of OutputStream.$init.overloads) {
      init.implementation = function(a, b, c) {
        console.log(`OutputStream-${this.hashCode()} created`, a, b, c);
        return this.$init(a, b, c);
      }
    }*/

    OutputStream.write.overload('[B', 'int', 'int').implementation = function(byteArray, offset, byteCount) {
      processData(byteArray, this);
      this.write(byteArray, offset, byteCount);
    }
  }

  console.log("Finished javascript");
});
