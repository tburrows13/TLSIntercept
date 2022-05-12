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
      TYPE: 'data',
      DIRECTION: direction,
      STREAM_ID: hashCode,
      LENGTH: byteCount,
    },
    intArray
  );

  send(
    {
      TYPE: 'combined-data',
      DIRECTION: direction,
      STREAM_ID: hashCode,
      LENGTH: data[hashCode].length,
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

function processData(byteArray, offset, byteCount, outputStream, direction) {
  saveData(byteArray, offset, byteCount, outputStream.hashCode(), direction);

  /*
  // Log current stack trace
  Java.perform(function() {
    console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()))
  });
  */
}


Java.perform(() => {
  console.log("Starting javascript");
  console.log(`Android version: ${Java.androidVersion}`);

  const ActivityThread = Java.use('android.app.ActivityThread');
  const processName = ActivityThread.currentProcessName();

  if (processName === 'org.thoughtcrime.securesms') {
    // Signal loads Conscrypt differently
    var conscrypt_id = 'org.conscrypt';
  } else {
    var conscrypt_id = 'com.android.org.conscrypt';
  }

  // Android 8 Conscrypt
  const FileDescriptorOutputStream = Java.use(conscrypt_id + '.ConscryptFileDescriptorSocket$SSLOutputStream');
  FileDescriptorOutputStream.write.overload('[B', 'int', 'int').implementation = function(byteArray, offset, byteCount) {
    processData(byteArray, offset, byteCount, this, 'sent');
    this.write(byteArray, offset, byteCount);
  }
  const FileDescriptorInputStream = Java.use(conscrypt_id + '.ConscryptFileDescriptorSocket$SSLInputStream');
  FileDescriptorInputStream.read.overload('[B', 'int', 'int').implementation = function(byteArray, offset, byteCount) {
    var ret = this.read(byteArray, offset, byteCount);
    processData(byteArray, offset, byteCount, this, 'received');
    return ret;
  }

  // Android 12 Conscrypt
  const EngineSocketOutputStream = Java.use(conscrypt_id + '.ConscryptEngineSocket$SSLOutputStream');
  EngineSocketOutputStream.write.overload('[B', 'int', 'int').implementation = function(byteArray, offset, byteCount) {
    processData(byteArray, offset, byteCount, this, 'sent');
    this.write(byteArray, offset, byteCount);
  }
  const EngineSocketInputStream = Java.use(conscrypt_id + '.ConscryptEngineSocket$SSLInputStream');
  EngineSocketInputStream.read.overload('[B', 'int', 'int').implementation = function(byteArray, offset, byteCount) {
    var ret = this.read(byteArray, offset, byteCount);
    processData(byteArray, offset, byteCount, this, 'received');
    return ret;
  }

  /*/ Used by WhatsApp
  const SocketOutputStream = Java.use('java.net.SocketOutputStream');
  SocketOutputStream.socketWrite.overload('[B', 'int', 'int').implementation = function(byteArray, offset, byteCount) {
    processData(byteArray, offset, byteCount, this, 'sent');
    this.socketWrite(byteArray, offset, byteCount);
  }
  const SocketInputStream = Java.use('java.net.SocketInputStream');
  SocketInputStream.socketRead0.overload('java.io.FileDescriptor', '[B', 'int', 'int', 'int').implementation = function(fd, byteArray, offset, byteCount, timeout) {
    var ret = this.socketRead0(fd, byteArray, offset, byteCount, timeout);
    processData(byteArray, offset, byteCount, this, 'received');
    return ret;
  }*/

  console.log("Finished javascript");
});
