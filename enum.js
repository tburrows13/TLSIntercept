Java.deoptimizeEverything();
Java.perform(() => {
  Java.deoptimizeEverything();
  console.log("Script loaded successfully");
  console.log(`Android version: ${Java.androidVersion}`);
  const groups = Java.enumerateMethods('*ConscryptFileDescriptorSocket*!*/is')
  //const groups = Java.enumerateMethods('*URLConnection*!connect*/s')
  console.log(JSON.stringify(groups, null, 2));

  /*Java.enumerateLoadedClasses({
    onMatch: function(name, handle) {
      if (name.toLowerCase().includes("conscrypt")){
        traceClass(name);
      }
    },
    onComplete: function() {}
  })*/

  console.log("Finished js");
});
