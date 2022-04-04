Java.perform(() => {
  Java.deoptimizeEverything();
  console.log("Starting javascript");
  console.log(`Android version: ${Java.androidVersion}`);

  // use enum_methods.js to work out which classes/methods to hook
  const PushTextSendJob = Java.use('org.thoughtcrime.securesms.jobs.PushTextSendJob');

  // if 'deliver' was overloaded then use e.g. 'PushTextSendJob.deliver.overload('java.lang.String', 'int').implementation'
  PushTextSendJob.deliver.implementation = function(record) {
    console.log(`Message intercepted: ${record.getBody()}`);
    return this.deliver(record)
  }

  console.log("Finished javascript");
});
