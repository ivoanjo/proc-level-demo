# OTEL Java Extension Demo

This is a demo for using the OTEL Java extension capability described in https://github.com/open-telemetry/opentelemetry-java-instrumentation/tree/main/examples/extension to automatically publish the OTEL process context for an example Java application. (The demo is also partially based on the code from that repo)

The Java application in use is the OTEL "Getting Started by Example" app from https://opentelemetry.io/docs/languages/java/getting-started/ .

This demo currently requires Linux AND Java 22+.

Here's how to run it:

1. Verify you're running the right Java version:

```
$ java -version
openjdk version "23.0.1" 2024-10-15
OpenJDK Runtime Environment Corretto-23.0.1.8.1 (build 23.0.1+8-FR)
OpenJDK 64-Bit Server VM Corretto-23.0.1.8.1 (build 23.0.1+8-FR, mixed mode, sharing)
```

2. Build the extension:

```
$ cd otel-process-ctx-extension/
$ ./gradlew jar
$ cd -
```

3. Start the Java app:

```
$ cd dice-application/
$ ./gradlew assemble
$ export JAVA_TOOL_OPTIONS="-javaagent:opentelemetry-javaagent.jar" \
  OTEL_TRACES_EXPORTER=logging \
  OTEL_METRICS_EXPORTER=logging \
  OTEL_LOGS_EXPORTER=logging \
  OTEL_METRIC_EXPORT_INTERVAL=15000
$ java -Dotel.javaagent.extensions=../otel-process-ctx-extension/build/libs/opentelemetry-java-instrumentation-extension-demo-1.0.jar -jar build/libs/dice-application.jar
```

4. Upon starting up, the app should flag if the process published successfully:

```
Picked up JAVA_TOOL_OPTIONS: -javaagent:opentelemetry-javaagent.jar
OpenJDK 64-Bit Server VM warning: Sharing is only supported for boot loader classes because bootstrap classpath has been appended
[otel.javaagent 2025-10-28 16:17:38:511 +0000] [main] INFO io.opentelemetry.javaagent.tooling.VersionLogger - opentelemetry-javaagent - version: 2.21.0
WARNING: A restricted method in java.lang.foreign.Linker has been called
WARNING: java.lang.foreign.Linker::downcallHandle has been called by com.example.javaagent.OtelProcessCtx in an unnamed module
WARNING: Use --enable-native-access=ALL-UNNAMED to avoid a warning for callers in this module
WARNING: Restricted methods will be blocked in a future release unless native access is enabled

Published OTEL_CTX
2025-10-28T16:17:41.322Z INFO 'Starting DiceApplication using Java 23.0.1 with PID 398219 (dice-application.jar started by ivo.anjo)' : 00000000000000000000000000000000 0000000000000000 [scopeInfo: otel.DiceApplication:] {}
```

5. You can now take the PID and use the `otel_process_ctx_dump.sh` from the `anonmapping-clib` folder to print the application context:

```
$ sudo ./otel_process_ctx_dump.sh 398219
Found OTEL context for PID 398219
Start address: 75e620025000
00000000  4f 54 45 4c 5f 43 54 58  02 00 00 00 07 f2 73 e5  |OTEL_CTX......s.|
00000010  86 b5 72 18 59 00 00 00  b0 40 73 1c e6 75 00 00  |..r.Y....@s..u..|
00000020
Parsed struct:
  otel_process_ctx_signature       : "OTEL_CTX"
  otel_process_ctx_version         : 2
  otel_process_ctx_published_at_ns : 1761669995235111431 (2025-10-28 16:46:35 GMT)
  otel_process_payload_size        : 89
  otel_process_payload             : 0x000075e61c7340b0
Payload dump (89 bytes):
00000000  12 00 1a 24 39 66 66 33  63 62 31 64 2d 39 62 33  |...$9ff3cb1d-9b3|
00000010  65 2d 34 31 33 33 2d 62  38 34 32 2d 66 39 61 37  |e-4133-b842-f9a7|
00000020  31 62 37 32 61 39 61 63  22 10 64 69 63 65 2d 61  |1b72a9ac".dice-a|
00000030  70 70 6c 69 63 61 74 69  6f 6e 2a 00 32 04 6a 61  |pplication*.2.ja|
00000040  76 61 3a 06 31 2e 35 35  2e 30 42 0d 6f 70 65 6e  |va:.1.55.0B.open|
00000050  74 65 6c 65 6d 65 74 72  79                       |telemetry|
00000059
Protobuf decode:
service_instance_id: "9ff3cb1d-9b3e-4133-b842-f9a71b72a9ac"
service_name: "dice-application"
telemetry_sdk_language: "java"
telemetry_sdk_version: "1.55.0"
telemetry_sdk_name: "opentelemetry"

```
