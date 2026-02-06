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
[otel.javaagent 2026-02-03 15:29:04:822 +0000] [main] INFO io.opentelemetry.javaagent.tooling.VersionLogger - opentelemetry-javaagent - version: 2.21.0
WARNING: A restricted method in java.lang.foreign.Linker has been called
WARNING: java.lang.foreign.Linker::downcallHandle has been called by com.example.javaagent.OtelProcessCtx in an unnamed module
WARNING: Use --enable-native-access=ALL-UNNAMED to avoid a warning for callers in this module
WARNING: Restricted methods will be blocked in a future release unless native access is enabled

Published OTEL_CTX
2026-02-03T15:29:08.077Z INFO 'Starting DiceApplication using Java 23.0.1 with PID 148671 (/home/ivo.anjo/datadog/ctx-sharing/proc-level-demo/otel-java-extension-demo/dice-application/build/libs/dice-application.jar started by ivo.anjo in /home/ivo.anjo/datadog/ctx-sharing/proc-level-demo/otel-java-extension-demo/dice-application)' : 00000000000000000000000000000000 0000000000000000 [scopeInfo: otel.DiceApplication:] {}
```

5. You can now take the PID and use the `otel_process_ctx_dump.sh` script (in this repo or from https://github.com/open-telemetry/sig-profiling/tree/main/process-context/c-and-cpp). The script expects `process_context.proto`, `resource.proto`, and `common.proto` in the same directory for protobuf decode:

```
$ sudo ./otel_process_ctx_dump.sh 148671
Found OTEL context for PID 148671
Start address: 7b2f4c342000
00000000  4f 54 45 4c 5f 43 54 58  02 00 00 00 5a 01 00 00  |OTEL_CTX....Z...|
00000010  18 ae b8 fd 2b c6 90 18  c0 72 79 44 2f 7b 00 00  |....+....ryD/{..|
00000020
Parsed struct:
  otel_process_ctx_signature       : "OTEL_CTX"
  otel_process_ctx_version         : 2
  otel_process_payload_size        : 268
  otel_process_ctx_published_at_ns : 1770132545799237144 (2026-02-03 15:29:05 GMT)
  otel_process_payload             : 0x00007b2f447972c0
Payload dump (268 bytes):
00000000  0a 89 02 0a 21 0a 1b 64  65 70 6c 6f 79 6d 65 6e  |....!..deploymen|
00000010  74 2e 65 6e 76 69 72 6f  6e 6d 65 6e 74 2e 6e 61  |t.environment.na|
...
Protobuf decode:
resource {
  attributes {
    key: "deployment.environment.name"
    value {
      string_value: ""
    }
  }
  attributes {
    key: "service.instance.id"
    value {
      string_value: "1aca2db9-844a-4025-8fc0-666c87fca85a"
    }
  }
  attributes {
    key: "service.name"
    value {
      string_value: "dice-application"
    }
  }
...
```
