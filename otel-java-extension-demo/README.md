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

5. You can now take the PID and use the `otel_process_ctx_dump.sh` from https://github.com/open-telemetry/sig-profiling/tree/main/process-context/c-and-cpp folder to print the application context:

```
$ sudo ./otel_process_ctx_dump.sh 148671
Found OTEL context for PID 148671
Start address: 7b2f4c342000
00000000  4f 54 45 4c 5f 43 54 58  02 00 00 00 09 01 00 00  |OTEL_CTX........|
00000010  18 ae b8 fd 2b c6 90 18  c0 72 79 44 2f 7b 00 00  |....+....ryD/{..|
00000020
Parsed struct:
  otel_process_ctx_signature       : "OTEL_CTX"
  otel_process_ctx_version         : 2
  otel_process_payload_size        : 265
  otel_process_ctx_published_at_ns : 1770132545799237144 (2026-02-03 15:29:05 GMT)
  otel_process_payload             : 0x00007b2f447972c0
Payload dump (265 bytes):
00000000  0a 21 0a 1b 64 65 70 6c  6f 79 6d 65 6e 74 2e 65  |.!..deployment.e|
00000010  6e 76 69 72 6f 6e 6d 65  6e 74 2e 6e 61 6d 65 12  |nvironment.name.|
00000020  02 0a 00 0a 3d 0a 13 73  65 72 76 69 63 65 2e 69  |....=..service.i|
00000030  6e 73 74 61 6e 63 65 2e  69 64 12 26 0a 24 31 61  |nstance.id.&.$1a|
00000040  63 61 32 64 62 39 2d 38  34 34 61 2d 34 30 32 35  |ca2db9-844a-4025|
00000050  2d 38 66 63 30 2d 36 36  36 63 38 37 66 63 61 38  |-8fc0-666c87fca8|
00000060  35 61 0a 22 0a 0c 73 65  72 76 69 63 65 2e 6e 61  |5a."..service.na|
00000070  6d 65 12 12 0a 10 64 69  63 65 2d 61 70 70 6c 69  |me....dice-appli|
00000080  63 61 74 69 6f 6e 0a 15  0a 0f 73 65 72 76 69 63  |cation....servic|
00000090  65 2e 76 65 72 73 69 6f  6e 12 02 0a 00 0a 20 0a  |e.version..... .|
000000a0  16 74 65 6c 65 6d 65 74  72 79 2e 73 64 6b 2e 6c  |.telemetry.sdk.l|
000000b0  61 6e 67 75 61 67 65 12  06 0a 04 6a 61 76 61 0a  |anguage....java.|
000000c0  21 0a 15 74 65 6c 65 6d  65 74 72 79 2e 73 64 6b  |!..telemetry.sdk|
000000d0  2e 76 65 72 73 69 6f 6e  12 08 0a 06 31 2e 35 35  |.version....1.55|
000000e0  2e 30 0a 25 0a 12 74 65  6c 65 6d 65 74 72 79 2e  |.0.%..telemetry.|
000000f0  73 64 6b 2e 6e 61 6d 65  12 0f 0a 0d 6f 70 65 6e  |sdk.name....open|
00000100  74 65 6c 65 6d 65 74 72  79                       |telemetry|
00000109
Protobuf decode:
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
attributes {
  key: "service.version"
  value {
    string_value: ""
  }
}
attributes {
  key: "telemetry.sdk.language"
  value {
    string_value: "java"
  }
}
attributes {
  key: "telemetry.sdk.version"
  value {
    string_value: "1.55.0"
  }
}
attributes {
  key: "telemetry.sdk.name"
  value {
    string_value: "opentelemetry"
  }
}
```
