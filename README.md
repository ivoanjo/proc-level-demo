# Purpose

This is a POC showing how we could identify anonymous mappings correctly when sharing process-level storage with the OpenTelemetry eBPF profiler.

Specifically:

* `anonmapping-clib` provides a reference C implementation for publishing the process-level data as described in https://github.com/open-telemetry/opentelemetry-specification/pull/4719 :
    * Data is written in an anonymous mapping requested from the kernel
    * This mapping is set up to be easy to find from an external process
    * The C implementation includes a context reader for testing, and we also include a simple bash script to do the same
    * The payload is kept in a protobuf-based format

* `anonmapping-java` is a proof of concept port of `anonmapping-clib` to pure Java, without any dependencies.

* `otel-java-extension-demo` provides a small Java test app + an OTEL Java SDK extension so that an app instrumented using the SDK can publish the process context automatically. It's based on `anonmapping-java`.

* `anonmapping-clib-msgpack` provides an earlier version of the reference C implementation for publishing the process-level data using msgpack as a payload:
    * (This version is otherwise equivalent to the protobuf-based version)
    * There's also a pure-go port of this code in https://github.com/DataDog/dd-trace-go/pull/3937

* `ebpf-program` shows how it's possible to hook on prctl if we optionally want to observe context publish/update events (instead of polling)

* See also:
    * https://github.com/DataDog/dd-otel-host-profiler/pull/210 Reading process-level data on Datadog's fork of the OTEL profiler
    * Integration of `anonmapping-clib` into [dd-trace-java](https://github.com/DataDog/java-profiler/pull/266) and [dd-trace-rb](https://github.com/DataDog/dd-trace-rb/pull/4865)
