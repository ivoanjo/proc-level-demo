# Purpose

This is a POC showing how we could identify anonymous mappings correctly when sharing process-level storage with the OpenTelemetry eBPF profiler.

Specifically:

* `anonmapping-clib-msgpack` provides a reference C implementation for publishing the process-level data as described in https://docs.google.com/document/d/1-4jo29vWBZZ0nKKAOG13uAQjRcARwmRc4P313LTbPOE/edit?tab=t.0 :
    * Data is written in an anonymous mapping requested from the kernel
    * This mapping is set up to be easy to find from an external process
    * The C implementation includes a context reader for testing, and we also include a simple bash script to do the same
    * There's also a pure-go port of this code in https://github.com/DataDog/dd-trace-go/pull/3937

* `ebpf-program` shows how it's possible to hook on prctl if we optionally want to observe context publish/update events (instead of polling)

* `original-poc` is an older version of the ideas above, kept for archival reasons

* See also:
    * https://github.com/DataDog/dd-otel-host-profiler/pull/210 Reading process-level data on Datadog's fork of the OTEL profiler
    * Integration of `anonmapping-clib` into [dd-trace-java](https://github.com/DataDog/java-profiler/pull/266) and [dd-trace-rb](https://github.com/DataDog/dd-trace-rb/pull/4865)
