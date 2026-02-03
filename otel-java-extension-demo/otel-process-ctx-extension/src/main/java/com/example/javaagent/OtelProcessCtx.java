package com.example.javaagent;

// This file is licensed under the Apache License (Version 2.0).
// This product includes software developed at Datadog (https://www.datadoghq.com/) Copyright 2025 Datadog, Inc.

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;

import static java.lang.foreign.ValueLayout.*;

/* This is a pure-Java prototype implementation of the `otel_process_ctx` API.
 *
 * It's not yet intended to be used in production, but to show off how in a few hundred lines of Java code we can:
 * * Setup the process mapping in pure Java code (using the new Java FFM API -- requires Java 22+)
 *   (TODO: Have not tried running it with preview versions of FFM that shipped with Java as far back as 19; maybe it works?)
 * * Emit the process context payload in protobof without any additional dependencies. In production we'll most likely want to use
 *   an actual protobuf encoder.
 */

 class OtelProcessCtx {
  private static final String OTEL_CTX_SIGNATURE = "OTEL_CTX";
  private static final int OTEL_CTX_VERSION = 2;
  private static final int KEY_VALUE_LIMIT = 4096;

  // System constants
  private static final int PROT_READ = 0x1;
  private static final int PROT_WRITE = 0x2;
  private static final int MAP_PRIVATE = 0x02;
  private static final int MAP_ANONYMOUS = 0x20;
  private static final int MADV_DONTFORK = 0x10;
  private static final int PR_SET_VMA = 0x53564d41;
  private static final int PR_SET_VMA_ANON_NAME = 0;
  private static final int MFD_CLOEXEC = 0x0001;
  private static final int MFD_ALLOW_SEALING = 0x0002;
  private static final int MFD_NOEXEC_SEAL = 0x0008;

  private static final Linker LINKER = Linker.nativeLinker();
  private static final SymbolLookup LIBC = LINKER.defaultLookup();

  private static final MethodHandle MMAP;
  private static final MethodHandle MUNMAP;
  private static final MethodHandle MADVISE;
  private static final MethodHandle PRCTL;
  private static final MethodHandle MEMFD_CREATE;
  private static final MethodHandle FTRUNCATE;
  private static final MethodHandle CLOSE;
  private static final MethodHandle GETPID;

  static {
      try {
          MMAP = LINKER.downcallHandle(
              LIBC.find("mmap").orElseThrow(),
              FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_LONG, JAVA_INT, JAVA_INT, JAVA_INT, JAVA_LONG)
          );
          MUNMAP = LINKER.downcallHandle(
              LIBC.find("munmap").orElseThrow(),
              FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG)
          );
          MADVISE = LINKER.downcallHandle(
              LIBC.find("madvise").orElseThrow(),
              FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, JAVA_INT)
          );
          PRCTL = LINKER.downcallHandle(
              LIBC.find("prctl").orElseThrow(),
              FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT, ADDRESS, JAVA_LONG, ADDRESS)
          );
          MEMFD_CREATE = LINKER.downcallHandle(
              LIBC.find("memfd_create").orElseThrow(),
              FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT)
          );
          FTRUNCATE = LINKER.downcallHandle(
              LIBC.find("ftruncate").orElseThrow(),
              FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_LONG)
          );
          CLOSE = LINKER.downcallHandle(
              LIBC.find("close").orElseThrow(),
              FunctionDescriptor.of(JAVA_INT, JAVA_INT)
          );
          GETPID = LINKER.downcallHandle(
              LIBC.find("getpid").orElseThrow(),
              FunctionDescriptor.of(JAVA_INT)
          );
      } catch (Throwable e) {
          throw new RuntimeException("Failed to initialize native method handles", e);
      }
  }

  private static record PublishedState(int publisherPid, MemorySegment mapping, MemorySegment payload) { }

  private static PublishedState publishedState = null;
  private static final Arena globalArena = Arena.global();

  // Size of the otel_process_ctx_mapping struct:
  // char[8] signature + uint32_t version + uint32_t size + uint64_t timestamp + char* pointer as uint64
  private static final long MAPPING_SIZE = 8 + 4 + 4 + 8 + 8; // = 32 bytes

  private static int protobufVarintSize(int value) {
      return value >= 128 ? 2 : 1;
  }

  private static int protobufRecordSize(int len) {
      return 1 + protobufVarintSize(len) + len;
  }

  private static int protobufStringSize(String str) {
      return protobufRecordSize(str.getBytes(StandardCharsets.UTF_8).length);
  }

  private static int protobufOtelKeyvalueStringSize(String key, String value) {
      int keyFieldSize = protobufStringSize(key);                           // String
      int valueFieldSize = protobufRecordSize(protobufStringSize(value));   // Nested AnyValue message with a string inside
      return keyFieldSize + valueFieldSize; // Does not include the keyvalue record tag + size, only its payload
  }

  private static void writeProtobufVarint(byte[] buffer, int[] offset, int value) {
      if (protobufVarintSize(value) == 1) {
          buffer[offset[0]++] = (byte) value;
      } else {
          // Two bytes: first byte has MSB set, second byte has value
          buffer[offset[0]++] = (byte) ((value & 0x7F) | 0x80); // Low 7 bits + continuation bit
          buffer[offset[0]++] = (byte) (value >> 7);            // High 7 bits
      }
  }

  private static void writeProtobufString(byte[] buffer, int[] offset, String str) {
      byte[] strBytes = str.getBytes(StandardCharsets.UTF_8);
      writeProtobufVarint(buffer, offset, strBytes.length);
      System.arraycopy(strBytes, 0, buffer, offset[0], strBytes.length);
      offset[0] += strBytes.length;
  }

  private static void writeProtobufTag(byte[] buffer, int[] offset, int fieldNumber) {
      buffer[offset[0]++] = (byte) ((fieldNumber << 3) | 2); // Field type is always 2 (LEN)
  }

  private static void writeAttribute(byte[] buffer, int[] offset, String key, String value) {
      writeProtobufTag(buffer, offset, 1); // Resource.attributes (field 1)
      writeProtobufVarint(buffer, offset, protobufOtelKeyvalueStringSize(key, value));

      // KeyValue
      writeProtobufTag(buffer, offset, 1); // KeyValue.key (field 1)
      writeProtobufString(buffer, offset, key);
      writeProtobufTag(buffer, offset, 2); // KeyValue.value (field 2)
      writeProtobufVarint(buffer, offset, protobufStringSize(value));

      // AnyValue
      writeProtobufTag(buffer, offset, 1); // AnyValue.string_value (field 1)
      writeProtobufString(buffer, offset, value);
  }

  private static String validateString(String str) {
      if (str == null) {
          throw new IllegalArgumentException("String cannot be null");
      }
      if (str.length() > KEY_VALUE_LIMIT) {
          throw new IllegalArgumentException("String exceeds KEY_VALUE_LIMIT");
      }
      return str;
  }

  private static byte[] encodeProtobufPayload(Data data) {
      // Build pairs array with keys and values
      String[][] pairs = {
          {"deployment.environment.name", data.deploymentEnvironmentName},
          {"service.instance.id", data.serviceInstanceId},
          {"service.name", data.serviceName},
          {"service.version", data.serviceVersion},
          {"telemetry.sdk.language", data.telemetrySdkLanguage},
          {"telemetry.sdk.version", data.telemetrySdkVersion},
          {"telemetry.sdk.name", data.telemetrySdkName}
      };

      // Validate and calculate size for fixed pairs
      int pairsSize = 0;
      for (String[] pair : pairs) {
          validateString(pair[0]);
          validateString(pair[1]);
          pairsSize += protobufRecordSize(protobufOtelKeyvalueStringSize(pair[0], pair[1]));
      }

      // Validate and calculate size for resource pairs
      int resourcesSize = 0;
      if (data.resources != null) {
          for (Map.Entry<String, String> entry : data.resources.entrySet()) {
              String key = validateString(entry.getKey());
              String value = validateString(entry.getValue());
              resourcesSize += protobufRecordSize(protobufOtelKeyvalueStringSize(key, value));
          }
      }

      int totalSize = pairsSize + resourcesSize;
      byte[] encoded = new byte[totalSize];
      int[] offset = {0};

      // Write all fixed fields as attributes
      for (String[] pair : pairs) {
          writeAttribute(encoded, offset, pair[0], pair[1]);
      }

      // Write all resource fields as attributes
      if (data.resources != null) {
          for (Map.Entry<String, String> entry : data.resources.entrySet()) {
              writeAttribute(encoded, offset, entry.getKey(), entry.getValue());
          }
      }

      return encoded;
  }

  public static record Data(
      String deploymentEnvironmentName,
      String serviceInstanceId,
      String serviceName,
      String serviceVersion,
      String telemetrySdkLanguage,
      String telemetrySdkVersion,
      String telemetrySdkName,
      Map<String, String> resources
  ) {}

  public static record Result(boolean success, String errorMessage) {
      public static Result withSuccess() {
          return new Result(true, null);
      }

      public static Result withError(String errorMessage) {
          return new Result(false, errorMessage);
      }
  }

  private static boolean ctxIsPublished(PublishedState state) {
      try {
          return state != null && state.mapping != null &&
                 state.mapping.address() != -1L &&
                 state.publisherPid == (Integer) GETPID.invoke();
      } catch (Throwable e) {
          return false;
      }
  }

  // The process context is designed to be read by an outside-of-process reader. Thus, for concurrency purposes the steps
  // on this method are ordered in a way to avoid races, or if not possible to avoid, to allow the reader to detect if there was a race.
  public static Result publish(Data data) {
      if (data == null) return Result.withError("Data cannot be null");

      try {
          // Get current time in nanoseconds since epoch
          Instant now = Instant.now();
          long publishedAtNs = now.getEpochSecond() * 1_000_000_000L + now.getNano();
          if (publishedAtNs == 0) {
              return Result.withError("Failed to get current time");
          }

          // Step: If the context has been published by this process, update it in place
          if (ctxIsPublished(publishedState)) {
              return update(publishedAtNs, data);
          }

          // Step: Drop any previous context state if it exists
          // No state should be around anywhere after this step.
          if (!dropCurrent()) {
              return Result.withError("Failed to drop previous context");
          }

          // Step: Prepare the payload to be published
          // The payload SHOULD be ready and valid before trying to actually create the mapping.
          byte[] payloadResult = encodeProtobufPayload(data);
          // Store the encoded payload in global arena
          MemorySegment payloadSegment = globalArena.allocate(payloadResult.length);
          payloadSegment.copyFrom(MemorySegment.ofArray(payloadResult));

          // Step: Create the mapping
          int publisherPid = (Integer) GETPID.invoke();
          MemorySegment mapping;

          // Try to create mapping from memfd
          MemorySegment nameSegment = globalArena.allocateFrom(OTEL_CTX_SIGNATURE);
          int fd = (Integer) MEMFD_CREATE.invoke(nameSegment, MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL);
          boolean failedToCloseFd = false;

          if (fd >= 0) {
              // Try to create mapping from memfd
              if ((Integer) FTRUNCATE.invoke(fd, MAPPING_SIZE) == -1) {
                  dropCurrent();
                  return Result.withError("Failed to truncate memfd");
              }
              mapping = ((MemorySegment) MMAP.invoke(
                  MemorySegment.NULL,           // addr
                  MAPPING_SIZE,                 // length
                  PROT_READ | PROT_WRITE,       // prot
                  MAP_PRIVATE,                  // flags
                  fd,                           // fd
                  0L                            // offset
              )).reinterpret(MAPPING_SIZE);
              failedToCloseFd = ((Integer) CLOSE.invoke(fd) == -1);
          } else {
              // Fallback: Use an anonymous mapping instead
              mapping = ((MemorySegment) MMAP.invoke(
                  MemorySegment.NULL,           // addr
                  MAPPING_SIZE,                 // length
                  PROT_READ | PROT_WRITE,       // prot
                  MAP_PRIVATE | MAP_ANONYMOUS,  // flags
                  -1,                           // fd
                  0L                            // offset
              )).reinterpret(MAPPING_SIZE);
          }

          // Check if mmap failed - in C, MAP_FAILED is (void*)-1
          if (mapping.address() == -1L || failedToCloseFd) {
              dropCurrent();
              if (failedToCloseFd) {
                  return Result.withError("Failed to close memfd");
              } else {
                  return Result.withError("Failed to allocate mapping");
              }
          }

          publishedState = new PublishedState(publisherPid, mapping, payloadSegment);

          // Step: Setup MADV_DONTFORK
          // This ensures that the mapping is not propagated to child processes (they should call update/publish again).
          int madviseResult = (Integer) MADVISE.invoke(mapping, MAPPING_SIZE, MADV_DONTFORK);
          if (madviseResult == -1) {
              if (dropCurrent()) {
                  return Result.withError("Failed to setup MADV_DONTFORK");
              } else {
                  return Result.withError("Failed to drop context");
              }
          }

          // Step: Populate the mapping
          // The payload and any extra fields must come first and not be reordered with the signature by the compiler.
          mapping.set(ADDRESS, 0, MemorySegment.NULL); // signature placeholder
          mapping.set(JAVA_INT, 8, OTEL_CTX_VERSION);
          mapping.set(JAVA_INT, 12, payloadResult.length);
          mapping.set(JAVA_LONG, 16, publishedAtNs);
          mapping.set(ADDRESS, 24, payloadSegment);

          // Step: Synchronization - Mapping has been filled and is missing signature
          // Make sure the initialization of the mapping + payload above does not get reordered with setting the signature below.
          // Setting the signature is what tells an outside reader that the context is fully published.
          java.lang.invoke.VarHandle.fullFence();

          // Step: Populate the signature into the mapping
          // The signature must come last and not be reordered with the fields above by the compiler. After this step, external readers
          // can read the signature and know that the payload is ready to be read.
          MemorySegment signatureSegment = globalArena.allocateFrom(OTEL_CTX_SIGNATURE);
          MemorySegment.copy(signatureSegment, 0, mapping, 0, 8);

          // Step: Attempt to name the mapping so outside readers can:
          // * Find it by name
          // * Hook on prctl to detect when new mappings are published
          MemorySegment nameSegment2 = globalArena.allocateFrom(OTEL_CTX_SIGNATURE);
          PRCTL.invoke(
              PR_SET_VMA,
              PR_SET_VMA_ANON_NAME,
              mapping,
              MAPPING_SIZE,
              nameSegment2
          );
          // Naming an anonymous mapping is an optional Linux 5.17+ feature (`CONFIG_ANON_VMA_NAME`).
          // Many distros, such as Ubuntu and Arch enable it. On earlier kernel versions or kernels without the feature, this call can fail.
          //
          // It's OK for this to fail because (per-usecase):
          // 1. "Find it by name" => As a fallback, it's possible to scan the mappings and for the memfd name.
          // 2. "Hook on prctl" => When hooking on prctl via eBPF it's still possible to see this call, even when it's not supported/enabled.
          //    This works even on older kernels! For this reason we unconditionally make this call even on older kernels -- to
          //    still allow detection via hooking onto prctl.

          return Result.withSuccess();
      } catch (Throwable e) {
          dropCurrent();
          return Result.withError("Exception during publish: " + e.getMessage());
      }
  }

  private static Result update(long publishedAtNs, Data data) {
      if (data == null || !ctxIsPublished(publishedState)) {
          return Result.withError("Unexpected: data is null or context is not published");
      }

      try {
          // Step: Prepare the new payload to be published
          // The payload SHOULD be ready and valid before trying to actually update the mapping.
          byte[] payloadResult = encodeProtobufPayload(data);
          MemorySegment newPayloadSegment = globalArena.allocate(payloadResult.length);
          newPayloadSegment.copyFrom(MemorySegment.ofArray(payloadResult));

          MemorySegment mapping = publishedState.mapping;

          // Step: Zero out published_at_ns in the mapping
          // This enables readers to detect that an update is in-progress
          mapping.set(JAVA_LONG, 16, 0L);

          // Step: Synchronization - Make sure readers observe the zeroing above before anything else below
          java.lang.invoke.VarHandle.fullFence();

          // Step: Install updated data
          mapping.set(JAVA_INT, 12, payloadResult.length);
          mapping.set(ADDRESS, 24, newPayloadSegment);

          // Step: Synchronization - Make sure readers observe the updated data before anything else below
          java.lang.invoke.VarHandle.fullFence();

          // Step: Install new published_at_ns
          // The update is now complete -- readers that observe the new timestamp will observe the updated payload
          mapping.set(JAVA_LONG, 16, publishedAtNs);

          // Step: Attempt to name the mapping so outside readers can detect the update
          MemorySegment nameSegment = globalArena.allocateFrom(OTEL_CTX_SIGNATURE);
          PRCTL.invoke(
              PR_SET_VMA,
              PR_SET_VMA_ANON_NAME,
              mapping,
              MAPPING_SIZE,
              nameSegment
          );
          // It's OK for this to fail -- see publish for why

          // Step: Update bookkeeping
          // The old payload segment is managed by the global arena, so we don't need to explicitly free it
          publishedState = new PublishedState(publishedState.publisherPid, mapping, newPayloadSegment);

          return Result.withSuccess();
      } catch (Throwable e) {
          return Result.withError("Exception during update: " + e.getMessage());
      }
  }

  public static boolean dropCurrent() {
      PublishedState state = publishedState;

      // Zero out the state and make sure no operations below are reordered with zeroing
      publishedState = null;
      java.lang.invoke.VarHandle.fullFence();

      boolean success = true;

      // The mapping only exists if it was created by the current process; if it was inherited by a fork it doesn't exist anymore
      // (due to the MADV_DONTFORK) and we don't need to do anything to it.
      if (ctxIsPublished(state)) {
          try {
              int munmapResult = (Integer) MUNMAP.invoke(state.mapping, MAPPING_SIZE);
              success = munmapResult != -1;
          } catch (Throwable e) {
              success = false;
          }
      }

      // The payload is managed by the global arena, so we don't need to explicitly free it

      return success;
  }
}
