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
 * * Emit the process context payload in protobof without any additional dependencies.
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

  private static final Linker LINKER = Linker.nativeLinker();
  private static final SymbolLookup LIBC = LINKER.defaultLookup();

  private static final MethodHandle MMAP;
  private static final MethodHandle MUNMAP;
  private static final MethodHandle MADVISE;
  private static final MethodHandle MPROTECT;
  private static final MethodHandle PRCTL;
  private static final MethodHandle SYSCONF;

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
          MPROTECT = LINKER.downcallHandle(
              LIBC.find("mprotect").orElseThrow(),
              FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, JAVA_INT)
          );
          PRCTL = LINKER.downcallHandle(
              LIBC.find("prctl").orElseThrow(),
              FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT, ADDRESS, JAVA_LONG, ADDRESS)
          );
          SYSCONF = LINKER.downcallHandle(
              LIBC.find("sysconf").orElseThrow(),
              FunctionDescriptor.of(JAVA_LONG, JAVA_INT)
          );
      } catch (Throwable e) {
          throw new RuntimeException("Failed to initialize native method handles", e);
      }
  }

  private static record PublishedState(MemorySegment mapping, long mappingSize) { }

  private static PublishedState publishedState = null;
  private static final Arena globalArena = Arena.global();

  private static int protobufVarintSize(int value) {
      return value >= 128 ? 2 : 1;
  }

  private static int protobufRecordSize(int len) {
      return 1 + protobufVarintSize(len) + len;
  }

  private static int protobufStringSize(String str) {
      return protobufRecordSize(str.getBytes(StandardCharsets.UTF_8).length);
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

  private static String validateString(String str) {
      if (str == null || protobufStringSize(str) > KEY_VALUE_LIMIT) {
          throw new IllegalArgumentException("Invalid string");
      }
      return str;
  }

  private static byte[] encodeProtobufPayload(Data data) {
      String[] fixedFields = {
          data.deploymentEnvironmentName,
          data.serviceInstanceId,
          data.serviceName,
          data.serviceVersion,
          data.telemetrySdkLanguage,
          data.telemetrySdkVersion,
          data.telemetrySdkName
      };

      int pairsSize = 0;
      for (String field : fixedFields) {
          validateString(field);
          pairsSize += protobufStringSize(field);
      }

      int resourcesSize = 0;
      if (data.resources != null) {
          for (Map.Entry<String, String> entry : data.resources.entrySet()) {
              String key = validateString(entry.getKey());
              String value = validateString(entry.getValue());
              int pairSize = protobufStringSize(key) + protobufStringSize(value);
              resourcesSize += pairSize + 1 + protobufVarintSize(pairSize);
          }
      }

      int totalSize = pairsSize + resourcesSize;
      byte[] encoded = new byte[totalSize];
      int[] offset = {0};

      // Write fixed fields (numbered from 2)
      for (int i = 0; i < fixedFields.length; i++) {
          writeProtobufTag(encoded, offset, i + 2);
          writeProtobufString(encoded, offset, fixedFields[i]);
      }

      // Write resources (field number 1)
      if (data.resources != null) {
          for (Map.Entry<String, String> entry : data.resources.entrySet()) {
              String key = entry.getKey();
              String value = entry.getValue();

              writeProtobufTag(encoded, offset, 1); // Resources field is field number 1
              writeProtobufVarint(encoded, offset, protobufStringSize(key) + protobufStringSize(value));
              writeProtobufTag(encoded, offset, 1); // Key is field number 1 in the submessage
              writeProtobufString(encoded, offset, key);
              writeProtobufTag(encoded, offset, 2); // Value is field number 2 in the submessage
              writeProtobufString(encoded, offset, value);
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

  // The process context is designed to be read by an outside-of-process reader. Thus, for concurrency purposes the steps
  // on this method are ordered in a way to avoid races, or if not possible to avoid, to allow the reader to detect if there was a race.
  public static Result publish(Data data) {
      if (data == null) return Result.withError("Data cannot be null");

      try {
          // Step: Drop any previous context it if it exists
          // No state should be around anywhere after this step.
          if (!dropCurrent()) {
              return Result.withError("Failed to drop previous context");
          }

          // Step: Determine size for mapping (2 pages)
          long pageSize = (Long) SYSCONF.invoke(30); // _SC_PAGESIZE
          if (pageSize < 4096) {
              return Result.withError("Failed to get page size");
          }
          long mappingSize = pageSize * 2;

          // Step: Prepare the payload to be published
          // The payload SHOULD be ready and valid before trying to actually create the mapping.
          byte[] payloadResult = encodeProtobufPayload(data);
          // Store the encoded payload in global arena
          MemorySegment payloadSegment = globalArena.allocate(payloadResult.length);
          payloadSegment.copyFrom(MemorySegment.ofArray(payloadResult));
          // TODO: We should make sure to drop `payloadSegment` when the mapping gets dropped

          // Step: Create the mapping
          MemorySegment mapping = ((MemorySegment) MMAP.invoke(
              MemorySegment.NULL,           // addr
              mappingSize,                  // length
              PROT_READ | PROT_WRITE,       // prot
              MAP_PRIVATE | MAP_ANONYMOUS,  // flags
              -1,                           // fd
              0                             // offset
          )).reinterpret(mappingSize);

          // Check if mmap failed - in C, MAP_FAILED is (void*)-1
          if (mapping.address() == -1L) {
              dropCurrent();
              return Result.withError("Failed to allocate mapping");
          }

          publishedState = new PublishedState(mapping, mappingSize);

          // Step: Setup MADV_DONTFORK
          // This ensures that the mapping is not propagated to child processes (they should call update/publish again).
          int madviseResult = (Integer) MADVISE.invoke(mapping, mappingSize, MADV_DONTFORK);
          if (madviseResult == -1) {
              if (dropCurrent()) {
                  return Result.withError("Failed to setup MADV_DONTFORK");
              } else {
                  return Result.withError("Failed to drop previous context");
              }
          }

          // Step: Populate the mapping
          // The payload and any extra fields must come first and not be reordered with the signature by the compiler.

          // Get current time in nanoseconds since epoch
          Instant now = Instant.now();
          long publishedAtNs = now.getEpochSecond() * 1_000_000_000L + now.getNano();

          mapping.set(ADDRESS, 0, MemorySegment.NULL); // signature placeholder
          mapping.set(JAVA_INT, 8, OTEL_CTX_VERSION);
          // Use unaligned long since offset 12 is not 8-byte aligned (C struct is packed)
          mapping.set(JAVA_LONG_UNALIGNED, 12, publishedAtNs);
          mapping.set(JAVA_INT, 20, payloadResult.length);
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
          // TODO: Should we somehow clean up `signatureSegment`?

          // Step: Change permissions on the mapping to only read permission
          // We've observed the combination of anonymous mapping + a given number of pages + read-only permission is not very common,
          // so this is left as a hint for when running on older kernels and the naming the mapping feature below isn't available.
          // For modern kernels, doing this is harmless so we do it unconditionally.
          int mprotectResult = (Integer) MPROTECT.invoke(mapping, mappingSize, PROT_READ);
          if (mprotectResult == -1) {
              if (dropCurrent()) {
                  return Result.withError("Failed to change permissions on mapping");
              } else {
                  return Result.withError("Failed to drop previous context");
              }
          }

          // Step: Name the mapping so outside readers can:
          // * Find it by name
          // * Hook on prctl to detect when new mappings are published
          //
          // Naming an anonymous mapping is a Linux 5.17+ feature. On earlier versions, this method call can fail. Thus it's OK
          // for this to fail because:
          // 1. Things that hook on prctl are still able to see this call, even though it's not supported
          // 2. As a fallback, on older kernels, it's possible to scan the mappings and look for the "OTEL_CTX" signature in the memory itself,
          //    after observing the mapping has the expected number of pages and permissions.
          MemorySegment nameSegment = globalArena.allocateFrom("OTEL_CTX");
          PRCTL.invoke(
              PR_SET_VMA,
              PR_SET_VMA_ANON_NAME,
              mapping,
              mappingSize,
              nameSegment
          );

          return Result.withSuccess();
      } catch (Throwable e) {
          dropCurrent();
          return Result.withError("Exception during publish: " + e.getMessage());
      }
  }

  public static boolean dropCurrent() {
      PublishedState state = publishedState;
      publishedState = null;

      // Unmap if mapping exists
      if (state != null) {
          try {
              int munmapResult = (Integer) MUNMAP.invoke(state.mapping, state.mappingSize);
              return munmapResult != -1;
          } catch (Throwable e) {
              return false;
          }
      }

      return true;
  }
}
