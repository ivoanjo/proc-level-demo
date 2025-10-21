// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License (Version 2.0).
// This product includes software developed at Datadog (https://www.datadoghq.com/) Copyright 2025 Datadog, Inc.

#include "otel_process_ctx.h"

#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif

#ifdef __cplusplus
  #include <atomic>
  using std::atomic_thread_fence;
  using std::memory_order_seq_cst;
#else
  #include <stdatomic.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>

#define ADD_QUOTES_HELPER(x) #x
#define ADD_QUOTES(x) ADD_QUOTES_HELPER(x)
#define KEY_VALUE_LIMIT 4096
#define UINT14_MAX 16383

#ifndef PR_SET_VMA
  #define PR_SET_VMA            0x53564d41
  #define PR_SET_VMA_ANON_NAME  0
#endif

static const otel_process_ctx_data empty_data = {
  .deployment_environment_name = NULL,
  .service_instance_id = NULL,
  .service_name = NULL,
  .service_version = NULL,
  .telemetry_sdk_language = NULL,
  .telemetry_sdk_version = NULL,
  .telemetry_sdk_name = NULL,
  .resources = NULL
};

#if (defined(OTEL_PROCESS_CTX_NOOP) && OTEL_PROCESS_CTX_NOOP) || !defined(__linux__)
  // NOOP implementations when OTEL_PROCESS_CTX_NOOP is defined or not on Linux

  otel_process_ctx_result otel_process_ctx_publish(const otel_process_ctx_data *data) {
    (void) data; // Suppress unused parameter warning
    return (otel_process_ctx_result) {.success = false, .error_message = "OTEL_PROCESS_CTX_NOOP mode is enabled - no-op implementation (" __FILE__ ":" ADD_QUOTES(__LINE__) ")"};
  }

  bool otel_process_ctx_drop_current(void) {
    return true; // Nothing to do, this always succeeds
  }

  #ifndef OTEL_PROCESS_CTX_NO_READ
    otel_process_ctx_read_result otel_process_ctx_read(void) {
      return (otel_process_ctx_read_result) {.success = false, .error_message = "OTEL_PROCESS_CTX_NOOP mode is enabled - no-op implementation (" __FILE__ ":" ADD_QUOTES(__LINE__) ")", .data = empty_data};
    }

    bool otel_process_ctx_read_drop(otel_process_ctx_read_result *result) {
      (void) result; // Suppress unused parameter warning
      return false;
    }
  #endif // OTEL_PROCESS_CTX_NO_READ
#else // OTEL_PROCESS_CTX_NOOP

/**
 * The process context data that's written into the published anonymous mapping.
 *
 * An outside-of-process reader will read this struct + otel_process_payload to get the data.
 */
typedef struct __attribute__((packed, aligned(8))) {
  char otel_process_ctx_signature[8];        // Always "OTEL_CTX"
  uint32_t otel_process_ctx_version;         // Always > 0, incremented when the data structure changes, currently v2
  uint64_t otel_process_ctx_published_at_ns; // Always > 0, timestamp from when the context was published in nanoseconds since epoch
  uint32_t otel_process_payload_size;        // Always > 0, size of storage
  char *otel_process_payload;                // Always non-null, points to the storage for the data; expected to be a protobuf map of string key/value pairs, null-terminated
} otel_process_ctx_mapping;

/**
 * The full state of a published process context.
 *
 * This is returned as an opaque type to the caller.
 *
 * It is used to store the all data for the process context and that needs to be kept around while the context is published.
 */
typedef struct {
  // The pid of the process that published the context.
  pid_t publisher_pid;
  // The actual mapping of the process context. Note that because we `madvise(..., MADV_DONTFORK)` this mapping is not
  // propagated to child processes and thus `mapping` is only valid on the process that published the context.
  otel_process_ctx_mapping *mapping;
  // The process context payload.
  char *payload;
} otel_process_ctx_state;

/**
 * Only one context is active, so we keep its state as a global.
 */
static otel_process_ctx_state published_state;

static otel_process_ctx_result otel_process_ctx_encode_protobuf_payload(char **out, uint32_t *out_size, otel_process_ctx_data data);

// We use a mapping size of 2 pages explicitly as a hint when running on legacy kernels that don't support the
// PR_SET_VMA_ANON_NAME prctl call; see below for more details.
static long size_for_mapping(void) {
  long page_size_bytes = sysconf(_SC_PAGESIZE);
  if (page_size_bytes < 4096) {
    return -1;
  }
  return page_size_bytes * 2;
}

static uint64_t time_now_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
    return 0;
  }
  return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// The process context is designed to be read by an outside-of-process reader. Thus, for concurrency purposes the steps
// on this method are ordered in a way to avoid races, or if not possible to avoid, to allow the reader to detect if there was a race.
otel_process_ctx_result otel_process_ctx_publish(const otel_process_ctx_data *data) {
  // Step: Drop any previous context it if it exists
  // No state should be around anywhere after this step.
  if (!otel_process_ctx_drop_current()) {
    return (otel_process_ctx_result) {.success = false, .error_message = "Failed to drop previous context (" __FILE__ ":" ADD_QUOTES(__LINE__) ")"};
  }

  // Step: Determine size for mapping
  long mapping_size = size_for_mapping();
  if (mapping_size == -1) {
    return (otel_process_ctx_result) {.success = false, .error_message = "Failed to get page size (" __FILE__ ":" ADD_QUOTES(__LINE__) ")"};
  }

  // Step: Prepare the payload to be published
  // The payload SHOULD be ready and valid before trying to actually create the mapping.
  if (!data) return (otel_process_ctx_result) {.success = false, .error_message = "otel_process_ctx_data is NULL (" __FILE__ ":" ADD_QUOTES(__LINE__) ")"};
  uint32_t payload_size = 0;
  otel_process_ctx_result result = otel_process_ctx_encode_protobuf_payload(&published_state.payload, &payload_size, *data);
  if (!result.success) return result;

  // Step: Create the mapping
  published_state.publisher_pid = getpid(); // This allows us to detect in forks that we shouldn't touch the mapping
  published_state.mapping = (otel_process_ctx_mapping *)
    mmap(NULL, mapping_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (published_state.mapping == MAP_FAILED) {
    otel_process_ctx_drop_current();
    return (otel_process_ctx_result) {.success = false, .error_message = "Failed to allocate mapping (" __FILE__ ":" ADD_QUOTES(__LINE__) ")"};
  }

  // Step: Setup MADV_DONTFORK
  // This ensures that the mapping is not propagated to child processes (they should call update/publish again).
  if (madvise(published_state.mapping, mapping_size, MADV_DONTFORK) == -1) {
    if (otel_process_ctx_drop_current()) {
      return (otel_process_ctx_result) {.success = false, .error_message = "Failed to setup MADV_DONTFORK (" __FILE__ ":" ADD_QUOTES(__LINE__) ")"};
    } else {
      return (otel_process_ctx_result) {.success = false, .error_message = "Failed to drop previous context (" __FILE__ ":" ADD_QUOTES(__LINE__) ")"};
    }
  }

  // Step: Populate the mapping
  // The payload and any extra fields must come first and not be reordered with the signature by the compiler.

  uint64_t published_at_ns = time_now_ns();
  if (published_at_ns == 0) {
    return (otel_process_ctx_result) {.success = false, .error_message = "Failed to get current time (" __FILE__ ":" ADD_QUOTES(__LINE__) ")"};
  }

  *published_state.mapping = (otel_process_ctx_mapping) {
    .otel_process_ctx_signature = {0}, // Set in "Step: Populate the signature into the mapping" below
    .otel_process_ctx_version = 2,
    .otel_process_ctx_published_at_ns = published_at_ns,
    .otel_process_payload_size = payload_size,
    .otel_process_payload = published_state.payload
  };

  // Step: Synchronization - Mapping has been filled and is missing signature
  // Make sure the initialization of the mapping + payload above does not get reordered with setting the signature below. Setting
  // the signature is what tells an outside reader that the context is fully published.
  atomic_thread_fence(memory_order_seq_cst);

  // Step: Populate the signature into the mapping
  // The signature must come last and not be reordered with the fields above by the compiler. After this step, external readers
  // can read the signature and know that the payload is ready to be read.
  memcpy(published_state.mapping->otel_process_ctx_signature, "OTEL_CTX", sizeof(published_state.mapping->otel_process_ctx_signature));

  // Step: Change permissions on the mapping to only read permission
  // We've observed the combination of anonymous mapping + a given number of pages + read-only permission is not very common,
  // so this is left as a hint for when running on older kernels and the naming the mapping feature below isn't available.
  // For modern kernels, doing this is harmless so we do it unconditionally.
  if (mprotect(published_state.mapping, mapping_size, PROT_READ) == -1) {
    if (otel_process_ctx_drop_current()) {
      return (otel_process_ctx_result) {.success = false, .error_message = "Failed to change permissions on mapping (" __FILE__ ":" ADD_QUOTES(__LINE__) ")"};
    } else {
      return (otel_process_ctx_result) {.success = false, .error_message = "Failed to drop previous context (" __FILE__ ":" ADD_QUOTES(__LINE__) ")"};
    }
  }

  // Step: Name the mapping so outside readers can:
  // * Find it by name
  // * Hook on prctl to detect when new mappings are published
  if (prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, published_state.mapping, mapping_size, "OTEL_CTX") == -1) {
    // Naming an anonymous mapping is a Linux 5.17+ feature. On earlier versions, this method call can fail. Thus it's OK
    // for this to fail because:
    // 1. Things that hook on prctl are still able to see this call, even though it's not supported (TODO: Confirm this is actually the case)
    // 2. As a fallback, on older kernels, it's possible to scan the mappings and look for the "OTEL_CTX" signature in the memory itself,
    //    after observing the mapping has the expected number of pages and permissions.
  }

  // All done!

  return (otel_process_ctx_result) {.success = true, .error_message = NULL};
}

bool otel_process_ctx_drop_current(void) {
  otel_process_ctx_state state = published_state;

  // Zero out the state and make sure no operations below are reordered with zeroing
  published_state = (otel_process_ctx_state) {.publisher_pid = 0, .mapping = NULL, .payload = NULL};
  atomic_thread_fence(memory_order_seq_cst);

  // The mapping only exists if it was created by the current process; if it was inherited by a fork it doesn't exist anymore
  // (due to the MADV_DONTFORK) and we don't need to do anything to it.
  if (state.mapping != NULL && state.mapping != MAP_FAILED && getpid() == state.publisher_pid) {
    long mapping_size = size_for_mapping();
    if (mapping_size == -1 || munmap(state.mapping, mapping_size) == -1) return false;
  }

  // The payload may have been inherited from a parent. This is a regular malloc so we need to free it so we don't leak.
  if (state.payload) free(state.payload);

  return true;
}

// The caller is responsible for enforcing that value fits within UINT14_MAX
static size_t protobuf_varint_size(uint16_t value) { return value >= 128 ? 2 : 1; }

// Field tag for record + varint len + data
static size_t protobuf_record_size(size_t len) { return 1 + protobuf_varint_size(len) + len; }

static size_t protobuf_string_size(char *str) { return protobuf_record_size(strlen(str)); }

// As a simplification, we enforce that keys and values are <= 4096 (KEY_VALUE_LIMIT) so that their size + extra bytes always fits within UINT14_MAX
static otel_process_ctx_result validate_and_calculate_protobuf_payload_size(size_t *out_pairs_size, char **pairs, bool fixed_key_fields) {
  size_t num_entries = 0;
  for (size_t i = 0; pairs[i] != NULL; i++) num_entries++;
  if (num_entries % 2 != 0) {
    return (otel_process_ctx_result) {.success = false, .error_message = "Value in otel_process_ctx_data is NULL (" __FILE__ ":" ADD_QUOTES(__LINE__) ")"};
  }

  *out_pairs_size = 0;
  for (size_t i = 0; pairs[i * 2] != NULL; i++) {
    size_t key_len = strlen(pairs[i * 2]);
    if (key_len > KEY_VALUE_LIMIT) {
      return (otel_process_ctx_result) {.success = false, .error_message = "Length of key in otel_process_ctx_data exceeds 4096 limit (" __FILE__ ":" ADD_QUOTES(__LINE__) ")"};
    }
    size_t value_len = strlen(pairs[i * 2 + 1]);
    if (value_len > KEY_VALUE_LIMIT) {
      return (otel_process_ctx_result) {.success = false, .error_message = "Length of value in otel_process_ctx_data exceeds 4096 limit (" __FILE__ ":" ADD_QUOTES(__LINE__) ")"};
    }
    size_t pair_size = protobuf_record_size(value_len);
    if (!fixed_key_fields) {
      pair_size += protobuf_record_size(key_len);
      pair_size += 1 + protobuf_varint_size(pair_size); // Field tag for record (1) + varint len (1 or 2)
    }

    *out_pairs_size += pair_size;
  }
  return (otel_process_ctx_result) {.success = true, .error_message = NULL};
}

/**
 * Writes a protobuf varint encoding for the given value.
 * As a simplification, only supports values that fit in 1 or 2 bytes (0-16383 UINT14_MAX).
 */
static void write_protobuf_varint(char **ptr, uint16_t value) {
  if (protobuf_varint_size(value) == 1) {
    *(*ptr)++ = (char)value;
  } else {
    // Two bytes: first byte has MSB set, second byte has value
    *(*ptr)++ = (char)((value & 0x7F) | 0x80); // Low 7 bits + continuation bit
    *(*ptr)++ = (char)(value >> 7);            // High 7 bits
  }
}

static void write_protobuf_string(char **ptr, const char *str) {
  size_t len = strlen(str);
  write_protobuf_varint(ptr, len);
  memcpy(*ptr, str, len);
  *ptr += len;
}

static void write_protobuf_tag(char **ptr, uint8_t field_number) {
  *(*ptr)++ = (char)((field_number << 3) | 2); // Field type is always 2 (LEN)
}

// TODO: The serialization format is still under discussion and is not considered stable yet.
// Comments **very** welcome.
//
// Encode the payload as protobuf bytes.
//
// This method implements an extremely compact but limited protobuf encoder for the otel_process_ctx.proto message.
// For extra compact code, it fixes strings at up to 4096 bytes.
static otel_process_ctx_result otel_process_ctx_encode_protobuf_payload(char **out, uint32_t *out_size, otel_process_ctx_data data) {
  const char *pairs[] = {
    "deployment.environment.name", data.deployment_environment_name,
    "service.instance.id", data.service_instance_id,
    "service.name", data.service_name,
    "service.version", data.service_version,
    "telemetry.sdk.language", data.telemetry_sdk_language,
    "telemetry.sdk.version", data.telemetry_sdk_version,
    "telemetry.sdk.name", data.telemetry_sdk_name,
    NULL
  };

  size_t pairs_size = 0;
  otel_process_ctx_result validation_result = validate_and_calculate_protobuf_payload_size(&pairs_size, (char **) pairs, true);
  if (!validation_result.success) return validation_result;

  size_t resources_pairs_size = 0;
  if (data.resources != NULL) {
    validation_result = validate_and_calculate_protobuf_payload_size(&resources_pairs_size, data.resources, false);
    if (!validation_result.success) return validation_result;
  }

  size_t total_size = pairs_size + resources_pairs_size;

  char *encoded = (char *) calloc(total_size, 1);
  if (!encoded) {
    return (otel_process_ctx_result) {.success = false, .error_message = "Failed to allocate memory for payload (" __FILE__ ":" ADD_QUOTES(__LINE__) ")"};
  }
  char *ptr = encoded;

  for (size_t i = 0; pairs[i * 2] != NULL; i++) {
    write_protobuf_tag(&ptr, i + 2); // Fixed fields are numbered from 2
    write_protobuf_string(&ptr, pairs[i * 2 + 1]); // Write value
  }

  if (data.resources != NULL) {
    for (size_t i = 0; data.resources[i * 2] != NULL; i++) {
      char *key = data.resources[i * 2];
      char *value = data.resources[i * 2 + 1];
      write_protobuf_tag(&ptr, 1); // Resources field is field number 1
      write_protobuf_varint(&ptr, protobuf_string_size(key) + protobuf_string_size(value));
      write_protobuf_tag(&ptr, 1); // Key is field number 1 in the submessage
      write_protobuf_string(&ptr, key);
      write_protobuf_tag(&ptr, 2); // Value is field number 2 in the submessage
      write_protobuf_string(&ptr,value);
    }
  }

  *out = encoded;
  *out_size = (uint32_t) total_size;

  return (otel_process_ctx_result) {.success = true, .error_message = NULL};
}

#ifndef OTEL_PROCESS_CTX_NO_READ
  #include <inttypes.h>
  #include <limits.h>
  #include <sys/uio.h>
  #include <sys/utsname.h>

  // Note: The below parsing code is only for otel_process_ctx_read and is only provided for debugging
  // and testing purposes.

  // Named mappings are supported on Linux 5.17+
  static bool named_mapping_supported(void) {
    struct utsname uts;
    int major, minor;
    if (uname(&uts) != 0 || sscanf(uts.release, "%d.%d", &major, &minor) != 2) return false;
    return (major > 5) || (major == 5 && minor >= 17);
  }

  static void *parse_mapping_start(char *line) {
    char *endptr = NULL;
    unsigned long long start = strtoull(line, &endptr, 16);
    if (start == 0 || start == ULLONG_MAX) return NULL;
    return (void *)(uintptr_t) start;
  }

  static bool is_otel_process_ctx_mapping(char *line) {
    size_t name_len = sizeof("[anon:OTEL_CTX]") - 1;
    size_t line_len = strlen(line);
    if (line_len < name_len) return false;
    if (line[line_len-1] == '\n') line[--line_len] = '\0';

    // Validate expected permission
    if (strstr(line, " r--p ") == NULL) return false;

    // Validate expected context size
    int64_t start, end;
    if (sscanf(line, "%" PRIx64 "-%" PRIx64, &start, &end) != 2) return false;
    if (start == 0 || end == 0 || end <= start) return false;
    if ((end - start) != size_for_mapping()) return false;

    if (named_mapping_supported()) {
      // On Linux 5.17+, check if the line ends with [anon:OTEL_CTX]
      return memcmp(line + (line_len - name_len), "[anon:OTEL_CTX]", name_len) == 0;
    } else {
      // On older kernels, parse the address to to find the OTEL_CTX signature
      void *addr = parse_mapping_start(line);
      if (addr == NULL) return false;

      // Read 8 bytes at the address using process_vm_readv (to avoid any issues with concurrency/races)
      char buffer[8];
      struct iovec local[] = {{.iov_base = buffer, .iov_len = sizeof(buffer)}};
      struct iovec remote[] = {{.iov_base = addr, .iov_len = sizeof(buffer)}};

      ssize_t bytes_read = process_vm_readv(getpid(), local, 1, remote, 1, 0);
      if (bytes_read != sizeof(buffer)) return false;

      return memcmp(buffer, "OTEL_CTX", sizeof(buffer)) == 0;
    }
  }

  static otel_process_ctx_mapping *try_finding_mapping(void) {
    char line[8192];
    otel_process_ctx_mapping *result = NULL;

    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return result;

    while (fgets(line, sizeof(line), fp)) {
      if (is_otel_process_ctx_mapping(line)) {
        result = (otel_process_ctx_mapping *)parse_mapping_start(line);
        break;
      }
    }

    fclose(fp);
    return result;
  }

  // Helper function to read a protobuf varint (limited to 1-2 bytes, max value UINT14_MAX, matching write_protobuf_varint above)
  static bool read_protobuf_varint(char **ptr, char *end_ptr, uint16_t *value) {
    if (*ptr >= end_ptr) return false; // Out of bounds

    unsigned char first_byte = (unsigned char)**ptr;
    (*ptr)++;

    if (first_byte < 128) {
      *value = first_byte;
      return true;
    } else {
      if (*ptr >= end_ptr) return false; // Out of bounds
      unsigned char second_byte = (unsigned char)**ptr;
      (*ptr)++;

      *value = (first_byte & 0x7F) | (second_byte << 7);
      return *value <= UINT14_MAX;
    }
  }

  // Helper function to read a protobuf string, within the same limits as the encoder imposes
  static bool read_protobuf_string(char **ptr, char *end_ptr, char **out_string) {
    uint16_t len;
    if (!read_protobuf_varint(ptr, end_ptr, &len)) return false;

    if (len > KEY_VALUE_LIMIT) return false; // Enforce same limit as encoder
    if (*ptr + len > end_ptr) return false; // Check bounds

    *out_string = (char *) calloc(len + 1, 1);
    if (!*out_string) return false;

    memcpy(*out_string, *ptr, len);
    (*out_string)[len] = '\0';
    *ptr += len;

    return true;
  }

  // Reads field name and validates the fixed LEN wire type
  static bool read_protobuf_tag(char **ptr, char *end_ptr, uint8_t *field_number, uint8_t *wire_type) {
    if (*ptr >= end_ptr) return false;

    unsigned char tag = (unsigned char)**ptr;
    (*ptr)++;

    *wire_type = tag & 0x07;
    *field_number = tag >> 3;

    return *wire_type == 2; // We only need the LEN wire type for now
  }

  // Simplified protobuf decoder to match the exact encoder above. If the protobuf data doesn't match the encoder, this will
  // return false.
  static bool otel_process_ctx_decode_payload(char *payload, uint32_t payload_size, otel_process_ctx_data *data_out) {
    char *ptr = payload;
    char *end_ptr = payload + payload_size;

    *data_out = empty_data;

    size_t resource_index = 0;
    size_t resource_capacity = 201; // Allocate space for 100 pairs + NULL terminator entry

    while (ptr < end_ptr) {
      uint8_t field_number, wire_type;
      if (!read_protobuf_tag(&ptr, end_ptr, &field_number, &wire_type)) return false;

      // Handle resources field (field 1)
      if (field_number == 1) {
        if (!data_out->resources) {
          data_out->resources = (char **) calloc(resource_capacity, sizeof(char *));
          if (!data_out->resources) return false;
        } else if (resource_index + 2 >= resource_capacity) {
          return false;
        }

        uint16_t resource_len;
        if (!read_protobuf_varint(&ptr, end_ptr, &resource_len)) return false;
        char *resource_ptr = ptr;
        char *resource_end = ptr + resource_len;

        if (resource_end > end_ptr) return false; // Invalid length

        // Parse the resource submessage (assuming key-value pairs in order)
        uint8_t sub_field_number, sub_wire_type;
        // Read key (field 1)
        char *key;
        if (
            !read_protobuf_tag(&resource_ptr, resource_end, &sub_field_number, &sub_wire_type) ||
            sub_field_number != 1 ||
            !read_protobuf_string(&resource_ptr, resource_end, &key)) {
          return false;
        }
        data_out->resources[resource_index++] = key;

        // Read value (field 2)
        char *value;
        if (!read_protobuf_tag(&resource_ptr, resource_end, &sub_field_number, &sub_wire_type) ||
            sub_field_number != 2 ||
            !read_protobuf_string(&resource_ptr, resource_end, &value)) {
          return false;
        }
        data_out->resources[resource_index++] = value;

        ptr = resource_end; // Move past this resource
        continue;
      }

      // Handle fixed fields
      if (field_number >= 2 && field_number <= 9) {
        char *value;
        if (!read_protobuf_string(&ptr, end_ptr, &value)) return false;

        char **field_ptr = NULL;
        switch (field_number) {
          case 2: field_ptr = &data_out->deployment_environment_name; break;
          case 3: field_ptr = &data_out->service_instance_id; break;
          case 4: field_ptr = &data_out->service_name; break;
          case 5: field_ptr = &data_out->service_version; break;
          case 6: field_ptr = &data_out->telemetry_sdk_language; break;
          case 7: field_ptr = &data_out->telemetry_sdk_version; break;
          case 8: field_ptr = &data_out->telemetry_sdk_name; break;
        }

        if (field_ptr == NULL || *field_ptr != NULL) {
          free(value);
          return false;
        }

        *field_ptr = value;
      } else {
        return false;
      }
    }

    // Validate all required fields were found
    return data_out->deployment_environment_name != NULL &&
           data_out->service_instance_id != NULL &&
           data_out->service_name != NULL &&
           data_out->service_version != NULL &&
           data_out->telemetry_sdk_language != NULL &&
           data_out->telemetry_sdk_version != NULL &&
           data_out->telemetry_sdk_name != NULL;
  }

  void otel_process_ctx_read_data_drop(otel_process_ctx_data data) {
    if (data.deployment_environment_name) free(data.deployment_environment_name);
    if (data.service_instance_id) free(data.service_instance_id);
    if (data.service_name) free(data.service_name);
    if (data.service_version) free(data.service_version);
    if (data.telemetry_sdk_language) free(data.telemetry_sdk_language);
    if (data.telemetry_sdk_version) free(data.telemetry_sdk_version);
    if (data.telemetry_sdk_name) free(data.telemetry_sdk_name);
    if (data.resources) {
      for (int i = 0; data.resources[i] != NULL; i++) free(data.resources[i]);
      free(data.resources);
    }
  }

  otel_process_ctx_read_result otel_process_ctx_read(void) {
    otel_process_ctx_mapping *mapping = try_finding_mapping();
    if (!mapping) {
      return (otel_process_ctx_read_result) {.success = false, .error_message = "No OTEL_CTX mapping found (" __FILE__ ":" ADD_QUOTES(__LINE__) ")", .data = empty_data};
    }

    if (strncmp(mapping->otel_process_ctx_signature, "OTEL_CTX", sizeof(mapping->otel_process_ctx_signature)) != 0 || mapping->otel_process_ctx_version != 2) {
      return (otel_process_ctx_read_result) {.success = false, .error_message = "Invalid OTEL_CTX signature or version (" __FILE__ ":" ADD_QUOTES(__LINE__) ")", .data = empty_data};
    }

    otel_process_ctx_data data = empty_data;

    if (!otel_process_ctx_decode_payload(mapping->otel_process_payload, mapping->otel_process_payload_size, &data)) {
      otel_process_ctx_read_data_drop(data);
      return (otel_process_ctx_read_result) {.success = false, .error_message = "Failed to decode payload (" __FILE__ ":" ADD_QUOTES(__LINE__) ")", .data = empty_data};
    }

    return (otel_process_ctx_read_result) {.success = true, .error_message = NULL, .data = data};
  }

  bool otel_process_ctx_read_drop(otel_process_ctx_read_result *result) {
    if (!result || !result->success) return false;

    // Free allocated strings in the data
    otel_process_ctx_read_data_drop(result->data);

    // Reset the result to empty state
    *result = (otel_process_ctx_read_result) {.success = false, .error_message = "Data dropped", .data = empty_data};

    return true;
  }
#endif // OTEL_PROCESS_CTX_NO_READ

#endif // OTEL_PROCESS_CTX_NOOP
