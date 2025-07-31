#include <csignal>  // for std::signal, SIGINT
#include <iostream> // for std::cout
#include <memory>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h> // for pause()
#include <vector>

// A flag that tells us when SIGINT has arrived.
// sig_atomic_t is guaranteed safe to modify in a signal handler.
static volatile sig_atomic_t sigint_received = 0;
// Simple handler: set the flag when SIGINT arrives.
extern "C" void handle_sigint(int) { sigint_received = 1; }

void write_utf8_string(std::vector<uint8_t> &buffer, const std::string &str) {
  uint32_t length = str.length();
  buffer.insert(buffer.end(), reinterpret_cast<uint8_t *>(&length),
                reinterpret_cast<uint8_t *>(&length) + sizeof(length));
  buffer.insert(buffer.end(), str.begin(), str.end());
}

const std::unique_ptr<uint8_t *>
generate_process_correlation_storage(std::string default_service,
                                     std::string default_environment,
                                     std::string runtime_id) {
  std::vector<uint8_t> buffer;

  uint16_t layout_minor_version = 2;
  buffer.insert(buffer.end(),
                reinterpret_cast<uint8_t *>(&layout_minor_version),
                reinterpret_cast<uint8_t *>(&layout_minor_version) +
                    sizeof(layout_minor_version));

  write_utf8_string(buffer, default_service);
  write_utf8_string(buffer, default_environment);
  write_utf8_string(buffer, runtime_id);

  uint8_t *res = new uint8_t[buffer.size()];
  memcpy(res, buffer.data(), buffer.size());
  return std::make_unique<uint8_t *>(res);
}

int main(int argc, char *argv[]) {

  std::signal(SIGINT, handle_sigint);

  size_t len = 16;
  void* mem = mmap(nullptr, len, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  std::cout << "allocated anonymous memory at " << mem << '\n';

  auto ptr = generate_process_correlation_storage(
            "my-awesome-service", "my-environment",
            "cff82e6d-bc51-418b-bd6c-982d21377a64");

  // Write "OTL-PROC" at beginning (8 bytes)
  const char *signature = "OTL-PROC";
  memcpy(mem, signature, 8);

  // Write pointer to storage after that
  void *ptr_location = static_cast<char *>(mem) + 8;
  memcpy(ptr_location, ptr.get(), sizeof(void *));

  char* h = (char*)(mem) + 8;

  std::cout << "Waiting for Ctrl-C...\n";
  while (!sigint_received) {
    pause();
    // When pause() returns, a signal was delivered. If it was SIGINT,
    // then sigint_received == 1 and we’ll exit the loop.
    // If it was some other signal, loop again.
  }

  int res = munmap(mem, len);
  if (res != 0) {
    std::cerr << "error: unable to unmap memory\n";
    return 1;
  }
  return 0;
}
