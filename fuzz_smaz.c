#include "smaz.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
  if (size == 0)
    return 0;

  char compressed[4096];
  char decompressed[4096];

  int compressed_size =
      smaz_compress((char *)data, size, compressed, sizeof(compressed));

  if (compressed_size > 0) {
    int decompressed_size = smaz_decompress(compressed, compressed_size,
                                            decompressed, sizeof(decompressed));

    if (decompressed_size > 0 && decompressed_size <= (int)size) {
      if (memcmp(data, decompressed, decompressed_size) != 0) {
        __builtin_trap();
      }
    }
  }

  return 0;
}
