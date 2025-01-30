#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "smaz.h"

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
    if (size == 0) return 0;

    char compressed[4096] = {0};
    char decompressed[4096] = {0};

    int compressed_size = smaz_compress((char *)data, size, compressed, sizeof(compressed));

    if (compressed_size <= 0 || compressed_size > (int)sizeof(compressed)) {
        return 0;
    }

    if (compressed_size > 0) {
        int decompressed_size = smaz_decompress(compressed, compressed_size, decompressed, sizeof(decompressed));

        if (decompressed_size > 0 && decompressed_size <= (int)size) {
            if (memcmp(data, decompressed, decompressed_size) != 0) {
                __builtin_trap();
            }
        }
    }

    return 0;
}