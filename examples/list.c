/*
 * list.c — minimal sutram-capi consumer: detect, mount, stream entries
 * as JSONL, and read one file.
 *
 * Build (macOS/Linux, after `cargo build --release`):
 *   cc -I../include list.c -L../target/release -lsutram_capi -o list
 *   ./list /path/to/image.img [/entry/path]
 */
#include <stdio.h>
#include <string.h>

#include "sutram.h"

static void print_entry(void *user, const char *json) {
    (void)user;
    puts(json);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <image> [entry_path]\n", argv[0]);
        return 2;
    }

    /* What does this image look like? */
    char *det = sutram_detect(argv[1]);
    if (det) {
        printf("detect: %s\n", det);
        sutram_free_string(det);
    }

    SutramFs *fs = sutram_open_image(argv[1]);
    if (!fs) {
        fprintf(stderr, "mount failed: %s\n",
                sutram_last_error() ? sutram_last_error() : "?");
        return 1;
    }
    printf("mounted as: %s\n", sutram_fs_type(fs));

    char *info = sutram_info_json(fs);
    if (info) {
        printf("info: %s\n", info);
        sutram_free_string(info);
    }

    int64_t n = sutram_list_entries(fs, print_entry, NULL);
    printf("(%lld entries)\n", (long long)n);

    /* Optionally read a file back. */
    if (argc > 2) {
        uint64_t len = 0;
        uint8_t *data = sutram_read_file(fs, argv[2], 64u << 20, &len);
        if (!data) {
            fprintf(stderr, "read failed: %s\n",
                    sutram_last_error() ? sutram_last_error() : "?");
        } else {
            fwrite(data, 1, (size_t)len, stdout);
            sutram_free_bytes(data, len);
        }
    }

    sutram_close(fs);
    return 0;
}
