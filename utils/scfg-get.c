/*
 * Copyright (c) 2013 Nicolas Martyanoff
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

#include <unistd.h>

#include "scfg.h"

static void die(const char *, ...)
    __attribute__((format(printf, 1, 2)));
static void usage(const char *, int);

int
main(int argc, char **argv) {
    const char *path, *key;
    struct cfg *cfg;
    enum cfg_type type;
    union cfg_value value;
    int opt;

    opterr = 0;
    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
            case 'h':
                usage(argv[0], 0);
                break;

            case '?':
                usage(argv[0], 1);
        }
    }

    argc -= optind;
    if (argc < 2)
        usage(argv[0], 1);

    argv += optind;
    path = argv[0];
    key = argv[1];

    cfg = cfg_new();
    if (!cfg)
        die("cannot create cfg: %s", cfg_get_error());
    cfg_set_parse_error_hook(cfg, cfg_parse_error_stderr);

    if (cfg_load(cfg, path) == -1)
        die("cannot load configuration from %s: %s", path, cfg_get_error());

    if (cfg_get_value(cfg, key, &type, &value) == 0) {
        fprintf(stderr, "no entry found with key '%s'\n", key);
        cfg_delete(cfg);
        return 1;
    }

    printf("%s: ", key);

    switch (type) {
        case CFG_TYPE_STRING:
            printf("%s", value.s);
            break;

        case CFG_TYPE_INT32:
            printf("%i", value.i32);
            break;

        case CFG_TYPE_BOOL:
            printf("%s", value.b ? "true" : "false");
            break;

        case CFG_TYPE_UNKNOWN:
            printf("<unknown>");
            break;
    }

    putchar('\n');

    cfg_delete(cfg);
    return 0;
}

static void
usage(const char *argv0, int exit_code) {
    printf("Usage: %s [-h] <file> <key>\n"
            "\n"
            "Options:\n"
            "  -h         display help\n",
            argv0);
    exit(exit_code);
}

void
die(const char *fmt, ...) {
    va_list ap;

    fprintf(stderr, "fatal error: ");

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    putc('\n', stderr);
    exit(1);
}
