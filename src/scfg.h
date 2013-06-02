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

#ifndef LIBSCFG_SCFG_H
#define LIBSCFG_SCFG_H

#include <stdbool.h>

struct cfg_memory_allocator {
   void *(*malloc)(size_t sz);
   void (*free)(void *ptr);
   void *(*calloc)(size_t nb, size_t sz);
   void *(*realloc)(void *ptr, size_t sz);
};

enum cfg_type {
    CFG_TYPE_UNKNOWN,

    CFG_TYPE_STRING,
    CFG_TYPE_INT32,
    CFG_TYPE_BOOL
};

union cfg_value {
    char *s;
    int32_t i32;
    bool b;
};

typedef void (*cfg_entry_hook)(const char *key, enum cfg_type,
                               union cfg_value);
typedef void (*cfg_parse_error_hook)(const char *error,
                                     const char *filename,
                                     const char *line,
                                     int lineno, int colno);

const char *cfg_get_error();
void cfg_set_error(const char *fmt, ...)
    __attribute__((format(printf, 1, 2)));

void cfg_set_memory_allocator(struct cfg_memory_allocator *allocator);

struct cfg *cfg_new();
void cfg_delete(struct cfg *cfg);
void cfg_set_entry_hook(struct cfg *cfg, cfg_entry_hook hook);
void cfg_set_parse_error_hook(struct cfg *cfg, cfg_parse_error_hook hook);

int cfg_load(struct cfg *cfg, const char *path);

int cfg_get_value(struct cfg *cfg, const char *key, enum cfg_type *type,
                  union cfg_value *value);
int cfg_get_string(struct cfg *cfg, const char *key, const char **value);
int cfg_get_integer(struct cfg *cfg, const char *key, int *value);
int cfg_get_bool(struct cfg *cfg, const char *key, bool *value);

struct cfg_iterator *cfg_iterate(const struct cfg *cfg, const char *prefix);
bool cfg_iterator_get_value(struct cfg_iterator *it, const char **key,
                            enum cfg_type *type, union cfg_value *value);
void cfg_iterator_delete(struct cfg_iterator *it);

void cfg_parse_error_stderr(const char *error,
                            const char *filename, const char *line,
                            int lineno, int colno);

#endif
