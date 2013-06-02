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

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "scfg.h"

#define CFG_ERROR_BUFSZ 1024

struct cfg_ctx {
    struct cfg *cfg;

    const char *filename;
    int lineno;
    int colno;

    const char *buf;
    const char *last_line_start;

    char *prefix;
    size_t prefix_sz;
    size_t prefix_len;

    bool did_abort;
};

struct cfg_entry {
    char *key;

    enum cfg_type type;
    union cfg_value value;
};

struct cfg {
    struct cfg_entry **entries;
    int entries_sz;
    int nb_entries;

    cfg_entry_hook entry_hook;
    cfg_parse_error_hook parse_error_hook;
};

struct cfg_iterator {
    const struct cfg *cfg;
    const char *prefix;

    int entry_index;
    const struct cfg_entry *entry;
};

static void *cfg_malloc(size_t);
static void cfg_free(void *);
static void *cfg_calloc(size_t, size_t);
static void *cfg_realloc(void *, size_t);

static struct cfg_entry *cfg_entry_new();
static void cfg_entry_delete(struct cfg_entry *);
static int cfg_entry_cmp(const void *, const void *);

static char *cfg_read_file(const char *);
static int cfg_add_entry(struct cfg *, struct cfg_entry *);
static const struct cfg_entry *cfg_get_entry(struct cfg *, const char *);

static int cfg_ctx_initialize(struct cfg_ctx *);
static void cfg_ctx_free(struct cfg_ctx *);

static void cfg_ctx_abort(struct cfg_ctx *, const char *, ...);
static void cfg_ctx_parse_error(struct cfg_ctx *, const char *, ...);

static void cfg_ctx_skip_whitespaces(struct cfg_ctx *);
static void cfg_ctx_skip_empty_lines(struct cfg_ctx *);
static void cfg_ctx_skip_comment(struct cfg_ctx *);
static void cfg_ctx_skip_ignored_content(struct cfg_ctx *);

static int cfg_ctx_read_elements(struct cfg_ctx *);
static int cfg_ctx_read_element(struct cfg_ctx *);
static struct cfg_entry *cfg_ctx_read_entry(struct cfg_ctx *, char *);
static char *cfg_ctx_read_string(struct cfg_ctx *);
static char *cfg_ctx_read_identifier(struct cfg_ctx *);

static int cfg_ctx_prefix_push(struct cfg_ctx *, const char *);
static void cfg_ctx_prefix_pop(struct cfg_ctx *);
static char *cfg_ctx_make_key(struct cfg_ctx *, char *);

static bool cfg_key_matches_prefix(const char *key, const char *prefix);

static bool char_is_oneof(int, const char *);
static const char *str_search_oneof(const char *, const char *);

static struct cfg_memory_allocator cfg_allocator = {
    .malloc = malloc,
    .free = free,
    .calloc = calloc,
    .realloc = realloc
};

static __thread char cfg_error_buf[CFG_ERROR_BUFSZ];

const char *
cfg_get_error() {
    return cfg_error_buf;
}

void
cfg_set_error(const char *fmt, ...) {
    char buf[CFG_ERROR_BUFSZ];
    va_list ap;
    int ret;

    va_start(ap, fmt);
    ret = vsnprintf(buf, CFG_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    if ((size_t)ret >= CFG_ERROR_BUFSZ) {
        memcpy(cfg_error_buf, buf, CFG_ERROR_BUFSZ);
        cfg_error_buf[CFG_ERROR_BUFSZ - 1] = '\0';
        return;
    }

    strncpy(cfg_error_buf, buf, (size_t)ret + 1);
    cfg_error_buf[ret] = '\0';
}

void
cfg_set_memory_allocator(struct cfg_memory_allocator *allocator) {
    cfg_allocator = *allocator;
}

struct cfg *
cfg_new() {
    struct cfg *cfg;

    cfg = cfg_malloc(sizeof(struct cfg));
    if (!cfg) {
        cfg_set_error("cannot allocate cfg: %m");
        return NULL;
    }

    memset(cfg, 0, sizeof(struct cfg));

    return cfg;
}

void
cfg_delete(struct cfg *cfg) {
    if (!cfg)
        return;

    for (int i = 0; i < cfg->nb_entries; i++)
        cfg_entry_delete(cfg->entries[i]);
    cfg_free(cfg->entries);
    cfg_free(cfg);
}

void
cfg_set_entry_hook(struct cfg *cfg, cfg_entry_hook hook) {
    cfg->entry_hook = hook;
}

void
cfg_set_parse_error_hook(struct cfg *cfg, cfg_parse_error_hook hook) {
    cfg->parse_error_hook = hook;
}

int
cfg_load(struct cfg *cfg, const char *path) {
    struct cfg_ctx ctx;
    char *content;

    content = cfg_read_file(path);
    if (!content) {
        cfg_delete(cfg);
        return -1;
    }

    if (cfg_ctx_initialize(&ctx) == -1) {
        cfg_free(content);
        cfg_delete(cfg);
        return -1;
    }

    ctx.cfg = cfg;
    ctx.filename = path;
    ctx.buf = content;
    ctx.last_line_start = ctx.buf;

    if (cfg_ctx_read_elements(&ctx) == -1) {
        if (!ctx.did_abort)
            cfg_set_error("syntax error");

        cfg_free(content);
        cfg_ctx_free(&ctx);
        cfg_delete(cfg);
        return -1;
    }

    cfg_ctx_free(&ctx);
    cfg_free(content);

    qsort(cfg->entries, (size_t)cfg->nb_entries, sizeof(struct cfg_entry *),
          cfg_entry_cmp);

    return 0;
}

int cfg_get_value(struct cfg *cfg, const char *key, enum cfg_type *type,
                  union cfg_value *value) {
    const struct cfg_entry *entry;

    entry = cfg_get_entry(cfg, key);
    if (!entry)
        return 0;

    *type = entry->type;
    *value = entry->value;

    return 1;
}

int
cfg_get_string(struct cfg *cfg, const char *key, const char **value) {
    const struct cfg_entry *entry;

    entry = cfg_get_entry(cfg, key);
    if (!entry)
        return 0;

    if (entry->type != CFG_TYPE_STRING) {
        cfg_set_error("value of key '%s' is not of type string", key);
        return -1;
    }

    *value = entry->value.s;
    return 1;
}

int
cfg_get_integer(struct cfg *cfg, const char *key, int *value) {
    const struct cfg_entry *entry;

    entry = cfg_get_entry(cfg, key);
    if (!entry)
        return 0;

    if (entry->type != CFG_TYPE_INT32) {
        cfg_set_error("value of key '%s' is not of type integer", key);
        return -1;
    }

    *value = entry->value.i32;
    return 1;
}

int
cfg_get_bool(struct cfg *cfg, const char *key, bool *value) {
    const struct cfg_entry *entry;

    entry = cfg_get_entry(cfg, key);
    if (!entry)
        return 0;

    if (entry->type != CFG_TYPE_BOOL) {
        cfg_set_error("value of key '%s' is not of type bool", key);
        return -1;
    }

    *value = entry->value.b;
    return 1;
}

struct cfg_iterator *
cfg_iterate(const struct cfg *cfg, const char *prefix) {
    struct cfg_iterator *it;

    it = cfg_malloc(sizeof(struct cfg_iterator));
    if (!it) {
        cfg_set_error("cannot allocate iterator: %m");
        return NULL;
    }

    memset(it, 0, sizeof(struct cfg_iterator));

    it->cfg = cfg;
    it->prefix = prefix;

    return it;
}

bool
cfg_iterator_get_value(struct cfg_iterator *it, const char **key,
                       enum cfg_type *type, union cfg_value *value) {
    const struct cfg *cfg;

    cfg = it->cfg;

    if (it->entry) {
        struct cfg_entry *entry;

        /* Get the next entry matching the prefix */

        it->entry_index++;
        if (it->entry_index >= cfg->nb_entries)
            return false;

        entry = cfg->entries[it->entry_index];
        if (!cfg_key_matches_prefix(entry->key, it->prefix)) {
            it->entry_index = 0;
            it->entry = NULL;
            return false;
        }

        it->entry = entry;
    } else {
        bool found;

        /* Get the first entry matching the prefix */

        found = false;
        for (int i = 0; i < cfg->nb_entries; i++) {
            struct cfg_entry *entry;

            entry = cfg->entries[i];

            if (cfg_key_matches_prefix(entry->key, it->prefix)) {
                it->entry_index = i;
                it->entry = entry;
                found = true;
                break;
            }
        }

        if (!found)
            return false;
    }

    *key = it->entry->key;
    *type = it->entry->type;
    *value = it->entry->value;

    return true;
}

void
cfg_iterator_delete(struct cfg_iterator *it) {
    cfg_free(it);
}

void
cfg_parse_error_stderr(const char *error,
                       const char *filename, const char *line,
                       int lineno, int colno) {
    fprintf(stderr, "%s:%d:%d: %s\n", filename, lineno, colno, error);

    fprintf(stderr, "\n%s\n", line);
    for (int i = 0; i < colno - 1; i++)
        fputc(' ', stderr);
    fprintf(stderr, "^\n\n");
}

static void *
cfg_malloc(size_t sz) {
    return cfg_allocator.malloc(sz);
}

static void
cfg_free(void *ptr) {
    cfg_allocator.free(ptr);
}

static void *
cfg_calloc(size_t nb, size_t sz) {
    return cfg_allocator.calloc(nb, sz);
}

static void *
cfg_realloc(void *ptr, size_t sz) {
    return cfg_allocator.realloc(ptr, sz);
}

static struct cfg_entry *
cfg_entry_new() {
    struct cfg_entry *entry;

    entry = cfg_malloc(sizeof(struct cfg_entry));
    if (!entry) {
        cfg_set_error("cannot allocate cfg entry: %m");
        return NULL;
    }

    memset(entry, 0, sizeof(struct cfg_entry));
    return entry;
}

static void
cfg_entry_delete(struct cfg_entry *entry) {
    if (!entry)
        return;

    cfg_free(entry->key);
    if (entry->type == CFG_TYPE_STRING)
        cfg_free(entry->value.s);
    cfg_free(entry);
}

static int
cfg_entry_cmp(const void *p1, const void *p2) {
    const struct cfg_entry *e1, *e2;

    e1 = *(struct cfg_entry **)p1;
    e2 = *(struct cfg_entry **)p2;

    return strcmp(e1->key, e2->key);
}

static char *
cfg_read_file(const char *path) {
    char *content, *ptr;
    struct stat st;
    size_t sz;
    int fd;

    fd = open(path, O_RDONLY);
    if (fd == -1) {
        cfg_set_error("cannot open file %s: %m", path);
        return NULL;
    }

    if (stat(path, &st) == -1) {
        cfg_set_error("cannot stat file %s: %m", path);
        close(fd);
        return NULL;
    }

    sz = (size_t)st.st_size;

    content = cfg_malloc(sz + 1);
    if (!content) {
        cfg_set_error("cannot allocate %zu bytes: %m", sz);
        close(fd);
        return NULL;
    }

    ptr = content;
    for (;;) {
        ssize_t ret;

        ret = read(fd, ptr, BUFSIZ);
        if (ret < 0) {
            if (errno == EINTR)
                continue;

            cfg_set_error("error while reading %s: %m", path);
            close(fd);
            cfg_free(content);
            return NULL;
        }

        if (ret == 0)
            break;

        ptr += ret;
    }

    *ptr = '\0';

    close(fd);
    return content;
}

static int
cfg_add_entry(struct cfg *cfg, struct cfg_entry *entry) {
    size_t entry_len = sizeof(struct cfg_entry *);

    if (!cfg->entries) {
        cfg->entries_sz = 8;
        cfg->entries = cfg_calloc((size_t)cfg->entries_sz, entry_len);
        if (!cfg->entries) {
            cfg_set_error("cannot allocate entry array: %m");
            return -1;
        }
    } else if (cfg->nb_entries + 1 > cfg->entries_sz) {
        struct cfg_entry **nentries;
        int nsz;

        nsz = cfg->entries_sz * 2;
        nentries = cfg_realloc(cfg->entries, (size_t)nsz * entry_len);
        if (!nentries) {
            cfg_set_error("cannot reallocate entry array: %m");
            return -1;
        }

        memset(nentries + cfg->entries_sz, 0,
               (size_t)(nsz - cfg->entries_sz) * entry_len);

        cfg->entries_sz = nsz;
        cfg->entries = nentries;
    }

    cfg->entries[cfg->nb_entries++] = entry;
    return 0;
}

static const struct cfg_entry *
cfg_get_entry(struct cfg *cfg, const char *key) {
    struct cfg_entry entry, *entry_ptr;
    void *res;

    entry.key = (char *)key;
    entry_ptr = &entry;

    res = bsearch(&entry_ptr, cfg->entries, (size_t)cfg->nb_entries,
                  sizeof(struct cfg_entry *), cfg_entry_cmp);
    if (!res)
        return NULL;

    return *(struct cfg_entry **)res;
}

static int
cfg_ctx_initialize(struct cfg_ctx *ctx) {
    memset(ctx, 0, sizeof(struct cfg_ctx));

    ctx->lineno = 1;
    ctx->colno = 1;

    ctx->prefix_sz = 16;
    ctx->prefix = cfg_malloc(ctx->prefix_sz);
    if (!ctx->prefix) {
        cfg_set_error("cannot allocate prefix: %m");
        return -1;
    }
    ctx->prefix[0] = '\0';

    return 0;
}

static void
cfg_ctx_free(struct cfg_ctx *ctx) {
    if (!ctx)
        return;

    cfg_free(ctx->prefix);
}

static void
cfg_ctx_abort(struct cfg_ctx *ctx, const char *fmt, ...) {
    char buf[CFG_ERROR_BUFSZ];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, CFG_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    cfg_set_error("%s", buf);

    ctx->did_abort = true;
}

static void
cfg_ctx_parse_error(struct cfg_ctx *ctx, const char *fmt, ...) {
    char err_buf[CFG_ERROR_BUFSZ];
    char line_buf[BUFSIZ];
    va_list ap;
    const char *line_start, *line_end;
    size_t sz;

    va_start(ap, fmt);
    vsnprintf(err_buf, CFG_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    line_start = ctx->last_line_start;
    line_end = str_search_oneof(ctx->buf, "\r\n\0");

    sz = (size_t)(line_end - line_start);
    if (sz >= BUFSIZ)
        sz = BUFSIZ - 1;
    memcpy(line_buf, line_start, sz);
    line_buf[sz] = '\0';

    if (ctx->cfg->parse_error_hook) {
        ctx->cfg->parse_error_hook(err_buf, ctx->filename, line_buf,
                                   ctx->lineno, ctx->colno);
    }
}

static void
cfg_ctx_skip_whitespaces(struct cfg_ctx *ctx) {
    while (char_is_oneof(*ctx->buf, " \t")) {
        ctx->buf++;
        ctx->colno++;
    }
}

static void
cfg_ctx_skip_empty_lines(struct cfg_ctx *ctx) {
    while (*ctx->buf) {
        if (*ctx->buf == '\n') {
            ctx->lineno++;
            ctx->colno = 1;
            ctx->last_line_start = ctx->buf + 1;
        } else if (char_is_oneof(*ctx->buf, " \t\r")) {
            ctx->colno++;
        } else {
            break;
        }

        ctx->buf++;
    }
}

static void
cfg_ctx_skip_comment(struct cfg_ctx *ctx) {
    assert(*ctx->buf == '#');

    while (*ctx->buf && *ctx->buf != '\n') {
        ctx->buf++;
        ctx->colno++;
    }

    if (ctx->buf) {
        /* Skip '\n' */
        ctx->buf++;
        ctx->lineno++;
        ctx->colno = 1;
        ctx->last_line_start = ctx->buf;
    }
}

static void
cfg_ctx_skip_ignored_content(struct cfg_ctx *ctx) {
    for (;;) {
        cfg_ctx_skip_empty_lines(ctx);

        if (*ctx->buf == '#') {
            cfg_ctx_skip_comment(ctx);
        } else {
            break;
        }
    }
}

static int
cfg_ctx_read_elements(struct cfg_ctx *ctx) {
    while (*ctx->buf) {
        cfg_ctx_skip_ignored_content(ctx);
        if (*ctx->buf == '\0')
            break;

        if (*ctx->buf == '}')
            break;

        if (cfg_ctx_read_element(ctx) == -1)
            return -1;
    }

    return 0;
}

static int
cfg_ctx_read_element(struct cfg_ctx *ctx) {
    char *identifier;

    identifier = cfg_ctx_read_identifier(ctx);
    if (!identifier)
        return -1;

    cfg_ctx_skip_empty_lines(ctx);
    if (*ctx->buf == '\0') {
        cfg_ctx_parse_error(ctx, "unexpected end of file after identifier");
        goto error;
    }

    if (*ctx->buf == '{') {
        if (cfg_ctx_prefix_push(ctx, identifier) == -1)
            goto error;

        cfg_free(identifier);
        identifier = NULL;

        /* Skip '{' */
        ctx->buf++;
        ctx->colno++;

        if (cfg_ctx_read_elements(ctx) == -1)
            goto error;

        cfg_ctx_skip_ignored_content(ctx);
        if (*ctx->buf == '\0') {
            cfg_ctx_parse_error(ctx, "unexpected end of file");
            goto error;
        }

        if (*ctx->buf != '}') {
            cfg_ctx_parse_error(ctx, "missing '}'");
            goto error;
        }

        /* Skip '}' */
        ctx->buf++;
        ctx->colno++;

        cfg_ctx_prefix_pop(ctx);
    } else if (*ctx->buf == ':') {
        struct cfg_entry *entry;

        entry = cfg_ctx_read_entry(ctx, identifier);
        if (!entry)
            goto error;

        if (cfg_add_entry(ctx->cfg, entry) == -1) {
            cfg_ctx_abort(ctx, "cannot add cfg entry: %s", cfg_get_error());
            goto error;
        }

        if (ctx->cfg->entry_hook)
            ctx->cfg->entry_hook(entry->key, entry->type, entry->value);

        cfg_free(identifier);
        identifier = NULL;
    } else {
        cfg_ctx_parse_error(ctx, "invalid character after identifier");
        goto error;
    }

    return 0;

error:
    if (identifier)
        cfg_free(identifier);
    return -1;
}

static struct cfg_entry *
cfg_ctx_read_entry(struct cfg_ctx *ctx, char *identifier) {
    struct cfg_entry *entry;

    assert(*ctx->buf == ':');

    entry = cfg_entry_new();
    entry->key = cfg_ctx_make_key(ctx, identifier);

    cfg_ctx_skip_whitespaces(ctx);
    if (*ctx->buf == '\0') {
        cfg_ctx_parse_error(ctx, "unexpected end of file while reading entry");
        goto error;
    }

    if (*ctx->buf != ':') {
        cfg_ctx_parse_error(ctx, "missing colon after entry key");
        goto error;
    }

    /* Skip ':' */
    ctx->buf++;
    ctx->colno++;

    cfg_ctx_skip_whitespaces(ctx);
    if (*ctx->buf == '\0') {
        cfg_ctx_parse_error(ctx, "unexpected end of file while reading entry");
        goto error;
    }

    if (*ctx->buf == '"') {
        entry->type = CFG_TYPE_STRING;
        entry->value.s = cfg_ctx_read_string(ctx);
        if (!entry->value.s)
            goto error;
    } else if (*ctx->buf == '-' || (*ctx->buf >= '0' && *ctx->buf <= '9')) {
        char *end;
        long l;

        errno = 0;
        l = strtol(ctx->buf, &end, 10);
        if (errno) {
            cfg_ctx_parse_error(ctx, "invalid syntax for integer: %m");
            goto error;
        }

        if (l < INT_MIN || l > INT_MAX) {
            cfg_ctx_parse_error(ctx, "integer is too large");
            goto error;
        }

        entry->type = CFG_TYPE_INT32;
        entry->value.i32 = (int)l;

        ctx->colno += end - ctx->buf + 1;
        ctx->buf = end;
    } else if (!strncmp(ctx->buf, "true", 4)) {
        entry->type = CFG_TYPE_BOOL;
        entry->value.b = true;

        ctx->buf += 4;
        ctx->colno += 4;
    } else if (!strncmp(ctx->buf, "false", 5)) {
        entry->type = CFG_TYPE_BOOL;
        entry->value.b = false;

        ctx->buf += 5;
        ctx->colno += 5;
    } else {
        cfg_ctx_parse_error(ctx, "invalid value");
        goto error;
    }

    return entry;

error:
    cfg_entry_delete(entry);
    return NULL;
}

static char *
cfg_ctx_read_string(struct cfg_ctx *ctx) {
    const char *ptr;
    char *buf;
    size_t sz, len;

    sz = 16;
    len = 0;
    buf = cfg_malloc(sz);
    if (!buf) {
        cfg_ctx_abort(ctx, "cannot allocate string: %m");
        return NULL;
    }

    buf[0] = '\0';

#define CFG_APPEND_CHAR(c_)                                                \
    do {                                                                   \
        if (len + 1 >= sz) {                                               \
            char *nbuf;                                                    \
            size_t nsz;                                                    \
                                                                           \
            nsz = sz * 2;                                                  \
            nbuf = cfg_realloc(buf, nsz);                                  \
            if (!nbuf) {                                                   \
                cfg_ctx_abort(ctx, "cannot reallocate string: %m");        \
                goto error;                                                \
            }                                                              \
                                                                           \
            buf = nbuf;                                                    \
            sz = nsz;                                                      \
        }                                                                  \
                                                                           \
        buf[len++] = (c_);                                                 \
        buf[len] = '\0';                                                   \
    } while (0)

    /* Skip '"' */
    ctx->buf++;
    ctx->colno++;

    ptr = ctx->buf;
    for (;;) {
        if (*ptr == '\0') {
            ctx->colno += ptr - ctx->buf;
            ctx->buf = ptr;

            cfg_ctx_parse_error(ctx, "unexpected end of file while reading"
                                " string");
            goto error;
        } else if (*ptr == '\n') {
            ctx->colno += ptr - ctx->buf;
            ctx->buf = ptr;

            cfg_ctx_parse_error(ctx, "unexpected end of line while reading"
                                " string");
            goto error;
        } else if (*ptr == '"') {
            ctx->colno += ptr - ctx->buf;
            ctx->buf = ptr + 1;

            return buf;
        } else if (*ptr == '\\') {
            ptr++;

            switch (*ptr) {
                case '"':
                case '\\':
                    CFG_APPEND_CHAR(*ptr);
                    break;

                case 'a': CFG_APPEND_CHAR('\a'); break;
                case 'b': CFG_APPEND_CHAR('\b'); break;
                case 't': CFG_APPEND_CHAR('\t'); break;
                case 'n': CFG_APPEND_CHAR('\n'); break;
                case 'v': CFG_APPEND_CHAR('\v'); break;
                case 'f': CFG_APPEND_CHAR('\f'); break;
                case 'r': CFG_APPEND_CHAR('\r'); break;

                default:
                    ctx->colno += ptr - ctx->buf;
                    ctx->buf = ptr;
                    cfg_ctx_parse_error(ctx, "invalid escape sequence");
                    goto error;
            }
        } else {
            CFG_APPEND_CHAR(*ptr);
        }

        ptr++;
    }

#undef CFG_APPEND_CHAR

error:
    cfg_free(buf);
    return NULL;
}

static char *
cfg_ctx_read_identifier(struct cfg_ctx *ctx) {
    const char *ptr;

    for (ptr = ctx->buf; *ptr; ptr++) {
        if (*ptr == ' ' || *ptr == ':'
            || *ptr == '\r' || *ptr == '\n') {
            char *identifier;
            size_t identifier_len;

            identifier_len = (size_t)(ptr - ctx->buf);
            identifier = cfg_malloc(identifier_len + 1);
            if (!identifier) {
                cfg_ctx_abort(ctx, "cannot allocate identifier: %m");
                return NULL;
            }
            memcpy(identifier, ctx->buf, identifier_len);
            identifier[identifier_len] = '\0';

            ctx->colno += ptr - ctx->buf;
            ctx->buf = ptr;
            return identifier;
        } else if (*ptr != '_'
                   && !(*ptr >= 'a' && *ptr <= 'z')
                   && !(*ptr >= 'A' && *ptr <= 'Z')
                   && !(*ptr >= '0' && *ptr <= '9')) {
            ctx->colno += ptr - ctx->buf;
            ctx->buf = ptr;
            cfg_ctx_parse_error(ctx, "invalid character '%c' in identifier",
                                *ptr);
            return NULL;
        }
    }

    ctx->colno += ptr - ctx->buf;
    ctx->buf = ptr;

    cfg_ctx_parse_error(ctx, "unexpected end of file while reading"
                        " identifier");
    return NULL;
}

static int
cfg_ctx_prefix_push(struct cfg_ctx *ctx, const char *name) {
    size_t len;

    len = strlen(name);

    if (ctx->prefix_len + len + 2 > ctx->prefix_sz) {
        char *nprefix;
        size_t nsz;

        nsz = ctx->prefix_sz * 2;
        if (nsz <= ctx->prefix_sz + len + 1)
            nsz = nsz + ctx->prefix_sz + len + 2;

        nprefix = cfg_realloc(ctx->prefix, nsz);
        if (!nprefix) {
            cfg_ctx_abort(ctx, "cannot reallocate prefix: %m");
            return -1;
        }

        ctx->prefix = nprefix;
        ctx->prefix_sz = nsz;
    }

    if (ctx->prefix_len > 0) {
        ctx->prefix[ctx->prefix_len] = '.';
        ctx->prefix_len++;
    }

    strcpy(ctx->prefix + ctx->prefix_len, name);
    ctx->prefix_len += len;

    return 0;
}

static void
cfg_ctx_prefix_pop(struct cfg_ctx *ctx) {
    char *dot;

    dot = strrchr(ctx->prefix, '.');
    if (dot) {
        *dot = '\0';
        ctx->prefix_len = (size_t)(dot - ctx->prefix);
    } else {
        ctx->prefix[0] = '\0';
        ctx->prefix_len = 0;
    }
}

static char *
cfg_ctx_make_key(struct cfg_ctx *ctx, char *name) {
    char *key;
    size_t sz;

    sz = ctx->prefix_len + 1 + strlen(name) + 1;
    key = cfg_malloc(sz);
    if (!key) {
        cfg_ctx_abort(ctx, "cannot allocate key: %m");
        return NULL;
    }

    if (ctx->prefix_len == 0) {
        strcpy(key, name);
    } else {
        sprintf(key, "%s.%s", ctx->prefix, name);
    }

    return key;
}

static bool
cfg_key_matches_prefix(const char *key, const char *prefix) {
    size_t key_len, prefix_len;

    key_len = strlen(key);
    prefix_len = strlen(prefix);

    if (prefix_len > key_len)
        return false;

    return memcmp(key, prefix, prefix_len) == 0;
}

static bool
char_is_oneof(int c, const char *chars) {
    for (const char *ptr = chars;; ptr++) {
        if (*ptr == c)
            return true;

        if (*ptr == '\0')
            break;
    }

    return false;
}

static const char *
str_search_oneof(const char *str, const char *chars) {
    for (const char *ptr = str;; ptr++) {
        if (char_is_oneof(*ptr, chars))
            return ptr;

        if (*ptr == '\0')
            break;
    }

    return NULL;
}
