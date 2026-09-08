#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define IO_CHUNK (64u * 1024u)
#define TRAILER_SIZE 16u
#define POSITION_BLOCK 16u

static const unsigned char MAGIC[8] = {'G','R','B','L','v','1','\r','\n'};
static const unsigned char TRAILER_MAGIC[4] = {'G','R','B','T'};

enum {
    TRANSFORM_XOR = 1,
    TRANSFORM_SUBST = 2,
    TRANSFORM_SHUFFLE = 3
};

static void die(const char *msg) {
    if (errno) fprintf(stderr, "garble: %s: %s\n", msg, strerror(errno));
    else fprintf(stderr, "garble: %s\n", msg);
    exit(1);
}

static void usage(FILE *f) {
    fprintf(f,
        "usage: garble [-d] [-t xor|subst|shuffle] (-k TEXT | -K FILE) [INPUT [OUTPUT]]\n"
        "       INPUT/OUTPUT default to '-' (stdin/stdout).\n"
        "       Encoding writes a GRBLv1 container; decoding reads its transform.\n");
}

static void put_u32le(unsigned char out[4], uint32_t v) {
    out[0] = (unsigned char)v;
    out[1] = (unsigned char)(v >> 8);
    out[2] = (unsigned char)(v >> 16);
    out[3] = (unsigned char)(v >> 24);
}

static uint32_t get_u32le(const unsigned char in[4]) {
    return ((uint32_t)in[0]) | ((uint32_t)in[1] << 8) |
           ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
}

static void put_u64le(unsigned char out[8], uint64_t v) {
    for (unsigned i = 0; i < 8; i++) out[i] = (unsigned char)(v >> (i * 8));
}

static uint64_t get_u64le(const unsigned char in[8]) {
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; i++) v |= (uint64_t)in[i] << (i * 8);
    return v;
}

static uint32_t crc_table[256];

static void crc_init(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (unsigned j = 0; j < 8; j++) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
        crc_table[i] = c;
    }
}

static uint32_t crc_update(uint32_t crc, const unsigned char *p, size_t n) {
    while (n--) crc = crc_table[(crc ^ *p++) & 0xffu] ^ (crc >> 8);
    return crc;
}

static void write_all(FILE *f, const unsigned char *p, size_t n) {
    while (n) {
        size_t w = fwrite(p, 1, n, f);
        if (w == 0) die("write failed");
        p += w;
        n -= w;
    }
}

static void read_exact(FILE *f, unsigned char *p, size_t n, const char *what) {
    while (n) {
        size_t r = fread(p, 1, n, f);
        if (r == 0) {
            errno = 0;
            if (ferror(f)) die("read failed");
            die(what);
        }
        p += r;
        n -= r;
    }
}

static unsigned char *read_key_file(const char *path, size_t *len_out) {
    FILE *f = fopen(path, "rb");
    if (!f) die("cannot open key file");
    size_t cap = 256, len = 0;
    unsigned char *buf = malloc(cap);
    if (!buf) die("out of memory");
    for (;;) {
        if (len == cap) {
            if (cap > (1u << 20)) { errno = 0; die("key file is unreasonably large"); }
            cap *= 2;
            unsigned char *nb = realloc(buf, cap);
            if (!nb) die("out of memory");
            buf = nb;
        }
        size_t r = fread(buf + len, 1, cap - len, f);
        len += r;
        if (r == 0) {
            if (ferror(f)) die("cannot read key file");
            break;
        }
    }
    if (fclose(f) != 0) die("cannot close key file");
    if (len == 0) { errno = 0; die("key must not be empty"); }
    *len_out = len;
    return buf;
}

static FILE *open_input(const char *path) {
    if (!path || strcmp(path, "-") == 0) return stdin;
    FILE *f = fopen(path, "rb");
    if (!f) die("cannot open input");
    return f;
}

static FILE *open_output(const char *path) {
    if (!path || strcmp(path, "-") == 0) return stdout;
    FILE *f = fopen(path, "wb");
    if (!f) die("cannot open output");
    return f;
}

static int paths_alias(const char *a, const char *b) {
    if (!a || !b || strcmp(a, "-") == 0 || strcmp(b, "-") == 0) return 0;
    struct stat sa, sb;
    if (stat(a, &sa) != 0) return 0;
    if (stat(b, &sb) != 0) {
        if (errno == ENOENT) { errno = 0; return 0; }
        die("cannot stat output");
    }
    return sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
}

static void xor_bytes(unsigned char *buf, size_t n, const unsigned char *key, size_t key_len, uint64_t offset) {
    for (size_t i = 0; i < n; i++) buf[i] ^= key[(size_t)((offset + i) % key_len)];
}

/*
 * Build a keyed permutation, then use it as a fixed one-byte substitution.
 * This is intentionally a pedestrian reversible transform, not encryption.
 * The KSA-shaped shuffle is merely a compact deterministic way to turn an
 * arbitrary binary key into a permutation of 0..255.
 */
static void build_subst_tables(const unsigned char *key, size_t key_len,
                               unsigned char enc[256], unsigned char dec[256]) {
    unsigned j = 0;
    for (unsigned i = 0; i < 256; i++) enc[i] = (unsigned char)i;
    for (unsigned i = 0; i < 256; i++) {
        unsigned char tmp;
        j = (j + enc[i] + key[i % key_len]) & 0xffu;
        tmp = enc[i];
        enc[i] = enc[j];
        enc[j] = tmp;
    }
    for (unsigned i = 0; i < 256; i++) dec[enc[i]] = (unsigned char)i;
}

static void subst_bytes(unsigned char *buf, size_t n, const unsigned char table[256]) {
    for (size_t i = 0; i < n; i++) buf[i] = table[buf[i]];
}

/*
 * Keyed fixed-position shuffle inside 16-byte blocks. Byte values are untouched;
 * only their positions move. The final short block gets a permutation of its own
 * actual length so the transform remains exactly reversible without padding.
 */
static void build_position_permutation(const unsigned char *key, size_t key_len,
                                       size_t n, unsigned char perm[POSITION_BLOCK]) {
    unsigned j = 0;
    for (size_t i = 0; i < n; i++) perm[i] = (unsigned char)i;
    for (size_t i = 0; i < n; i++) {
        unsigned char tmp;
        j = (j + perm[i] + key[(i + n) % key_len] + key[(i * 7u + 3u) % key_len]) % (unsigned)n;
        tmp = perm[i];
        perm[i] = perm[j];
        perm[j] = tmp;
    }
}

static void shuffle_positions(unsigned char *buf, size_t n,
                              const unsigned char *key, size_t key_len, int decode_mode) {
    unsigned char perm[POSITION_BLOCK];
    unsigned char tmp[POSITION_BLOCK];
    for (size_t base = 0; base < n; base += POSITION_BLOCK) {
        size_t m = n - base;
        if (m > POSITION_BLOCK) m = POSITION_BLOCK;
        build_position_permutation(key, key_len, m, perm);
        if (!decode_mode) {
            for (size_t out_pos = 0; out_pos < m; out_pos++)
                tmp[out_pos] = buf[base + perm[out_pos]];
        } else {
            for (size_t out_pos = 0; out_pos < m; out_pos++)
                tmp[perm[out_pos]] = buf[base + out_pos];
        }
        memcpy(buf + base, tmp, m);
    }
}

static int transform_id_from_name(const char *name) {
    if (strcmp(name, "xor") == 0) return TRANSFORM_XOR;
    if (strcmp(name, "subst") == 0) return TRANSFORM_SUBST;
    if (strcmp(name, "shuffle") == 0) return TRANSFORM_SHUFFLE;
    return 0;
}

static void apply_encode_transform(unsigned char *buf, size_t n, int transform_id,
                                   const unsigned char *key, size_t key_len, uint64_t offset,
                                   const unsigned char subst_enc[256]) {
    if (transform_id == TRANSFORM_XOR) xor_bytes(buf, n, key, key_len, offset);
    else if (transform_id == TRANSFORM_SUBST) subst_bytes(buf, n, subst_enc);
    else if (transform_id == TRANSFORM_SHUFFLE) {
        if ((offset % POSITION_BLOCK) != 0) { errno = 0; die("internal shuffle alignment error"); }
        shuffle_positions(buf, n, key, key_len, 0);
    } else { errno = 0; die("unsupported transform"); }
}

static void apply_decode_transform(unsigned char *buf, size_t n, int transform_id,
                                   const unsigned char *key, size_t key_len, uint64_t offset,
                                   const unsigned char subst_dec[256]) {
    if (transform_id == TRANSFORM_XOR) xor_bytes(buf, n, key, key_len, offset);
    else if (transform_id == TRANSFORM_SUBST) subst_bytes(buf, n, subst_dec);
    else if (transform_id == TRANSFORM_SHUFFLE) {
        if ((offset % POSITION_BLOCK) != 0) { errno = 0; die("internal shuffle alignment error"); }
        shuffle_positions(buf, n, key, key_len, 1);
    } else { errno = 0; die("unsupported transform"); }
}

static int encode(FILE *in, FILE *out, int transform_id,
                  const unsigned char *key, size_t key_len) {
    unsigned char h[16] = {0};
    unsigned char subst_enc[256], subst_dec[256];
    memcpy(h, MAGIC, sizeof(MAGIC));
    h[8] = 1;
    h[9] = (unsigned char)transform_id;
    put_u32le(h + 12, (uint32_t)sizeof(h));
    write_all(out, h, sizeof(h));

    if (transform_id == TRANSFORM_SUBST)
        build_subst_tables(key, key_len, subst_enc, subst_dec);

    unsigned char *buf = malloc(IO_CHUNK);
    if (!buf) die("out of memory");
    uint64_t total = 0;
    uint32_t crc = 0xffffffffu;

    for (;;) {
        size_t n = fread(buf, 1, IO_CHUNK, in);
        if (n) {
            crc = crc_update(crc, buf, n);
            apply_encode_transform(buf, n, transform_id, key, key_len, total, subst_enc);
            write_all(out, buf, n);
            total += n;
        }
        if (n < IO_CHUNK) {
            if (ferror(in)) die("read failed");
            break;
        }
    }
    free(buf);
    crc ^= 0xffffffffu;

    unsigned char trailer[TRAILER_SIZE];
    memcpy(trailer, TRAILER_MAGIC, 4);
    put_u64le(trailer + 4, total);
    put_u32le(trailer + 12, crc);
    write_all(out, trailer, sizeof(trailer));
    if (fflush(out) != 0) die("flush failed");
    return 0;
}

static int decode(FILE *in, FILE *out, const unsigned char *key, size_t key_len) {
    unsigned char h[16];
    unsigned char subst_enc[256], subst_dec[256];
    read_exact(in, h, sizeof(h), "truncated header");
    if (memcmp(h, MAGIC, sizeof(MAGIC)) != 0 || h[8] != 1) {
        errno = 0; die("not a supported GRBLv1 stream");
    }
    if (get_u32le(h + 12) != sizeof(h)) { errno = 0; die("unsupported header length"); }
    if (h[10] || h[11]) { errno = 0; die("unsupported container flags"); }
    int transform_id = h[9];
    if (transform_id != TRANSFORM_XOR && transform_id != TRANSFORM_SUBST &&
        transform_id != TRANSFORM_SHUFFLE) {
        errno = 0; die("unsupported transform");
    }
    if (transform_id == TRANSFORM_SUBST)
        build_subst_tables(key, key_len, subst_enc, subst_dec);

    unsigned char *buf = malloc(IO_CHUNK + TRAILER_SIZE);
    if (!buf) die("out of memory");
    unsigned char tail[TRAILER_SIZE];
    size_t tail_len = 0;
    uint64_t total = 0;
    uint32_t crc = 0xffffffffu;

    for (;;) {
        size_t n = fread(buf + tail_len, 1, IO_CHUNK, in);
        if (tail_len) memcpy(buf, tail, tail_len);
        size_t have = tail_len + n;

        if (have > TRAILER_SIZE) {
            size_t payload_n = have - TRAILER_SIZE;
            memcpy(tail, buf + payload_n, TRAILER_SIZE);
            tail_len = TRAILER_SIZE;
            apply_decode_transform(buf, payload_n, transform_id, key, key_len, total, subst_dec);
            crc = crc_update(crc, buf, payload_n);
            write_all(out, buf, payload_n);
            total += payload_n;
        } else {
            memcpy(tail, buf, have);
            tail_len = have;
        }

        if (n < IO_CHUNK) {
            if (ferror(in)) die("read failed");
            break;
        }
    }
    free(buf);

    if (tail_len != TRAILER_SIZE || memcmp(tail, TRAILER_MAGIC, 4) != 0) {
        errno = 0; die("missing or truncated trailer");
    }
    uint64_t expected_len = get_u64le(tail + 4);
    uint32_t expected_crc = get_u32le(tail + 12);
    crc ^= 0xffffffffu;

    if (total != expected_len) {
        errno = 0; die("decoded length does not match trailer");
    }
    if (crc != expected_crc) {
        errno = 0; die("integrity check failed (wrong key or damaged stream)");
    }
    if (fflush(out) != 0) die("flush failed");
    return 0;
}

int main(int argc, char **argv) {
    int decode_mode = 0;
    const char *key_text = NULL;
    const char *key_path = NULL;
    const char *transform = "xor";
    int transform_set = 0;
    int opt;

    while ((opt = getopt(argc, argv, "dt:k:K:h")) != -1) {
        switch (opt) {
            case 'd': decode_mode = 1; break;
            case 't': transform = optarg; transform_set = 1; break;
            case 'k': key_text = optarg; break;
            case 'K': key_path = optarg; break;
            case 'h': usage(stdout); return 0;
            default: usage(stderr); return 2;
        }
    }
    if (key_text && key_path) { fprintf(stderr, "garble: use only one of -k and -K\n"); return 2; }
    if (!key_text && !key_path) { fprintf(stderr, "garble: a key is required (-k or -K)\n"); return 2; }
    if (decode_mode && transform_set) { fprintf(stderr, "garble: -t is encode-only; decode reads the transform from the container\n"); return 2; }
    int transform_id = transform_id_from_name(transform);
    if (!transform_id) { fprintf(stderr, "garble: unknown transform: %s\n", transform); return 2; }
    if (argc - optind > 2) { usage(stderr); return 2; }

    size_t key_len;
    unsigned char *owned_key = NULL;
    const unsigned char *key;
    if (key_path) {
        owned_key = read_key_file(key_path, &key_len);
        key = owned_key;
    } else {
        key = (const unsigned char *)key_text;
        key_len = strlen(key_text);
        if (key_len == 0) { fprintf(stderr, "garble: key must not be empty\n"); return 2; }
    }

    const char *input_path = (argc - optind >= 1) ? argv[optind] : "-";
    const char *output_path = (argc - optind >= 2) ? argv[optind + 1] : "-";
    if (paths_alias(input_path, output_path)) {
        fprintf(stderr, "garble: input and output refer to the same file\n");
        return 2;
    }
    FILE *in = open_input(input_path);
    FILE *out = open_output(output_path);

    crc_init();
    int rc = decode_mode ? decode(in, out, key, key_len)
                         : encode(in, out, transform_id, key, key_len);

    if (in != stdin && fclose(in) != 0) die("cannot close input");
    if (out != stdout && fclose(out) != 0) die("cannot close output");
    if (owned_key) {
        volatile unsigned char *p = owned_key;
        for (size_t i = 0; i < key_len; i++) p[i] = 0;
        free(owned_key);
    }
    return rc;
}
