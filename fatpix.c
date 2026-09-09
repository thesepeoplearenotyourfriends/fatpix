#define _FILE_OFFSET_BITS 64
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

/* A small Linux fbdev FatPix.  The dump-grid path deliberately uses the same
 * source, sampling, and literal classification code as the interactive view. */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fb.h>
#include <linux/fs.h>
#include <linux/kd.h>
#include <linux/vt.h>
#include <math.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include <zlib.h>

#define SAMPLE_MAX 1024
#define BATCH_MAX (8u * 1024u * 1024u)
#define CELL_DEFAULT 14
#define MOUSE_SPEED_DEFAULT 3.0
#define FONT_SCALE_DEFAULT 2

typedef struct {
    int fd;
    uint64_t size, read_calls;
    const char *path;
} Source;
typedef struct {
    uint8_t color;
    const char *kind;
} Cell;
typedef struct {
    int fd, tty, kd_mode, raw, mapped;
    int keyboard_mode, keyboard_mode_saved, vt_mode_saved, vt_process, active;
    struct vt_mode saved_vt_mode;
    struct termios saved_termios;
    struct fb_var_screeninfo var;
    struct fb_fix_screeninfo fix;
    uint8_t *map, *back;
    size_t map_len;
    int mouse, mouse_x, mouse_y, font_scale;
    int measure_text, measured_text_width;
    double mouse_speed, mouse_remainder_x, mouse_remainder_y;
} Display;
typedef struct {
    uint64_t view, scale, cursor, selection_start, selection_end, selection_anchor;
    uint64_t inspect_focus;
    int cell, inspect, inspect_page, lens, selecting, selection_dragged, help;
    int inspector_x, inspector_y, inspector_w, inspector_h, inspector_positioned;
    char message[160];
} View;
typedef struct {
    Cell *cells, *literal_cells;
    size_t count;
    uint64_t view, scale;
    int cols, rows, valid;
    uint8_t inspect_data[1024];
    uint8_t baseline_data[1024];
    size_t inspect_n;
    uint64_t inspect_start;
    int inspect_valid;
    uint8_t *samples, *contexts, *previous;
    uint16_t *sample_n, *context_n;
    uint64_t baseline_start, baseline_scale;
    size_t baseline_n;
    int baseline_valid, colored_lens;
    uint64_t colored_cursor;
    uint64_t recolor_count;
} RenderCache;

static const char *lens_names[] = {"",         "literal",       "xor-prev",  "delta-prev",
                                   "compress", "neighbor-diff", "cursor-sim"};
static const char *page_names[] = {"HEX", "TEXT", "NUM", "MAGIC", "STATS", "RANGE", "DIFF HEX"};

static volatile sig_atomic_t stopping, vt_release_requested, vt_acquire_requested;
static int signal_wake_pipe[2] = {-1, -1};

static void wake_event_loop(void) {
    int saved_errno = errno;
    uint8_t byte = 1;

    if (signal_wake_pipe[1] >= 0) {
        ssize_t written = write(signal_wake_pipe[1], &byte, sizeof(byte));
        (void)written;
    }
    errno = saved_errno;
}

static void stop_now(int sig) {
    (void)sig;
    stopping = 1;
    wake_event_loop();
}

static void request_vt_release(int sig) {
    (void)sig;
    vt_release_requested = 1;
    wake_event_loop();
}

static void request_vt_acquire(int sig) {
    (void)sig;
    vt_acquire_requested = 1;
    wake_event_loop();
}

static int open_signal_wake_pipe(void) {
    int i;

    if (pipe(signal_wake_pipe) < 0) {
        return -1;
    }
    for (i = 0; i < 2; i++) {
        int flags = fcntl(signal_wake_pipe[i], F_GETFL);
        int fd_flags = fcntl(signal_wake_pipe[i], F_GETFD);
        if (flags < 0 || fd_flags < 0 || fcntl(signal_wake_pipe[i], F_SETFL, flags | O_NONBLOCK) < 0 ||
            fcntl(signal_wake_pipe[i], F_SETFD, fd_flags | FD_CLOEXEC) < 0) {
            close(signal_wake_pipe[0]);
            close(signal_wake_pipe[1]);
            signal_wake_pipe[0] = signal_wake_pipe[1] = -1;
            return -1;
        }
    }
    return 0;
}

static void close_signal_wake_pipe(void) {
    if (signal_wake_pipe[0] >= 0) {
        close(signal_wake_pipe[0]);
    }
    if (signal_wake_pipe[1] >= 0) {
        close(signal_wake_pipe[1]);
    }
    signal_wake_pipe[0] = signal_wake_pipe[1] = -1;
}

static void drain_signal_wake_pipe(void) {
    uint8_t bytes[64];

    while (read(signal_wake_pipe[0], bytes, sizeof(bytes)) > 0) {
        ;
    }
}

static int install_signal_handlers(void) {
    struct sigaction action;

    if (open_signal_wake_pipe() < 0) {
        return -1;
    }
    memset(&action, 0, sizeof(action));
    action.sa_handler = stop_now;
    sigemptyset(&action.sa_mask);
    /* Deliberately omit SA_RESTART as a fallback; the self-pipe is the reliable
     * wakeup path around the flag-check/poll boundary. */
    if (sigaction(SIGINT, &action, NULL) < 0 || sigaction(SIGTERM, &action, NULL) < 0 ||
        sigaction(SIGHUP, &action, NULL) < 0) {
        return -1;
    }
    action.sa_handler = request_vt_release;
    if (sigaction(SIGUSR1, &action, NULL) < 0) {
        return -1;
    }
    action.sa_handler = request_vt_acquire;
    if (sigaction(SIGUSR2, &action, NULL) < 0) {
        return -1;
    }
    return 0;
}

static const uint32_t palette[9] = {0x050505, 0xf1f1e8, 0xef3e36, 0x2677c9, 0xe67e2f,
                                    0xf2d34f, 0x74b83f, 0x9b45b2, 0x444444};

static const uint8_t font5x7[96][7] = {
    [0] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},  [1] = {0x04, 0x04, 0x04, 0x04, 0x04, 0x00, 0x04},
    [2] = {0x0a, 0x0a, 0x0a, 0x00, 0x00, 0x00, 0x00},  [3] = {0x0a, 0x1f, 0x0a, 0x0a, 0x1f, 0x0a, 0x00},
    [4] = {0x0e, 0x11, 0x01, 0x02, 0x04, 0x00, 0x04},  [5] = {0x19, 0x1a, 0x04, 0x08, 0x16, 0x06, 0x00},
    [6] = {0x0c, 0x12, 0x14, 0x08, 0x15, 0x12, 0x0d},  [7] = {0x04, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00},
    [8] = {0x02, 0x04, 0x08, 0x08, 0x08, 0x04, 0x02},  [9] = {0x08, 0x04, 0x02, 0x02, 0x02, 0x04, 0x08},
    [10] = {0x00, 0x15, 0x0e, 0x1f, 0x0e, 0x15, 0x00}, [11] = {0x00, 0x04, 0x04, 0x1f, 0x04, 0x04, 0x00},
    [12] = {0x00, 0x00, 0x00, 0x00, 0x04, 0x04, 0x08}, [13] = {0x00, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x00},
    [14] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x04}, [15] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x00, 0x00},
    [16] = {0x0e, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0e}, [17] = {0x04, 0x0c, 0x04, 0x04, 0x04, 0x04, 0x0e},
    [18] = {0x0e, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1f}, [19] = {0x1e, 0x01, 0x01, 0x0e, 0x01, 0x01, 0x1e},
    [20] = {0x02, 0x06, 0x0a, 0x12, 0x1f, 0x02, 0x02}, [21] = {0x1f, 0x10, 0x10, 0x1e, 0x01, 0x01, 0x1e},
    [22] = {0x0e, 0x10, 0x10, 0x1e, 0x11, 0x11, 0x0e}, [23] = {0x1f, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08},
    [24] = {0x0e, 0x11, 0x11, 0x0e, 0x11, 0x11, 0x0e}, [25] = {0x0e, 0x11, 0x11, 0x0f, 0x01, 0x01, 0x0e},
    [26] = {0x00, 0x04, 0x04, 0x00, 0x04, 0x04, 0x00}, [27] = {0x00, 0x04, 0x04, 0x00, 0x04, 0x04, 0x08},
    [28] = {0x02, 0x04, 0x08, 0x10, 0x08, 0x04, 0x02}, [29] = {0x00, 0x00, 0x1f, 0x00, 0x1f, 0x00, 0x00},
    [30] = {0x08, 0x04, 0x02, 0x01, 0x02, 0x04, 0x08}, [31] = {0x0e, 0x11, 0x01, 0x02, 0x04, 0x00, 0x04},
    [32] = {0x0e, 0x11, 0x17, 0x15, 0x17, 0x10, 0x0e}, [33] = {0x0e, 0x11, 0x11, 0x1f, 0x11, 0x11, 0x11},
    [34] = {0x1e, 0x11, 0x11, 0x1e, 0x11, 0x11, 0x1e}, [35] = {0x0f, 0x10, 0x10, 0x10, 0x10, 0x10, 0x0f},
    [36] = {0x1e, 0x11, 0x11, 0x11, 0x11, 0x11, 0x1e}, [37] = {0x1f, 0x10, 0x10, 0x1e, 0x10, 0x10, 0x1f},
    [38] = {0x1f, 0x10, 0x10, 0x1e, 0x10, 0x10, 0x10}, [39] = {0x0f, 0x10, 0x10, 0x17, 0x11, 0x11, 0x0f},
    [40] = {0x11, 0x11, 0x11, 0x1f, 0x11, 0x11, 0x11}, [41] = {0x1f, 0x04, 0x04, 0x04, 0x04, 0x04, 0x1f},
    [42] = {0x07, 0x02, 0x02, 0x02, 0x02, 0x12, 0x0c}, [43] = {0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11},
    [44] = {0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1f}, [45] = {0x11, 0x1b, 0x15, 0x15, 0x11, 0x11, 0x11},
    [46] = {0x11, 0x19, 0x15, 0x13, 0x11, 0x11, 0x11}, [47] = {0x0e, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0e},
    [48] = {0x1e, 0x11, 0x11, 0x1e, 0x10, 0x10, 0x10}, [49] = {0x0e, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0d},
    [50] = {0x1e, 0x11, 0x11, 0x1e, 0x14, 0x12, 0x11}, [51] = {0x0f, 0x10, 0x10, 0x0e, 0x01, 0x01, 0x1e},
    [52] = {0x1f, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04}, [53] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0e},
    [54] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x0a, 0x04}, [55] = {0x11, 0x11, 0x11, 0x15, 0x15, 0x15, 0x0a},
    [56] = {0x11, 0x11, 0x0a, 0x04, 0x0a, 0x11, 0x11}, [57] = {0x11, 0x11, 0x0a, 0x04, 0x04, 0x04, 0x04},
    [58] = {0x1f, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1f}, [59] = {0x0e, 0x08, 0x08, 0x08, 0x08, 0x08, 0x0e},
    [60] = {0x10, 0x08, 0x04, 0x02, 0x01, 0x00, 0x00}, [61] = {0x0e, 0x02, 0x02, 0x02, 0x02, 0x02, 0x0e},
    [62] = {0x0e, 0x11, 0x01, 0x02, 0x04, 0x00, 0x04}, [63] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f},
    [64] = {0x0e, 0x11, 0x01, 0x02, 0x04, 0x00, 0x04}, [65] = {0x00, 0x00, 0x0e, 0x01, 0x0f, 0x11, 0x0f},
    [66] = {0x10, 0x10, 0x16, 0x19, 0x11, 0x11, 0x1e}, [67] = {0x00, 0x00, 0x0e, 0x10, 0x10, 0x11, 0x0e},
    [68] = {0x01, 0x01, 0x0d, 0x13, 0x11, 0x11, 0x0f}, [69] = {0x00, 0x00, 0x0e, 0x11, 0x1f, 0x10, 0x0e},
    [70] = {0x06, 0x08, 0x08, 0x1c, 0x08, 0x08, 0x08}, [71] = {0x00, 0x0f, 0x11, 0x11, 0x0f, 0x01, 0x0e},
    [72] = {0x10, 0x10, 0x16, 0x19, 0x11, 0x11, 0x11}, [73] = {0x04, 0x00, 0x0c, 0x04, 0x04, 0x04, 0x0e},
    [74] = {0x02, 0x00, 0x06, 0x02, 0x02, 0x12, 0x0c}, [75] = {0x10, 0x10, 0x12, 0x14, 0x18, 0x14, 0x12},
    [76] = {0x0c, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0e}, [77] = {0x00, 0x00, 0x1a, 0x15, 0x15, 0x15, 0x15},
    [78] = {0x00, 0x00, 0x16, 0x19, 0x11, 0x11, 0x11}, [79] = {0x00, 0x00, 0x0e, 0x11, 0x11, 0x11, 0x0e},
    [80] = {0x00, 0x1e, 0x11, 0x11, 0x1e, 0x10, 0x10}, [81] = {0x00, 0x0f, 0x11, 0x11, 0x0f, 0x01, 0x01},
    [82] = {0x00, 0x00, 0x16, 0x19, 0x10, 0x10, 0x10}, [83] = {0x00, 0x00, 0x0f, 0x10, 0x0e, 0x01, 0x1e},
    [84] = {0x08, 0x08, 0x1c, 0x08, 0x08, 0x09, 0x06}, [85] = {0x00, 0x00, 0x11, 0x11, 0x11, 0x13, 0x0d},
    [86] = {0x00, 0x00, 0x11, 0x11, 0x11, 0x0a, 0x04}, [87] = {0x00, 0x00, 0x11, 0x11, 0x15, 0x15, 0x0a},
    [88] = {0x00, 0x00, 0x11, 0x0a, 0x04, 0x0a, 0x11}, [89] = {0x00, 0x11, 0x11, 0x11, 0x0f, 0x01, 0x0e},
    [90] = {0x00, 0x00, 0x1f, 0x02, 0x04, 0x08, 0x1f}, [91] = {0x0e, 0x11, 0x01, 0x02, 0x04, 0x00, 0x04},
    [92] = {0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04}, [93] = {0x0e, 0x11, 0x01, 0x02, 0x04, 0x00, 0x04},
    [94] = {0x0e, 0x11, 0x01, 0x02, 0x04, 0x00, 0x04}, [95] = {0x0e, 0x11, 0x01, 0x02, 0x04, 0x00, 0x04},
};

static int source_open(Source *s, const char *path) {
    struct stat st;
    uint64_t bytes = 0;
    memset(s, 0, sizeof(*s));
    s->fd = -1;
    s->path = path;
    s->fd = open(path, O_RDONLY | O_CLOEXEC);
    if (s->fd < 0) {
        return -1;
    }
    if (fstat(s->fd, &st) < 0) {
        return -1;
    }
    if (S_ISREG(st.st_mode)) {
        bytes = (uint64_t)st.st_size;
    } else if (S_ISBLK(st.st_mode)) {
        if (ioctl(s->fd, BLKGETSIZE64, &bytes) < 0) {
            return -1;
        }
    } else {
        errno = ENOTSUP;
        return -1;
    }
    s->size = bytes;
    return 0;
}

static ssize_t source_read(const Source *s, void *buf, size_t count, uint64_t off) {
    size_t done = 0;
    ((Source *)s)->read_calls++;
    if (off >= s->size) {
        return 0;
    }
    if ((uint64_t)count > s->size - off) {
        count = (size_t)(s->size - off);
    }
    while (done < count) {
        ssize_t n = pread(s->fd, (uint8_t *)buf + done, count - done, (off_t)(off + done));
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return done ? (ssize_t)done : n;
        }
        done += (size_t)n;
    }
    return (ssize_t)done;
}

static Cell byte_cell(uint8_t b) {
    static const uint8_t ring[] = {3, 4, 5, 2, 7, 8};
    if (!b) {
        return (Cell){0, "00"};
    }
    if (b == 255) {
        return (Cell){1, "ff"};
    }
    if (b >= 32 && b <= 126) {
        return (Cell){6, "text"};
    }
    return (Cell){ring[((unsigned)b * 6u) / 256u], "byte"};
}

static Cell summary_cell(const uint8_t *p, size_t n) {
    unsigned hist[256] = {0};
    size_t zero = 0, ff = 0, printable = 0, unique = 0, i;
    double entropy = 0.0;
    if (!n) {
        return (Cell){8, "unreadable"};
    }
    for (i = 0; i < n; i++) {
        hist[p[i]]++;
        zero += p[i] == 0;
        ff += p[i] == 255;
        printable += p[i] == 9 || p[i] == 10 || p[i] == 13 || (p[i] >= 32 && p[i] <= 126);
    }
    for (i = 0; i < 256; i++) {
        if (hist[i]) {
            double q = (double)hist[i] / (double)n;
            unique++;
            entropy -= q * log2(q);
        }
    }
    if (zero == n) {
        return (Cell){0, "zero"};
    }
    if (ff == n) {
        return (Cell){1, "ff"};
    }
    if ((double)printable / n >= .85) {
        return (Cell){6, "text"};
    }
    if ((double)zero / n >= .75) {
        return (Cell){8, "sparse"};
    }
    if (unique <= 4 || entropy < 2.0) {
        return (Cell){3, "repeat"};
    }
    if (entropy < 4.0) {
        return (Cell){4, "low-H"};
    }
    if (entropy < 5.5) {
        return (Cell){5, "mid-H"};
    }
    if (entropy < 7.0) {
        return (Cell){7, "dense"};
    }
    return (Cell){2, "high-H"};
}

/* Match Python's viewport loader: one contiguous read (including previous
 * byte and short-cell context) for bounded views, or one representative read
 * per cell when the viewport would exceed BATCH_MAX. */
static int make_grid_data(const Source *s, uint64_t start, uint64_t scale, size_t count, Cell *cells,
                          uint8_t *samples, uint8_t *contexts, uint8_t *previous, uint16_t *sample_n,
                          uint16_t *context_n) {
    uint8_t *batch = NULL, local[SAMPLE_MAX + 1];
    size_t batch_n = 0, i;
    uint64_t total, batch_start = 0;
    if (!scale || count > UINT64_MAX / scale) {
        errno = EOVERFLOW;
        return -1;
    }
    total = scale * count;
    if (total <= BATCH_MAX && start < s->size) {
        uint64_t extra, want, avail;
        batch_start = start ? start - 1 : start;
        extra = start - batch_start + 256;
        want = total > UINT64_MAX - extra ? UINT64_MAX : total + extra;
        avail = s->size - batch_start;
        if (want > avail) {
            want = avail;
        }
        batch_n = (size_t)want;
        batch = malloc(batch_n ? batch_n : 1);
        if (!batch || source_read(s, batch, batch_n, batch_start) != (ssize_t)batch_n) {
            free(batch);
            return -1;
        }
    }
    for (i = 0; i < count; i++) {
        uint64_t off, span, sample_start;
        size_t n = 0, cn = 0;
        uint8_t prev = 0, *dst = samples ? samples + i * SAMPLE_MAX : local;
        if (i > (UINT64_MAX - start) / scale) {
            off = UINT64_MAX;
        } else {
            off = start + (uint64_t)i * scale;
        }
        if (off < s->size) {
            span = s->size - off;
            if (span > scale) {
                span = scale;
            }
            n = (size_t)(span > SAMPLE_MAX ? SAMPLE_MAX : span);
            sample_start = span > SAMPLE_MAX ? off + (span - n) / 2 : off;
            if (batch) {
                size_t rel = (size_t)(sample_start - batch_start);
                memcpy(dst, batch + rel, n);
                if (sample_start > batch_start) {
                    prev = batch[rel - 1];
                }
                if (span < 256) {
                    cn = (size_t)((s->size - off) < 256 ? s->size - off : 256);
                    if (contexts) {
                        memcpy(contexts + i * SAMPLE_MAX, batch + (size_t)(off - batch_start), cn);
                    }
                } else {
                    cn = n;
                    if (contexts) {
                        memcpy(contexts + i * SAMPLE_MAX, dst, n);
                    }
                }
            } else {
                uint64_t read_start = sample_start ? sample_start - 1 : sample_start;
                size_t want = n + (sample_start ? 1 : 0);
                ssize_t got = source_read(s, local, want, read_start);
                if (got < 0) {
                    free(batch);
                    return -1;
                }
                if (sample_start) {
                    prev = got ? local[0] : 0;
                    n = got > 0 ? (size_t)got - 1 : 0;
                    if (samples) {
                        memcpy(dst, local + 1, n);
                    } else {
                        memmove(local, local + 1, n);
                    }
                } else {
                    n = (size_t)got;
                }
                cn = n;
                if (contexts) {
                    memcpy(contexts + i * SAMPLE_MAX, dst, n);
                }
            }
            cells[i] = span == 1 && n ? byte_cell(dst[0]) : summary_cell(dst, n);
        } else {
            cells[i] = (Cell){8, "eof"};
        }
        if (previous) {
            previous[i] = prev;
        }
        if (sample_n) {
            sample_n[i] = (uint16_t)n;
        }
        if (context_n) {
            context_n[i] = (uint16_t)cn;
        }
    }
    free(batch);
    return 0;
}
static int make_grid(const Source *s, uint64_t start, uint64_t scale, size_t count, Cell *cells) {
    return make_grid_data(s, start, scale, count, cells, NULL, NULL, NULL, NULL, NULL);
}

static uint8_t scalar_color(double v) {
    if (v <= .005) {
        return 0;
    }
    if (v < .05) {
        return 3;
    }
    if (v < .15) {
        return 6;
    }
    if (v < .30) {
        return 5;
    }
    if (v < .50) {
        return 4;
    }
    if (v < .70) {
        return 7;
    }
    return 2;
}
static uint8_t similarity_color(double v) {
    if (v < .02) {
        return 0;
    }
    if (v < .10) {
        return 3;
    }
    if (v < .25) {
        return 6;
    }
    if (v < .45) {
        return 5;
    }
    if (v < .65) {
        return 4;
    }
    if (v < .85) {
        return 2;
    }
    if (v < .999) {
        return 7;
    }
    return 1;
}
static double jsd16(const uint8_t *a, size_t an, const uint8_t *b, size_t bn) {
    unsigned ah[16] = {0}, bh[16] = {0};
    double d = 0;
    size_t i;
    if (!an || !bn) {
        return 0;
    }
    for (i = 0; i < an; i++) {
        ah[a[i] >> 4]++;
    }
    for (i = 0; i < bn; i++) {
        bh[b[i] >> 4]++;
    }
    for (i = 0; i < 16; i++) {
        double p = (double)ah[i] / an, q = (double)bh[i] / bn, m = (p + q) / 2;
        if (p) {
            d += .5 * p * log2(p / m);
        }
        if (q) {
            d += .5 * q * log2(q / m);
        }
    }
    return d;
}
static Cell classify_lens(int lens, const uint8_t *p, size_t n, uint8_t previous, const uint8_t *neighbor,
                          size_t nn, const uint8_t *cursor, size_t cn) {
    uint8_t tmp[SAMPLE_MAX];
    size_t i;
    double score;
    if (!n) {
        return (Cell){8, "eof"};
    }
    if (lens == 1) {
        return n == 1 ? byte_cell(*p) : summary_cell(p, n);
    }
    if (lens == 2) {
        for (i = 0; i < n; i++) {
            tmp[i] = p[i] ^ (i ? p[i - 1] : previous);
        }
        return n == 1 ? byte_cell(tmp[0]) : summary_cell(tmp, n);
    }
    if (lens == 3) {
        double sum = 0;
        for (i = 0; i < n; i++) {
            sum += abs((int)p[i] - (int)(i ? p[i - 1] : previous));
        }
        return (Cell){scalar_color(sum / n / 255.0), "delta"};
    }
    if (lens == 4) {
        uLongf outn = compressBound(n);
        uint8_t *out = malloc(outn);
        int ok = out && compress2(out, &outn, p, n, 1) == Z_OK;
        score = ok ? fmin(1.0, (double)outn / n) : 1;
        free(out);
        return (Cell){scalar_color(score), "compress"};
    }
    if (lens == 5) {
        return (Cell){scalar_color(neighbor ? jsd16(p, n, neighbor, nn) : 0), "neighbor-diff"};
    }
    if (lens == 6) {
        size_t same = 0, common = n < cn ? n : cn;
        if (!common) {
            score = 0;
        } else {
            for (i = 0; i < common; i++) {
                same += p[i] == cursor[i];
            }
            score = (double)same / common;
        }
        return (Cell){similarity_color(score), "cursor-sim"};
    }
    return summary_cell(p, n);
}

static void recolor_grid(const View *v, RenderCache *c) {
    size_t i, cursor_i = 0;
    if (v->cursor >= v->view) {
        cursor_i = (size_t)((v->cursor - v->view) / v->scale);
    }
    if (cursor_i >= c->count) {
        cursor_i = 0;
    }
    for (i = 0; i < c->count; i++) {
        const uint8_t *p = v->lens == 4 ? c->contexts + i * SAMPLE_MAX : c->samples + i * SAMPLE_MAX;
        size_t n = v->lens == 4 ? c->context_n[i] : c->sample_n[i];
        c->cells[i] = classify_lens(v->lens, p, n, c->previous[i],
                                    i ? c->samples + (i - 1) * SAMPLE_MAX : NULL, i ? c->sample_n[i - 1] : 0,
                                    c->samples + cursor_i * SAMPLE_MAX, c->sample_n[cursor_i]);
    }
    c->recolor_count++;
}

static int parse_u64(const char *text, int fractional, uint64_t *out) {
    char *end;
    double d;
    uint64_t mult = 1;
    if (!fractional) {
        unsigned long long integer;
        errno = 0;
        integer = strtoull(text, &end, 0);
        if (errno || end == text) {
            return -1;
        }
        if (*end) {
            switch (*end | 32) {
            case 'k':
                mult = 1024;
                break;
            case 'm':
                mult = 1024ULL * 1024;
                break;
            case 'g':
                mult = 1024ULL * 1024 * 1024;
                break;
            case 't':
                mult = 1024ULL * 1024 * 1024 * 1024;
                break;
            default:
                return -1;
            }
            end++;
        }
        if (*end || integer > UINT64_MAX / mult) {
            return -1;
        }
        *out = (uint64_t)integer * mult;
        return 0;
    }
    errno = 0;
    d = strtod(text, &end);
    if (errno || end == text || d < 0) {
        return -1;
    }
    if (*end) {
        switch (*end | 32) {
        case 'k':
            mult = 1024;
            break;
        case 'm':
            mult = 1024ULL * 1024;
            break;
        case 'g':
            mult = 1024ULL * 1024 * 1024;
            break;
        case 't':
            mult = 1024ULL * 1024 * 1024 * 1024;
            break;
        default:
            return -1;
        }
        end++;
        if ((*end == 'b' || *end == 'B') && !end[1]) {
            end++;
        }
    }
    if (*end || (!fractional && d != floor(d)) || !isfinite(d) || d * mult > UINT64_MAX ||
        d * mult != floor(d * mult)) {
        return -1;
    }
    *out = (uint64_t)(d * mult);
    return 0;
}

static uint32_t pack_pixel(const Display *d, uint32_t rgb) {
    uint32_t r = (rgb >> 16) & 255, g = (rgb >> 8) & 255, b = rgb & 255;
    r = ((r * ((1u << d->var.red.length) - 1) + 127) / 255) << d->var.red.offset;
    g = ((g * ((1u << d->var.green.length) - 1) + 127) / 255) << d->var.green.offset;
    b = ((b * ((1u << d->var.blue.length) - 1) + 127) / 255) << d->var.blue.offset;
    return r | g | b;
}
static void rect(Display *d, int x, int y, int w, int h, uint32_t rgb) {
    int yy, xx, bytes = d->var.bits_per_pixel / 8;
    uint32_t px = pack_pixel(d, rgb);
    if (d->measure_text) {
        return;
    }
    if (x < 0) {
        w += x;
        x = 0;
    }
    if (y < 0) {
        h += y;
        y = 0;
    }
    if (x + w > (int)d->var.xres) {
        w = d->var.xres - x;
    }
    if (y + h > (int)d->var.yres) {
        h = d->var.yres - y;
    }
    for (yy = y; yy < y + h; yy++) {
        for (xx = x; xx < x + w; xx++) {
            memcpy(d->back + (size_t)yy * d->fix.line_length + (size_t)xx * bytes, &px, (size_t)bytes);
        }
    }
}
static void text5(Display *d, int x, int y, const char *s, uint32_t rgb) {
    int size = d->font_scale > 0 ? d->font_scale : 1;
    int width = *s ? (int)strlen(s) * 6 * size - size : 0;
    if (d->measure_text) {
        int right = x + width;
        if (right > d->measured_text_width) {
            d->measured_text_width = right;
        }
        return;
    }
    for (; *s; s++, x += 6 * size) {
        unsigned c = (unsigned char)*s;
        int yy, xx;
        const uint8_t *glyph;
        if (c < 32 || c > 127) {
            c = '?';
        }
        glyph = font5x7[c - 32];
        for (yy = 0; yy < 7; yy++) {
            for (xx = 0; xx < 5; xx++) {
                if (glyph[yy] & (1u << (4 - xx))) {
                    rect(d, x + xx * size, y + yy * size, size, size, rgb);
                }
            }
        }
    }
}

static void display_close(Display *d) {
    if (d->tty >= 0) {
        if (d->vt_process && d->vt_mode_saved) {
            ioctl(d->tty, VT_SETMODE, &d->saved_vt_mode);
            d->vt_process = 0;
        }
        if (d->raw) {
            tcsetattr(d->tty, TCSAFLUSH, &d->saved_termios);
        }
        if (d->keyboard_mode_saved) {
            ioctl(d->tty, KDSKBMODE, d->keyboard_mode);
        }
        if (d->kd_mode >= 0) {
            ioctl(d->tty, KDSETMODE, d->kd_mode);
        }
    }
    if (d->mapped) {
        munmap(d->map, d->map_len);
    }
    free(d->back);
    if (d->fd >= 0) {
        close(d->fd);
    }
    if (d->tty >= 0) {
        close(d->tty);
    }
    if (d->mouse >= 0) {
        close(d->mouse);
    }
}
static int display_open(Display *d, const char *fb, const char *mouse) {
    struct termios raw;
    struct vt_mode process_mode;
    memset(d, 0, sizeof(*d));
    d->fd = d->tty = d->kd_mode = d->mouse = -1;
    d->tty = open("/dev/tty", O_RDWR | O_CLOEXEC);
    if (d->tty < 0) {
        fprintf(stderr, "fatpix-c: cannot open controlling VT: %s\n", strerror(errno));
        return -1;
    }
    if (ioctl(d->tty, KDGETMODE, &d->kd_mode) < 0) {
        fprintf(stderr, "fatpix-c: controlling terminal is not a Linux VT: %s\n", strerror(errno));
        return -1;
    }
    if (ioctl(d->tty, KDGKBMODE, &d->keyboard_mode) < 0) {
        fprintf(stderr, "fatpix-c: cannot inspect Linux VT keyboard mode: %s\n", strerror(errno));
        return -1;
    }
    d->keyboard_mode_saved = 1;
    if ((d->keyboard_mode == K_RAW || d->keyboard_mode == K_MEDIUMRAW) &&
        ioctl(d->tty, KDSKBMODE, K_XLATE) < 0) {
        fprintf(stderr, "fatpix-c: cannot enable kernel VT-switch keys: %s\n", strerror(errno));
        return -1;
    }
    if (ioctl(d->tty, VT_GETMODE, &d->saved_vt_mode) < 0) {
        fprintf(stderr, "fatpix-c: cannot read Linux VT switching mode: %s\n", strerror(errno));
        return -1;
    }
    d->vt_mode_saved = 1;
    process_mode = d->saved_vt_mode;
    process_mode.mode = VT_PROCESS;
    process_mode.relsig = SIGUSR1;
    process_mode.acqsig = SIGUSR2;
    process_mode.frsig = 0;
    if (ioctl(d->tty, VT_SETMODE, &process_mode) < 0) {
        fprintf(stderr, "fatpix-c: cannot enable Linux VT process switching: %s\n", strerror(errno));
        return -1;
    }
    d->vt_process = 1;
    d->active = 1;
    if (tcgetattr(d->tty, &d->saved_termios) < 0) {
        return -1;
    }
    raw = d->saved_termios;
    cfmakeraw(&raw);
    if (tcsetattr(d->tty, TCSAFLUSH, &raw) < 0) {
        return -1;
    }
    d->raw = 1;
    d->fd = open(fb, O_RDWR | O_CLOEXEC);
    if (d->fd < 0) {
        fprintf(stderr, "fatpix-c: cannot open %s: %s\n", fb, strerror(errno));
        return -1;
    }
    if (ioctl(d->fd, FBIOGET_FSCREENINFO, &d->fix) < 0 || ioctl(d->fd, FBIOGET_VSCREENINFO, &d->var) < 0) {
        return -1;
    }
    if (d->var.bits_per_pixel != 32) {
        fprintf(stderr, "fatpix-c: framebuffer must be 32 bpp (got %u)\n", d->var.bits_per_pixel);
        errno = ENOTSUP;
        return -1;
    }
    d->map_len = d->fix.smem_len;
    d->map = mmap(NULL, d->map_len, PROT_READ | PROT_WRITE, MAP_SHARED, d->fd, 0);
    if (d->map == MAP_FAILED) {
        d->map = NULL;
        return -1;
    }
    d->mapped = 1;
    d->back = calloc(1, d->map_len);
    if (!d->back) {
        return -1;
    }
    if (ioctl(d->tty, KDSETMODE, KD_GRAPHICS) < 0) {
        return -1;
    }
    if (mouse) {
        d->mouse = open(mouse, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    }
    return 0;
}

static const char *base_name(const char *p) {
    const char *q = strrchr(p, '/');
    return q ? q + 1 : p;
}
static void human_scale(uint64_t n, char *buf, size_t cap) {
    const char *u[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double v = n;
    int i = 0;
    while (v >= 1024 && i < 4) {
        v /= 1024;
        i++;
    }
    if (!i) {
        snprintf(buf, cap, "%lluB", (unsigned long long)n);
    } else {
        snprintf(buf, cap, "%.1f%s", v, u[i]);
    }
}
static void outline(Display *d, int x, int y, int cell, uint32_t color) {
    rect(d, x, y, cell, 1, color);
    rect(d, x, y + cell - 1, cell, 1, color);
    rect(d, x, y, 1, cell, color);
    rect(d, x + cell - 1, y, 1, cell, color);
}

static void inspector_position(const Display *d, View *v, const RenderCache *cache, int panel_w,
                               int panel_h, int *x, int *y) {
    size_t index = v->cursor >= v->view ? (size_t)((v->cursor - v->view) / v->scale) : 0;
    int cursor_x = (int)(index % (size_t)cache->cols) * v->cell;
    int cursor_y = (int)(index / (size_t)cache->cols) * v->cell;
    int margin = v->cell + 8;
    int overlap;
    int anchored_left = v->inspector_x == 8;
    int anchored_top = v->inspector_y == 8;

    overlap = v->inspector_positioned && cursor_x + v->cell + margin >= v->inspector_x &&
              cursor_x - margin < v->inspector_x + v->inspector_w &&
              cursor_y + v->cell + margin >= v->inspector_y &&
              cursor_y - margin < v->inspector_y + v->inspector_h;
    if (!v->inspector_positioned || overlap) {
        int cursor_right = cursor_x + v->cell / 2 >= (int)d->var.xres / 2;
        int cursor_bottom = cursor_y + v->cell / 2 >= (int)d->var.yres / 2;
        v->inspector_x = cursor_right ? 8 : (int)d->var.xres - panel_w - 8;
        v->inspector_y = cursor_bottom ? 8 : (int)d->var.yres - panel_h - 8;
        v->inspector_positioned = 1;
    } else {
        v->inspector_x = anchored_left ? 8 : (int)d->var.xres - panel_w - 8;
        v->inspector_y = anchored_top ? 8 : (int)d->var.yres - panel_h - 8;
    }
    v->inspector_w = panel_w;
    v->inspector_h = panel_h;
    *x = v->inspector_x;
    *y = v->inspector_y;
}

static uint64_t inspection_start(const Source *s, const View *v) {
    uint64_t span = s->size - v->cursor < v->scale ? s->size - v->cursor : v->scale;
    if (v->inspect_focus < s->size) {
        return v->inspect_focus;
    }
    return span > 1024 ? v->cursor + (span - 1024) / 2 : v->cursor;
}
static uint16_t le16(const uint8_t *p) { return (uint16_t)p[0] | (uint16_t)p[1] << 8; }
static uint32_t le32(const uint8_t *p) { return (uint32_t)le16(p) | (uint32_t)le16(p + 2) << 16; }
static uint64_t le64(const uint8_t *p) { return (uint64_t)le32(p) | (uint64_t)le32(p + 4) << 32; }
static uint16_t be16(const uint8_t *p) { return (uint16_t)p[0] << 8 | p[1]; }
static uint32_t be32(const uint8_t *p) { return (uint32_t)be16(p) << 16 | be16(p + 2); }
static uint64_t be64(const uint8_t *p) { return (uint64_t)be32(p) << 32 | be32(p + 4); }
static int render_inspector(Display *d, const Source *s, View *v, RenderCache *cache) {
    char line[512];
    int measuring = d->measure_text;
    int size = d->font_scale > 0 ? d->font_scale : 1, panel_w, panel_h = 150 * size, x = 0, y = 0, row;
    uint64_t cell_index = v->cursor >= v->view ? (v->cursor - v->view) / v->scale : 0,
             cell_start = v->view + cell_index * v->scale;
    uint64_t start = inspection_start(s, v),
             span = s->size - cell_start < v->scale ? s->size - cell_start : v->scale;
    size_t want = span < 256 ? 256 : (span < 1024 ? (size_t)span : 1024), n;
    if (!measuring) {
        d->measure_text = 1;
        d->measured_text_width = 0;
        if (render_inspector(d, s, v, cache) < 0) {
            d->measure_text = 0;
            return -1;
        }
        d->measure_text = 0;
        panel_w = d->measured_text_width + 8 * size;
        if (panel_w > (int)d->var.xres - 16) {
            panel_w = (int)d->var.xres - 16;
        }
    } else {
        panel_w = 0;
    }
    if (panel_h > (int)d->var.yres - 16) {
        panel_h = (int)d->var.yres - 16;
    }
    if (!measuring) {
        inspector_position(d, v, cache, panel_w, panel_h, &x, &y);
        rect(d, x - 2, y - 2, panel_w + 4, panel_h + 4, 0xe0e0e0);
        rect(d, x, y, panel_w, panel_h, 0x101010);
    }
    snprintf(line, sizeof(line), "INSPECT %s %d/7  (,/. PAGE i/ESC CLOSE)", page_names[v->inspect_page],
             v->inspect_page + 1);
    text5(d, x + 8 * size, y + 7 * size, line, 0xf1f1e8);
    if (!cache->inspect_valid || cache->inspect_start != start) {
        ssize_t got = source_read(s, cache->inspect_data, want, start);
        if (got < 0) {
            return -1;
        }
        cache->inspect_start = start;
        cache->inspect_n = (size_t)got;
        cache->inspect_valid = 1;
    }
    n = cache->inspect_n;
#define LINE(...)                                                                                            \
    do {                                                                                                     \
        snprintf(line, sizeof(line), __VA_ARGS__);                                                           \
        text5(d, x + 8 * size, y + (21 + row++ * 8) * size, line, 0xd0d0d0);                                 \
    } while (0)
    row = 0;
    if (v->inspect_page == 0 || v->inspect_page == 6) {
        size_t off, j, changed = 0;
        if (v->inspect_page == 6 && cache->baseline_n && cache->baseline_scale == v->scale) {
            size_t common = n < cache->baseline_n ? n : cache->baseline_n;
            for (j = 0; j < common; j++) {
                changed += cache->inspect_data[j] != cache->baseline_data[j];
            }
            changed += n > common ? n - common : cache->baseline_n - common;
            LINE("current 0x%llx vs previous 0x%llx; changed %zu/%zuB", (unsigned long long)start,
                 (unsigned long long)cache->baseline_start, changed,
                 n > cache->baseline_n ? n : cache->baseline_n);
        } else {
            LINE("%s %zuB; data starts 0x%llx", span < 256 ? "context" : "sample", n,
                 (unsigned long long)start);
        }
        for (off = 0; off < n && row < 16; off += 12) {
            size_t pos = snprintf(line, sizeof(line), "%08llx  ", (unsigned long long)(start + off));
            for (j = 0; j < 12; j++) {
                pos += snprintf(line + pos, sizeof(line) - pos, off + j < n ? "%02x " : "   ",
                                off + j < n ? cache->inspect_data[off + j] : 0);
            }
            pos += snprintf(line + pos, sizeof(line) - pos, " |");
            for (j = 0; j < 12 && off + j < n; j++) {
                uint8_t q = cache->inspect_data[off + j];
                line[pos++] = q >= 32 && q <= 126 ? q : '.';
            }
            line[pos++] = '|';
            line[pos] = 0;
            if (v->inspect_page == 6 && cache->baseline_n && cache->baseline_scale == v->scale) {
                int ly = y + (21 + row++ * 8) * size;
                char one[4];
                snprintf(line, sizeof(line), "%08llx", (unsigned long long)(start + off));
                text5(d, x + 8 * size, ly, line, 0xd0d0d0);
                text5(d, x + (8 + 47 * 6) * size, ly, "|", 0xd0d0d0);
                for (j = 0; j < 12 && off + j < n; j++) {
                    uint32_t color = off + j >= cache->baseline_n ||
                                             cache->inspect_data[off + j] != cache->baseline_data[off + j]
                                         ? 0xffffff
                                         : 0x666666;
                    snprintf(one, sizeof(one), "%02x", cache->inspect_data[off + j]);
                    text5(d, x + (8 + 10 * 6 + (int)j * 18) * size, ly, one, color);
                    one[0] = cache->inspect_data[off + j] >= 32 && cache->inspect_data[off + j] <= 126
                                 ? cache->inspect_data[off + j]
                                 : '.';
                    one[1] = 0;
                    text5(d, x + (8 + 48 * 6 + (int)j * 6) * size, ly, one, color);
                }
                text5(d, x + (8 + 60 * 6) * size, ly, "|", 0xd0d0d0);
            } else {
                text5(d, x + 8 * size, y + (21 + row++ * 8) * size, line, 0xd0d0d0);
            }
        }
    } else if (v->inspect_page == 1) {
        size_t i, j;
        LINE("printable runs in sample @ 0x%llx", (unsigned long long)start);
        for (i = 0; i < n && row < 16; i = j + 1) {
            for (; i < n && !(cache->inspect_data[i] == 9 ||
                              (cache->inspect_data[i] >= 32 && cache->inspect_data[i] <= 126));
                 i++)
                ;
            for (j = i; j < n && (cache->inspect_data[j] == 9 ||
                                  (cache->inspect_data[j] >= 32 && cache->inspect_data[j] <= 126));
                 j++)
                ;
            if (j - i >= 4) {
                size_t z = snprintf(line, sizeof(line), "+0x%04zx 0x%08llx  '", i,
                                    (unsigned long long)(start + i)),
                       k;
                for (k = i; k < j && z + 5 < sizeof(line); k++) {
                    line[z++] = cache->inspect_data[k] == 9 ? ' ' : cache->inspect_data[k];
                }
                line[z++] = '\'';
                line[z] = 0;
                text5(d, x + 8 * size, y + (21 + row++ * 8) * size, line, 0xd0d0d0);
            }
        }
        if (row == 1) {
            LINE("no ASCII runs >= 4 bytes");
        }
    } else if (v->inspect_page == 2) {
        size_t rel = v->cursor >= start && v->cursor < start + n ? (size_t)(v->cursor - start) : 0;
        uint8_t *q = cache->inspect_data + rel;
        size_t z = n - rel;
        LINE("anchor=0x%llx", (unsigned long long)(start + rel));
        if (z) {
            LINE("u8=%u i8=%d", q[0], (int8_t)q[0]);
        }
        if (z >= 2) {
            LINE("u16 le=%u be=%u", le16(q), be16(q));
            LINE("i16 le=%d be=%d", (int16_t)le16(q), (int16_t)be16(q));
        }
        if (z >= 4) {
            uint32_t lb = le32(q), bb = be32(q);
            float lf, bf;
            memcpy(&lf, &lb, 4);
            memcpy(&bf, &bb, 4);
            LINE("u32 le=%u be=%u", lb, bb);
            LINE("i32 le=%d be=%d", (int32_t)lb, (int32_t)bb);
            LINE("f32 le=%.7g be=%.7g", lf, bf);
        }
        if (z >= 8) {
            uint64_t lb = le64(q), bb = be64(q);
            double ld, bd;
            memcpy(&ld, &lb, 8);
            memcpy(&bd, &bb, 8);
            LINE("u64 le=%llu be=%llu", (unsigned long long)lb, (unsigned long long)bb);
            LINE("f64 le=%.7g be=%.7g", ld, bd);
        }
    } else if (v->inspect_page == 3) {
        static const struct {
            const char *s;
            size_t n;
            const char *l;
        } m[] = {{"%PDF-", 5, "PDF header"},
                 {"\x89PNG\r\n\x1a\n", 8, "PNG signature"},
                 {"\x7f"
                  "ELF",
                  4, "ELF header"},
                 {"PK\x03\x04", 4, "ZIP local header"},
                 {"PK\x05\x06", 4, "ZIP end directory"},
                 {"\x1f\x8b\x08", 3, "gzip header"},
                 {"SQLite format 3\0", 16, "SQLite header"},
                 {"RIFF", 4, "RIFF header"},
                 {"ID3", 3, "ID3 header"},
                 {"\xff\xd8\xff", 3, "JPEG header"}};
        size_t i, j, h = 0;
        LINE("cheap signature scan in sample @ 0x%llx", (unsigned long long)start);
        for (i = 0; i < sizeof(m) / sizeof(*m); i++) {
            for (j = 0; j + m[i].n <= n; j++) {
                if (!memcmp(cache->inspect_data + j, m[i].s, m[i].n)) {
                    LINE("0x%08llx  %s", (unsigned long long)(start + j), m[i].l);
                    h++;
                }
            }
        }
        for (j = 0; j + 1 < n; j++) {
            uint64_t absolute = start + j;
            if (absolute % 512 == 510 && cache->inspect_data[j] == 0x55 &&
                cache->inspect_data[j + 1] == 0xaa) {
                LINE("0x%08llx  boot-sector 55 aa signature", (unsigned long long)absolute);
                h++;
            }
            {
                unsigned cmf = cache->inspect_data[j], flg = cache->inspect_data[j + 1];
                if ((cmf & 15) == 8 && (cmf >> 4) <= 7 && ((cmf << 8) + flg) % 31 == 0) {
                    LINE("0x%08llx  possible zlib header", (unsigned long long)absolute);
                    h++;
                }
            }
        }
        if (!h) {
            LINE("no known signatures in sampled bytes");
        }
    } else if (v->inspect_page == 4) {
        unsigned hist[256] = {0}, unique = 0, topb[6] = {0}, topn[6] = {0};
        size_t i, k, zero = 0, ff = 0, pr = 0,
                     index = v->cursor >= v->view ? (size_t)((v->cursor - v->view) / v->scale) : 0, sn;
        double ent = 0;
        const uint8_t *sample;
        if (index >= cache->count) {
            index = 0;
        }
        sample = cache->samples + index * SAMPLE_MAX;
        sn = cache->sample_n[index];
        for (i = 0; i < sn; i++) {
            uint8_t q = sample[i];
            hist[q]++;
            zero += q == 0;
            ff += q == 255;
            pr += q == 9 || q == 10 || q == 13 || (q >= 32 && q <= 126);
        }
        for (i = 0; i < 256; i++) {
            if (hist[i]) {
                double q = (double)hist[i] / sn;
                unique++;
                ent -= q * log2(q);
                for (k = 0; k < 6; k++) {
                    if (hist[i] > topn[k]) {
                        size_t z;
                        for (z = 5; z > k; z--) {
                            topn[z] = topn[z - 1];
                            topb[z] = topb[z - 1];
                        }
                        topn[k] = hist[i];
                        topb[k] = (unsigned)i;
                        break;
                    }
                }
            }
        }
        {
            uLongf packed = compressBound(n);
            uint8_t *out = malloc(packed);
            int ok = out && compress2(out, &packed, cache->inspect_data, n, 1) == Z_OK;
            LINE("cell=%lluB sample=%zuB @ 0x%llx", (unsigned long long)span, n, (unsigned long long)start);
            LINE("entropy=%.3f bits/B unique=%u", ent, unique);
            LINE("zero=%.2f%% ff=%.2f%% printable=%.2f%%", sn ? 100.0 * zero / sn : 0,
                 sn ? 100.0 * ff / sn : 0, sn ? 100.0 * pr / sn : 0);
            LINE("zlib/raw=%.2f%% (%lu/%zu bytes)", ok && n ? 100.0 * packed / n : 0,
                 (unsigned long)(ok ? packed : 0), n);
            free(out);
        }
        {
            char detail[128] = "";
            if (v->lens == 1) {
                snprintf(detail, sizeof(detail), "kind=%s", cache->cells[index].kind);
            } else if (v->lens == 2) {
                snprintf(detail, sizeof(detail), "xor transformed sample");
            } else if (v->lens == 3) {
                double sum = 0;
                for (i = 0; i < sn; i++) {
                    sum += abs((int)sample[i] - (int)(i ? sample[i - 1] : cache->previous[index]));
                }
                snprintf(detail, sizeof(detail), "mean |delta|=%.1f/255", sn ? sum / sn : 0);
            } else if (v->lens == 4) {
                snprintf(detail, sizeof(detail), "zlib context=%uB", cache->context_n[index]);
            } else if (v->lens == 5) {
                snprintf(detail, sizeof(detail), "neighbor JSD=%.3f",
                         index ? jsd16(sample, sn, cache->samples + (index - 1) * SAMPLE_MAX,
                                       cache->sample_n[index - 1])
                               : 0);
            } else if (v->lens == 6) {
                size_t same = 0, cn = cache->sample_n[0], common = sn < cn ? sn : cn,
                       total = sn > cn ? sn : cn;
                for (i = 0; i < common; i++) {
                    same += sample[i] == cache->samples[i];
                }
                snprintf(detail, sizeof(detail), "cursor similarity=%.0f%%",
                         total ? 100.0 * same / total : 0);
            }
            LINE("lens=%d:%s %s", v->lens, lens_names[v->lens], detail);
        }
        if (topn[0]) {
            size_t pos = snprintf(line, sizeof(line), "top bytes:");
            for (k = 0; k < 6 && topn[k]; k++) {
                pos += snprintf(line + pos, sizeof(line) - pos, " %02x:%u", topb[k], topn[k]);
            }
            text5(d, x + 8 * size, y + (21 + row++ * 8) * size, line, 0xd0d0d0);
        }
    } else {
        size_t index = v->cursor >= v->view ? (size_t)((v->cursor - v->view) / v->scale) : 0, j, pos;
        LINE("cell 0x%llx..0x%llx (%lluB)", (unsigned long long)cell_start,
             (unsigned long long)(cell_start + span), (unsigned long long)span);
        LINE("sample 0x%llx..0x%llx (%zuB)", (unsigned long long)start, (unsigned long long)(start + n), n);
        LINE("cursor=0x%llx screen=%zu,%zu", (unsigned long long)v->cursor, index % (size_t)cache->cols,
             index / (size_t)cache->cols);
        LINE("scale=%lluB/cell row=%lluB", (unsigned long long)v->scale,
             (unsigned long long)(v->scale * cache->cols));
        pos = snprintf(line, sizeof(line), "head:");
        for (j = 0; j < n && j < 16; j++) {
            pos += snprintf(line + pos, sizeof(line) - pos, " %02x", cache->inspect_data[j]);
        }
        text5(d, x + 8 * size, y + (21 + row++ * 8) * size, line, 0xd0d0d0);
        pos = snprintf(line, sizeof(line), "tail:");
        for (j = n > 16 ? n - 16 : 0; j < n; j++) {
            pos += snprintf(line + pos, sizeof(line) - pos, " %02x", cache->inspect_data[j]);
        }
        text5(d, x + 8 * size, y + (21 + row++ * 8) * size, line, 0xd0d0d0);
        LINE("source size=%lluB", (unsigned long long)s->size);
    }
#undef LINE
    return 0;
}
static void render_help(Display *d, const View *v) {
    static const char *general[] = {"FATPIX FILE VIEW - BYTES AS FAT PIXELS",
                                    "ARROWS/WASD MOVE | PGUP/PGDN HALF-PAGE",
                                    "-/= ZOOM | _/+ LARGE ZOOM | G GOTO | : COMMAND",
                                    "1-6 LITERAL/XOR/DELTA/COMPRESS/DIFF/SIMILAR",
                                    "I INSPECT | ,/. PAGE | MOUSE CLICK/DRAG SELECT",
                                    "COMMANDS GOTO|G SCALE|S VIEW DUMP",
                                    "? OR ESC RETURN | Q QUIT"};
    static const char *inspect[] = {"FATPIX INSPECTOR HELP",
                                    "I/ESC CLOSE | ,/. PREV/NEXT PAGE",
                                    "HEX TEXT NUM MAGIC STATS RANGE DIFF HEX",
                                    "NAVIGATION MOVES THE UNDERLYING EXACT CURSOR",
                                    "ZOOM PRESERVES THE INSPECTED BYTE LOCUS",
                                    "MOUSE SELECTS CONTIGUOUS CELL RANGES",
                                    "? OR ESC RETURN | Q QUIT"};
    const char **lines = v->inspect ? inspect : general;
    size_t i;
    int size = d->font_scale > 0 ? d->font_scale : 1;
    rect(d, 0, 0, d->var.xres, d->var.yres, 0x050505);
    for (i = 0; i < 7; i++) {
        text5(d, 8 * size, (int)(8 + i * 12) * size, lines[i], i ? 0xd0d0d0 : 0xf2d34f);
    }
}
static void footer_status(const Source *s, const View *v, char *status, size_t cap) {
    char sc[40], selected[40];

    human_scale(v->scale, sc, sizeof(sc));
    if (v->selection_dragged && v->selection_end > v->selection_start + 1) {
        human_scale(v->selection_end - v->selection_start, selected, sizeof(selected));
        snprintf(status, cap, "file=%s  scale=%s/cell  pos=0x%llx  sel=0x%llx..0x%llx (%s)  view=%s",
                 base_name(s->path), sc, (unsigned long long)v->cursor,
                 (unsigned long long)v->selection_start, (unsigned long long)(v->selection_end - 1),
                 selected, lens_names[v->lens]);
    } else {
        snprintf(status, cap, "file=%s  scale=%s/cell  pos=0x%llx  view=%s", base_name(s->path), sc,
                 (unsigned long long)v->cursor, lens_names[v->lens]);
    }
}

static int render(Display *d, const Source *s, View *v, RenderCache *cache, int grid_dirty) {
    uint64_t view = v->view, scale = v->scale, cursor = v->cursor;
    int cell = v->cell;
    int footer = 22 * (d->font_scale > 0 ? d->font_scale : 1);
    int cols = d->var.xres / cell, rows = ((int)d->var.yres - footer) / cell, x, y;
    size_t count;
    Cell *grid;
    char status[512];
    if (cols < 1 || rows < 1) {
        return -1;
    }
    count = (size_t)cols * rows;
    if (grid_dirty || !cache->valid || cache->view != view || cache->scale != scale || cache->cols != cols ||
        cache->rows != rows) {
        Cell *replacement = realloc(cache->cells, count * sizeof(*replacement)), *literal;
        uint8_t *bytes;
        uint16_t *sizes;
        if (!replacement) {
            return -1;
        }
        cache->cells = replacement;
        literal = realloc(cache->literal_cells, count * sizeof(*literal));
        if (!literal) {
            return -1;
        }
        cache->literal_cells = literal;
        bytes = realloc(cache->samples, count * SAMPLE_MAX);
        if (!bytes) {
            return -1;
        }
        cache->samples = bytes;
        bytes = realloc(cache->contexts, count * SAMPLE_MAX);
        if (!bytes) {
            return -1;
        }
        cache->contexts = bytes;
        bytes = realloc(cache->previous, count);
        if (!bytes) {
            return -1;
        }
        cache->previous = bytes;
        sizes = realloc(cache->sample_n, count * sizeof(*sizes));
        if (!sizes) {
            return -1;
        }
        cache->sample_n = sizes;
        sizes = realloc(cache->context_n, count * sizeof(*sizes));
        if (!sizes) {
            return -1;
        }
        cache->context_n = sizes;
        if (make_grid_data(s, view, scale, count, cache->cells, cache->samples, cache->contexts,
                           cache->previous, cache->sample_n, cache->context_n) < 0) {
            return -1;
        }
        memcpy(cache->literal_cells, cache->cells, count * sizeof(*cache->cells));
        cache->count = count;
        cache->view = view;
        cache->scale = scale;
        cache->cols = cols;
        cache->rows = rows;
        cache->valid = 1;
        cache->colored_lens = 0;
    }
    if (cache->colored_lens != v->lens || (v->lens == 6 && cache->colored_cursor != v->cursor)) {
        memcpy(cache->cells, cache->literal_cells, count * sizeof(*cache->cells));
        if (v->lens != 1) {
            recolor_grid(v, cache);
        }
        cache->colored_lens = v->lens;
        cache->colored_cursor = v->cursor;
    }
    grid = cache->cells;
    memset(d->back, 0, d->map_len);
    for (y = 0; y < rows; y++) {
        for (x = 0; x < cols; x++) {
            size_t i = (size_t)y * cols + x;
            uint64_t a = view + (uint64_t)i * scale, b = a + scale;
            rect(d, x * cell + 1, y * cell + 1, cell - 2, cell - 2, palette[grid[i].color]);
            if (v->selection_end > v->selection_start && a < v->selection_end && b > v->selection_start) {
                outline(d, x * cell, y * cell, cell, 0xef3e36);
            }
        }
    }
    if (cursor >= view && (cursor - view) / scale < count) {
        size_t i = (size_t)((cursor - view) / scale);
        x = (int)(i % cols) * cell;
        y = (int)(i / cols) * cell;
        outline(d, x, y, cell, 0xffffff);
    }
    footer_status(s, v, status, sizeof(status));
    rect(d, 0, rows * cell, d->var.xres, d->var.yres - rows * cell, 0x050505);
    text5(d, 2, rows * cell + 2 * (d->font_scale > 0 ? d->font_scale : 1), status, 0xe0e0e0);
    text5(d, 2, rows * cell + 11 * (d->font_scale > 0 ? d->font_scale : 1),
          v->message[0] ? v->message : "? help", 0xe0e0e0);
    if (v->inspect && render_inspector(d, s, v, cache) < 0) {
        return -1;
    }
    if (v->help) {
        render_help(d, v);
    }
    if (d->mouse >= 0) {
        rect(d, d->mouse_x - 4, d->mouse_y, 9, 1, 0xffffff);
        rect(d, d->mouse_x, d->mouse_y - 4, 1, 9, 0xffffff);
    }
    if (d->active) {
        memcpy(d->map, d->back, d->map_len);
    }
    return 0;
}

static void show_command(Display *d, int cell, const char *command, size_t n) {
    int size = d->font_scale > 0 ? d->font_scale : 1, rows = ((int)d->var.yres - 22 * size) / cell;
    char line[132];
    if (n > sizeof(line) - 2) {
        n = sizeof(line) - 2;
    }
    line[0] = ':';
    memcpy(line + 1, command, n);
    line[n + 1] = 0;
    rect(d, 0, rows * cell, d->var.xres, d->var.yres - rows * cell, 0x050505);
    text5(d, 2, rows * cell + 4 * size, line, 0xe0e0e0);
    if (d->active) {
        memcpy(d->map, d->back, d->map_len);
    }
}

static int handle_vt_requests(Display *d, int *present_dirty) {
    if (vt_release_requested) {
        vt_release_requested = 0;
        d->active = 0;
        if (ioctl(d->tty, VT_RELDISP, 1) < 0) {
            fprintf(stderr, "fatpix-c: cannot release Linux VT: %s\n", strerror(errno));
            return -1;
        }
    }
    if (vt_acquire_requested) {
        vt_acquire_requested = 0;
        if (ioctl(d->tty, VT_RELDISP, VT_ACKACQ) < 0) {
            fprintf(stderr, "fatpix-c: cannot acknowledge Linux VT acquire: %s\n", strerror(errno));
            return -1;
        }
        d->active = 1;
        *present_dirty = 1;
    }
    return 0;
}

static int read_key(int fd, char *out, size_t cap) {
    ssize_t n = read(fd, out, cap);
    if (n < 0 && errno == EINTR) {
        return 0;
    }
    return n > 0 ? (int)n : -1;
}
static void keep_cursor_visible(View *v, int cols, int rows) {
    uint64_t row, page, viewport_end, scroll_rows;

    if (!v->scale || cols < 1 || rows < 1) {
        return;
    }
    row = (uint64_t)cols > UINT64_MAX / v->scale ? UINT64_MAX : (uint64_t)cols * v->scale;
    page = (uint64_t)rows > UINT64_MAX / row ? UINT64_MAX : (uint64_t)rows * row;
    viewport_end = v->view > UINT64_MAX - page ? UINT64_MAX : v->view + page;
    if (v->cursor >= v->view && v->cursor < viewport_end) {
        return;
    }
    if (v->cursor < v->view) {
        scroll_rows = (v->view - v->cursor + row - 1) / row;
        v->view -= scroll_rows > v->view / row ? v->view : scroll_rows * row;
    } else {
        scroll_rows = (v->cursor - viewport_end) / row + 1;
        v->view = scroll_rows > (UINT64_MAX - v->view) / row ? UINT64_MAX : v->view + scroll_rows * row;
    }
}
static void center_view(View *v, uint64_t source_size, uint64_t cells) {
    uint64_t page = cells > UINT64_MAX / v->scale ? UINT64_MAX : cells * v->scale;
    uint64_t half = (cells / 2) > UINT64_MAX / v->scale ? UINT64_MAX : (cells / 2) * v->scale;
    uint64_t start = v->cursor > half ? v->cursor - half : 0,
             max_start = source_size > page ? source_size - page : 0;
    start = (start / v->scale) * v->scale;
    max_start = (max_start / v->scale) * v->scale;
    v->view = start > max_start ? max_start : start;
}
static uint64_t representative_start(uint64_t start, uint64_t span) {
    return span > 1024 ? start + (span - 1024) / 2 : start;
}
static void page_cursor(View *v, uint64_t source_size, int cols, int rows, int down) {
    uint64_t half_rows = (uint64_t)(rows / 2 > 0 ? rows / 2 : 1);
    uint64_t row_bytes = (uint64_t)cols * v->scale;
    uint64_t view_phase = v->view % row_bytes;
    uint64_t delta = half_rows > UINT64_MAX / row_bytes ? UINT64_MAX : half_rows * row_bytes;
    uint64_t old_column = ((v->cursor - v->view) / v->scale) % (uint64_t)cols;
    uint64_t page = (uint64_t)rows * row_bytes;
    uint64_t target_row = half_rows;
    uint64_t start, max_start;

    if (down) {
        v->cursor = v->cursor > UINT64_MAX - delta ? UINT64_MAX : v->cursor + delta;
    } else {
        v->cursor -= delta > v->cursor ? v->cursor : delta;
    }
    if (source_size && v->cursor >= source_size) {
        v->cursor = source_size - 1;
    }
    if (v->cursor >= v->view && v->cursor - v->view < page) {
        return;
    }
    start = v->cursor / v->scale > target_row * (uint64_t)cols + old_column
                ? v->cursor - (target_row * (uint64_t)cols + old_column) * v->scale
                : 0;
    max_start = source_size > page ? source_size - page : 0;
    max_start = max_start >= view_phase ? max_start - (max_start - view_phase) % row_bytes : 0;
    v->view = start > max_start ? max_start : start;
}
static void capture_baseline(const View *v, RenderCache *c) {
    if (v->inspect && c->inspect_valid) {
        memcpy(c->baseline_data, c->inspect_data, c->inspect_n);
        c->baseline_n = c->inspect_n;
        c->baseline_start = c->inspect_start;
        c->baseline_scale = v->scale;
    }
}
static int mouse_event(Display *d, View *v, const Source *s, RenderCache *cache, const uint8_t packet[3]) {
    uint64_t old_cursor = v->cursor;
    static int old_left;
    int size = d->font_scale > 0 ? d->font_scale : 1, left = packet[0] & 1, cols = d->var.xres / v->cell,
        rows = ((int)d->var.yres - 22 * size) / v->cell;
    int64_t dx = (int8_t)packet[1], dy = (int8_t)packet[2];
    size_t index;
    uint64_t a, b;
    double speed = d->mouse_speed > 0 ? d->mouse_speed : 1.0, scaled;
    scaled = (double)dx * speed + d->mouse_remainder_x;
    dx = (int64_t)scaled;
    d->mouse_remainder_x = scaled - (double)dx;
    scaled = (double)dy * speed + d->mouse_remainder_y;
    dy = (int64_t)scaled;
    d->mouse_remainder_y = scaled - (double)dy;
    d->mouse_x += (int)dx;
    d->mouse_y -= (int)dy;
    if (!left) {
        v->selecting = 0;
    }
    if (d->mouse_x < 0) {
        d->mouse_x = 0;
    }
    if (d->mouse_x >= (int)d->var.xres) {
        d->mouse_x = (int)d->var.xres - 1;
    }
    if (d->mouse_y < 0) {
        d->mouse_y = 0;
    }
    if (d->mouse_y >= (int)d->var.yres) {
        d->mouse_y = (int)d->var.yres - 1;
    }
    if (v->inspect) {
        if (v->inspector_positioned && d->mouse_x >= v->inspector_x - 2 &&
            d->mouse_x < v->inspector_x + v->inspector_w + 2 && d->mouse_y >= v->inspector_y - 2 &&
            d->mouse_y < v->inspector_y + v->inspector_h + 2) {
            old_left = left;
            return 0;
        }
    }
    if (d->mouse_x >= cols * v->cell || d->mouse_y >= rows * v->cell) {
        old_left = left;
        return 0;
    }
    index = (size_t)(d->mouse_y / v->cell) * cols + (size_t)(d->mouse_x / v->cell);
    if (index > UINT64_MAX / v->scale) {
        old_left = left;
        return 0;
    }
    a = v->view + (uint64_t)index * v->scale;
    if (a >= s->size) {
        old_left = left;
        return 0;
    }
    b = a + v->scale;
    if (b < a || b > s->size) {
        b = s->size;
    }
    if (left && v->inspect && a != old_cursor) {
        capture_baseline(v, cache);
    }
    if (left && !old_left) {
        v->selection_anchor = a;
        v->selection_start = a;
        v->selection_end = b;
        v->selection_dragged = 0;
        v->cursor = a;
        if (v->inspect) {
            v->inspect_focus = representative_start(a, b - a);
        }
        v->selecting = 1;
    } else if (left && v->selecting) {
        uint64_t anchor_end = v->selection_anchor + v->scale;
        if (anchor_end < v->selection_anchor || anchor_end > s->size) {
            anchor_end = s->size;
        }
        v->selection_start = a < v->selection_anchor ? a : v->selection_anchor;
        v->selection_end = b > anchor_end ? b : anchor_end;
        v->selection_dragged = a != v->selection_anchor;
        v->cursor = a;
    }
    old_left = left;
    if (v->cursor != old_cursor) {
        if (v->inspect) {
            v->inspect_focus = representative_start(a, b - a);
        }
        cache->inspect_valid = 0;
    }
    return v->cursor != old_cursor;
}

static const uint64_t small_scales[] = {1,  2,  3,  4,  6,   8,   10,  12,  16,  24,
                                        32, 48, 64, 96, 128, 192, 256, 384, 512, 768};
static uint64_t zoom_scale(uint64_t old, int inward, int steps) {
    uint64_t ladder[140];
    size_t n = 0, i, pos;
    uint64_t p;
    for (i = 0; i < sizeof(small_scales) / sizeof(*small_scales); i++) {
        ladder[n++] = small_scales[i];
    }
    for (p = 1024; p <= (1ULL << 50); p <<= 1) {
        ladder[n++] = p;
        if (p + p / 2 <= (1ULL << 50)) {
            ladder[n++] = p + p / 2;
        }
    }
    for (pos = 0; pos < n && ladder[pos] < old; pos++)
        ;
    if (inward) {
        while (steps-- && pos) {
            pos--;
        }
        return ladder[pos];
    }
    if (pos < n && ladder[pos] <= old) {
        pos++;
    }
    while (--steps > 0 && pos + 1 < n) {
        pos++;
    }
    return pos < n ? ladder[pos] : old;
}
static int dump_selection(const Source *s, const View *v, const char *name) {
    uint8_t buf[1024 * 1024];
    uint64_t at = v->selection_start, left = v->selection_end - v->selection_start;
    int fd;
    struct stat source_stat, dest_stat;
    if (!left) {
        errno = EINVAL;
        return -1;
    }
    if (fstat(s->fd, &source_stat) == 0 && stat(name, &dest_stat) == 0 &&
        source_stat.st_dev == dest_stat.st_dev && source_stat.st_ino == dest_stat.st_ino) {
        errno = EINVAL;
        return -1;
    }
    fd = open(name, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (fd < 0) {
        return -1;
    }
    while (left) {
        size_t want = left > sizeof(buf) ? sizeof(buf) : (size_t)left;
        ssize_t n = source_read(s, buf, want, at);
        if (n <= 0 || write(fd, buf, (size_t)n) != n) {
            close(fd);
            return -1;
        }
        at += (uint64_t)n;
        left -= (uint64_t)n;
    }
    return close(fd);
}
static int lens_number(const char *t) {
    int found = 0, i;
    if (t[0] >= '1' && t[0] <= '6' && !t[1]) {
        return t[0] - '0';
    }
    for (i = 1; i <= 6; i++) {
        if (!strncmp(lens_names[i], t, strlen(t))) {
            if (found) {
                return 0;
            }
            found = i;
        }
    }
    return found;
}
static int run_file_command(const Source *s, View *v, char *cmd) {
    char *arg, *op = cmd;
    uint64_t value;
    int lens;
    while (*op == ' ') {
        op++;
    }
    arg = strchr(op, ' ');
    if (arg) {
        *arg++ = 0;
        while (*arg == ' ') {
            arg++;
        }
    }
    {
        char *q;
        for (q = op; *q; q++) {
            *q = (char)tolower((unsigned char)*q);
        }
        if (!strcmp(op, "view") && arg) {
            for (q = arg; *q; q++) {
                *q = (char)tolower((unsigned char)*q);
            }
        }
    }
    if ((!strcmp(op, "g") || !strcmp(op, "goto")) && arg && parse_u64(arg, 0, &value) == 0 &&
        value < s->size) {
        v->cursor = value;
        v->inspect_focus = value;
        snprintf(v->message, sizeof(v->message), "goto 0x%llx", (unsigned long long)value);
        return 2;
    }
    if ((!strcmp(op, "s") || !strcmp(op, "scale")) && arg && parse_u64(arg, 1, &value) == 0 && value) {
        if (v->inspect && v->inspect_focus < s->size) {
            v->cursor = v->inspect_focus;
        }
        v->scale = value;
        snprintf(v->message, sizeof(v->message), "scale %lluB/cell", (unsigned long long)value);
        return 2;
    }
    if (!strcmp(op, "view") && arg && (lens = lens_number(arg))) {
        v->lens = lens;
        snprintf(v->message, sizeof(v->message), "view %d: %s", lens, lens_names[lens]);
        return 1;
    }
    if (!strcmp(op, "dump") && arg) {
        if (dump_selection(s, v, arg) < 0) {
            snprintf(v->message, sizeof(v->message), "command error: %s", strerror(errno));
        } else {
            snprintf(v->message, sizeof(v->message), "dumped selection");
        }
        return 0;
    }
    snprintf(v->message, sizeof(v->message), "command error: invalid command or argument");
    return 0;
}

static int mouse_gestures_allowed(const View *v, int command_mode) { return !v->help && !command_mode; }

static int interactive(Source *s, const char *fb, const char *mouse, int cell, uint64_t scale,
                       uint64_t cursor, double mouse_speed, int font_scale) {
    Display d;
    View v = {0};
    RenderCache cache = {0};
    char in[256], command[128];
    uint8_t mouse_buf[3];
    size_t mouse_n = 0, cmdn = 0;
    int command_mode = 0, present_dirty = 1, grid_dirty = 1, n, i;
    v.scale = scale;
    v.cursor = cursor;
    v.cell = cell;
    v.lens = 1;
    v.inspect_focus = UINT64_MAX;
    stopping = 0;
    vt_release_requested = vt_acquire_requested = 0;
    if (install_signal_handlers() < 0) {
        close_signal_wake_pipe();
        return -1;
    }
    if (display_open(&d, fb, mouse) < 0) {
        display_close(&d);
        close_signal_wake_pipe();
        return -1;
    }
    d.mouse_speed = mouse_speed;
    d.font_scale = font_scale;
    d.mouse_x = (int)d.var.xres / 2;
    d.mouse_y = (int)d.var.yres / 2;
    while (!stopping) {
        int cols = d.var.xres / cell, rows = ((int)d.var.yres - 22 * font_scale) / cell;
        struct pollfd fds[3] = {
            {d.tty, POLLIN, 0}, {d.mouse, POLLIN, 0}, {signal_wake_pipe[0], POLLIN, 0}};
        uint64_t old_view = v.view;
        if (handle_vt_requests(&d, &present_dirty) < 0) {
            break;
        }
        scale = v.scale;
        cursor = v.cursor;
        if (cursor >= s->size && s->size) {
            cursor = s->size - 1;
        }
        v.cursor = cursor;
        keep_cursor_visible(&v, cols, rows);
        if (v.view != old_view) {
            grid_dirty = 1;
        }
        if (d.active && (present_dirty || grid_dirty)) {
            if (render(&d, s, &v, &cache, grid_dirty) < 0) {
                break;
            }
            present_dirty = grid_dirty = 0;
        }
        if (poll(fds, 3, -1) < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (fds[2].revents & POLLIN) {
            drain_signal_wake_pipe();
            if (handle_vt_requests(&d, &present_dirty) < 0) {
                break;
            }
            if (stopping || !d.active) {
                mouse_n = 0;
                continue;
            }
        }
        if (d.mouse >= 0 && (fds[1].revents & POLLIN)) {
            uint8_t buf[48];
            ssize_t got = read(d.mouse, buf, sizeof(buf));
            ssize_t z;
            if (got > 0 && d.active) {
                for (z = 0; z < got; z++) {
                    if (!mouse_n && !(buf[z] & 8)) {
                        continue;
                    }
                    mouse_buf[mouse_n++] = buf[z];
                    if (mouse_n == 3) {
                        if (mouse_gestures_allowed(&v, command_mode)) {
                            mouse_event(&d, &v, s, &cache, mouse_buf);
                        }
                        mouse_n = 0;
                        present_dirty = 1;
                    }
                }
            }
            if (!d.active) {
                mouse_n = 0;
            }
        }
        if (!d.active) {
            continue;
        }
        if (!(fds[0].revents & POLLIN)) {
            continue;
        }
        n = read_key(d.tty, in, sizeof(in));
        if (n < 0) {
            break;
        }
        for (i = 0; i < n; i++) {
            unsigned char k = in[i];
            uint64_t move = 0, old_cursor = cursor;
            if (k == 3) {
                stopping = 1;
                break;
            }
            if (v.help) {
                if (k == 'q') {
                    stopping = 1;
                    break;
                }
                if (k == '?' || k == 27) {
                    v.help = 0;
                    present_dirty = 1;
                }
                continue;
            }
            if (k == '?') {
                v.help = 1;
                present_dirty = 1;
                continue;
            }
            if (command_mode) {
                if (k == 27) {
                    command_mode = 0;
                    cmdn = 0;
                    present_dirty = 1;
                } else if (k == '\r' || k == '\n') {
                    command[cmdn] = 0;
                    {
                        int is_goto = !strncmp(command, "g ", 2) || !strncmp(command, "goto ", 5), changed;
                        if (is_goto) {
                            capture_baseline(&v, &cache);
                        }
                        changed = run_file_command(s, &v, command);
                        cursor = v.cursor;
                        scale = v.scale;
                        if (changed == 2) {
                            center_view(&v, s->size, (uint64_t)cols * rows);
                            if (!is_goto) {
                                cache.baseline_n = 0;
                            }
                        }
                        if (changed == 2) {
                            grid_dirty = 1;
                        }
                    }
                    command_mode = 0;
                    cmdn = 0;
                    present_dirty = 1;
                } else if ((k == 127 || k == 8) && cmdn) {
                    cmdn--;
                } else if (k >= 32 && k < 127 && cmdn + 1 < sizeof(command)) {
                    command[cmdn++] = k;
                }
                if (command_mode) {
                    show_command(&d, cell, command, cmdn);
                }
                continue;
            }
            if (k == ':') {
                command_mode = 1;
                cmdn = 0;
                show_command(&d, cell, command, cmdn);
                continue;
            }
            if (k == 'g') {
                command_mode = 1;
                memcpy(command, "g ", 2);
                cmdn = 2;
                show_command(&d, cell, command, cmdn);
                continue;
            }
            if (k == 'q') {
                stopping = 1;
                break;
            }
            if (k == 'i') {
                uint64_t cell_start = v.view + ((v.cursor - v.view) / v.scale) * v.scale,
                         span = s->size - cell_start < v.scale ? s->size - cell_start : v.scale;
                v.inspect = !v.inspect;
                v.inspector_positioned = 0;
                v.inspect_focus = v.inspect ? representative_start(cell_start, span) : UINT64_MAX;
                cache.inspect_valid = 0;
                cache.baseline_n = 0;
                snprintf(v.message, sizeof(v.message), "inspector %s", v.inspect ? "open" : "closed");
                present_dirty = 1;
                continue;
            }
            if (v.inspect && (k == ',' || k == '<' || k == '.' || k == '>')) {
                v.inspect_page = (v.inspect_page + (k == ',' || k == '<' ? 6 : 1)) % 7;
                snprintf(v.message, sizeof(v.message), "inspect %s", page_names[v.inspect_page]);
                present_dirty = 1;
                continue;
            }
            if (k >= '1' && k <= '6') {
                v.lens = k - '0';
                present_dirty = 1;
                snprintf(v.message, sizeof(v.message), "view %d: %s", v.lens, lens_names[v.lens]);
                continue;
            }
            if (k == 'a' || k == 'h') {
                move = scale > cursor ? cursor : scale, cursor -= move;
            } else if (k == 'd' || k == 'l') {
                cursor += scale;
            } else if (k == 'w' || k == 'k') {
                move = (uint64_t)cols * scale, cursor -= move > cursor ? cursor : move;
            } else if (k == 's' || k == 'j') {
                cursor += (uint64_t)cols * scale;
            } else if (k == '-' || k == '=' || k == '_' || k == '+' || k == '\r' || k == '\n') {
                int inward = k == '=' || k == '+' || k == '\r' || k == '\n',
                    steps = k == '_' || k == '+' ? 4 : 1;
                uint64_t old = scale;
                if (v.inspect && v.inspect_focus < s->size) {
                    cursor = v.inspect_focus;
                }
                scale = zoom_scale(scale, inward, steps);
                v.scale = scale;
                v.cursor = cursor;
                center_view(&v, s->size, (uint64_t)cols * rows);
                cache.inspect_valid = 0;
                cache.baseline_n = 0;
                grid_dirty = 1;
                snprintf(v.message, sizeof(v.message),
                         scale == old ? "already at zoom limit" : "scale %lluB/cell",
                         (unsigned long long)scale);
            } else if (k == 0x1b && i + 2 < n && in[i + 1] == '[') {
                unsigned char z = in[i + 2];
                i += 2;
                if (z == 'A') {
                    cursor -= (uint64_t)cols * scale > cursor ? cursor : (uint64_t)cols * scale;
                } else if (z == 'B') {
                    cursor += (uint64_t)cols * scale;
                } else if (z == 'C') {
                    cursor += scale;
                } else if (z == 'D') {
                    cursor -= scale > cursor ? cursor : scale;
                } else if ((z == '5' || z == '6') && i + 1 < n && in[i + 1] == '~') {
                    i++;
                    v.cursor = cursor;
                    page_cursor(&v, s->size, cols, rows, z == '6');
                    cursor = v.cursor;
                    grid_dirty = 1;
                }
            } else if (k == 27) {
                if (v.inspect) {
                    v.inspect = 0;
                    v.inspect_focus = UINT64_MAX;
                    present_dirty = 1;
                    continue;
                }
                if (v.selection_end > v.selection_start) {
                    v.selection_start = v.selection_end = 0;
                    v.selection_dragged = 0;
                    snprintf(v.message, sizeof(v.message), "selection cleared");
                    present_dirty = 1;
                    continue;
                }
                continue;
            }
            v.cursor = cursor;
            v.scale = scale;
            if (v.inspect && cursor != old_cursor) {
                capture_baseline(&v, &cache);
            }
            if (v.inspect && v.inspect_focus < s->size && cursor != old_cursor) {
                int64_t delta =
                    cursor >= old_cursor ? (int64_t)(cursor - old_cursor) : -(int64_t)(old_cursor - cursor);
                if (delta < 0 && (uint64_t)(-delta) > v.inspect_focus) {
                    v.inspect_focus = 0;
                } else {
                    v.inspect_focus = (uint64_t)((int64_t)v.inspect_focus + delta);
                }
                if (v.inspect_focus >= s->size && s->size) {
                    v.inspect_focus = s->size - 1;
                }
                cache.inspect_valid = 0;
            }
            present_dirty = 1;
        }
    }
    free(cache.cells);
    free(cache.literal_cells);
    free(cache.samples);
    free(cache.contexts);
    free(cache.previous);
    free(cache.sample_n);
    free(cache.context_n);
    display_close(&d);
    close_signal_wake_pipe();
    return stopping ? 0 : -1;
}

static void usage(FILE *f) {
    fprintf(f, "usage: fatpix-c [--fb PATH] [--mouse PATH|--no-mouse] [--mouse-speed N] [--font-scale N] "
               "[--cell PX] [--scale N|10K|1.5M] [--offset N] FILE\n       fatpix-c --dump-grid WIDTHxHEIGHT "
               "[--scale N] [--offset N] FILE\n");
}
int main(int argc, char **argv) {
    const char *path = NULL, *fb = "/dev/fb0", *mouse = "/dev/input/mice", *dump = NULL;
    uint64_t scale = 1, off = 0;
    double mouse_speed = MOUSE_SPEED_DEFAULT;
    int font_scale = FONT_SCALE_DEFAULT, cell = CELL_DEFAULT, i;
    Source s;
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--fb") && ++i < argc) {
            fb = argv[i];
        } else if (!strcmp(argv[i], "--mouse") && ++i < argc) {
            mouse = argv[i];
        } else if (!strcmp(argv[i], "--no-mouse")) {
            mouse = NULL;
        } else if (!strcmp(argv[i], "--mouse-speed") && ++i < argc) {
            char *end;
            errno = 0;
            mouse_speed = strtod(argv[i], &end);
            if (errno || end == argv[i] || *end || !isfinite(mouse_speed) || mouse_speed <= 0) {
                fprintf(stderr, "fatpix-c: invalid mouse speed\n");
                return 2;
            }
        } else if (!strcmp(argv[i], "--font-scale") && ++i < argc) {
            char *end;
            long value;
            errno = 0;
            value = strtol(argv[i], &end, 10);
            if (errno || end == argv[i] || *end || value < 1 || value > 16) {
                fprintf(stderr, "fatpix-c: invalid font scale\n");
                return 2;
            }
            font_scale = (int)value;
        } else if (!strcmp(argv[i], "--cell") && ++i < argc) {
            cell = atoi(argv[i]);
        } else if (!strcmp(argv[i], "--scale") && ++i < argc) {
            if (parse_u64(argv[i], 1, &scale) || !scale) {
                fprintf(stderr, "fatpix-c: invalid scale\n");
                return 2;
            }
        } else if (!strcmp(argv[i], "--offset") && ++i < argc) {
            if (parse_u64(argv[i], 0, &off)) {
                fprintf(stderr, "fatpix-c: invalid offset\n");
                return 2;
            }
        } else if (!strcmp(argv[i], "--dump-grid") && ++i < argc) {
            dump = argv[i];
        } else if (!strcmp(argv[i], "--help")) {
            usage(stdout);
            return 0;
        } else if (argv[i][0] == '-') {
            usage(stderr);
            return 2;
        } else if (path) {
            usage(stderr);
            return 2;
        } else {
            path = argv[i];
        }
    }
    if (!path || cell < 4) {
        usage(stderr);
        return 2;
    }
    if (source_open(&s, path) < 0) {
        fprintf(stderr, "fatpix-c: %s: %s\n", path, strerror(errno));
        if (s.fd >= 0) {
            close(s.fd);
        }
        return 1;
    }
    if (dump) {
        unsigned w, h;
        char tail;
        size_t n, j;
        Cell *g;
        if (sscanf(dump, "%ux%u%c", &w, &h, &tail) != 2 || !w || !h || w > 10000 || h > 10000) {
            fprintf(stderr, "fatpix-c: invalid grid size\n");
            return 2;
        }
        n = (size_t)w * h;
        g = malloc(n * sizeof(*g));
        if (!g || make_grid(&s, off, scale, n, g) < 0) {
            fprintf(stderr, "fatpix-c: grid: %s\n", strerror(errno));
            return 1;
        }
        for (j = 0; j < n; j++) {
            printf("%u:%s%c", g[j].color, g[j].kind, (j + 1) % w ? ' ' : '\n');
        }
        free(g);
        close(s.fd);
        return 0;
    }
    i = interactive(&s, fb, mouse, cell, scale, off, mouse_speed, font_scale);
    if (i < 0) {
        fprintf(stderr, "fatpix-c: display failed: %s\n", strerror(errno));
    }
    close(s.fd);
    return i < 0 ? 1 : 0;
}
