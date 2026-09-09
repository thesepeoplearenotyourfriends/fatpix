#define _FILE_OFFSET_BITS 64
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

/* A small Linux fbdev FatPix.  The dump-grid path deliberately uses the same
 * source, sampling, and literal classification code as the interactive view. */
#include <errno.h>
#include <fcntl.h>
#include <linux/fb.h>
#include <linux/fs.h>
#include <linux/kd.h>
#include <math.h>
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

#define SAMPLE_MAX 1024
#define BATCH_MAX (8u * 1024u * 1024u)
#define CELL_DEFAULT 14

typedef struct { int fd; uint64_t size; const char *path; } Source;
typedef struct { uint8_t color; const char *kind; } Cell;
typedef struct {
    int fd, tty, kd_mode, raw, mapped;
    struct termios saved_termios;
    struct fb_var_screeninfo var;
    struct fb_fix_screeninfo fix;
    uint8_t *map, *back;
    size_t map_len;
} Display;

static volatile sig_atomic_t stopping;
static void stop_now(int sig) { (void)sig; stopping = 1; }

static int install_signal_handlers(void) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = stop_now;
    sigemptyset(&action.sa_mask);
    /* Deliberately omit SA_RESTART: an idle blocking read must wake so the VT
     * and termios state are restored without waiting for another keypress. */
    if (sigaction(SIGINT, &action, NULL) < 0 ||
        sigaction(SIGTERM, &action, NULL) < 0 ||
        sigaction(SIGHUP, &action, NULL) < 0) return -1;
    return 0;
}

static const uint32_t palette[9] = {
    0x050505, 0xf1f1e8, 0xef3e36, 0x2677c9, 0xe67e2f,
    0xf2d34f, 0x74b83f, 0x9b45b2, 0x444444
};

static const uint8_t font5x7[96][7] = {
  [0] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00},
  [1] = {0x04,0x04,0x04,0x04,0x04,0x00,0x04},
  [2] = {0x0a,0x0a,0x0a,0x00,0x00,0x00,0x00},
  [3] = {0x0a,0x1f,0x0a,0x0a,0x1f,0x0a,0x00},
  [4] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [5] = {0x19,0x1a,0x04,0x08,0x16,0x06,0x00},
  [6] = {0x0c,0x12,0x14,0x08,0x15,0x12,0x0d},
  [7] = {0x04,0x04,0x08,0x00,0x00,0x00,0x00},
  [8] = {0x02,0x04,0x08,0x08,0x08,0x04,0x02},
  [9] = {0x08,0x04,0x02,0x02,0x02,0x04,0x08},
  [10] = {0x00,0x15,0x0e,0x1f,0x0e,0x15,0x00},
  [11] = {0x00,0x04,0x04,0x1f,0x04,0x04,0x00},
  [12] = {0x00,0x00,0x00,0x00,0x04,0x04,0x08},
  [13] = {0x00,0x00,0x00,0x1f,0x00,0x00,0x00},
  [14] = {0x00,0x00,0x00,0x00,0x00,0x04,0x04},
  [15] = {0x01,0x02,0x04,0x08,0x10,0x00,0x00},
  [16] = {0x0e,0x11,0x13,0x15,0x19,0x11,0x0e},
  [17] = {0x04,0x0c,0x04,0x04,0x04,0x04,0x0e},
  [18] = {0x0e,0x11,0x01,0x02,0x04,0x08,0x1f},
  [19] = {0x1e,0x01,0x01,0x0e,0x01,0x01,0x1e},
  [20] = {0x02,0x06,0x0a,0x12,0x1f,0x02,0x02},
  [21] = {0x1f,0x10,0x10,0x1e,0x01,0x01,0x1e},
  [22] = {0x0e,0x10,0x10,0x1e,0x11,0x11,0x0e},
  [23] = {0x1f,0x01,0x02,0x04,0x08,0x08,0x08},
  [24] = {0x0e,0x11,0x11,0x0e,0x11,0x11,0x0e},
  [25] = {0x0e,0x11,0x11,0x0f,0x01,0x01,0x0e},
  [26] = {0x00,0x04,0x04,0x00,0x04,0x04,0x00},
  [27] = {0x00,0x04,0x04,0x00,0x04,0x04,0x08},
  [28] = {0x02,0x04,0x08,0x10,0x08,0x04,0x02},
  [29] = {0x00,0x00,0x1f,0x00,0x1f,0x00,0x00},
  [30] = {0x08,0x04,0x02,0x01,0x02,0x04,0x08},
  [31] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [32] = {0x0e,0x11,0x17,0x15,0x17,0x10,0x0e},
  [33] = {0x0e,0x11,0x11,0x1f,0x11,0x11,0x11},
  [34] = {0x1e,0x11,0x11,0x1e,0x11,0x11,0x1e},
  [35] = {0x0f,0x10,0x10,0x10,0x10,0x10,0x0f},
  [36] = {0x1e,0x11,0x11,0x11,0x11,0x11,0x1e},
  [37] = {0x1f,0x10,0x10,0x1e,0x10,0x10,0x1f},
  [38] = {0x1f,0x10,0x10,0x1e,0x10,0x10,0x10},
  [39] = {0x0f,0x10,0x10,0x17,0x11,0x11,0x0f},
  [40] = {0x11,0x11,0x11,0x1f,0x11,0x11,0x11},
  [41] = {0x1f,0x04,0x04,0x04,0x04,0x04,0x1f},
  [42] = {0x07,0x02,0x02,0x02,0x02,0x12,0x0c},
  [43] = {0x11,0x12,0x14,0x18,0x14,0x12,0x11},
  [44] = {0x10,0x10,0x10,0x10,0x10,0x10,0x1f},
  [45] = {0x11,0x1b,0x15,0x15,0x11,0x11,0x11},
  [46] = {0x11,0x19,0x15,0x13,0x11,0x11,0x11},
  [47] = {0x0e,0x11,0x11,0x11,0x11,0x11,0x0e},
  [48] = {0x1e,0x11,0x11,0x1e,0x10,0x10,0x10},
  [49] = {0x0e,0x11,0x11,0x11,0x15,0x12,0x0d},
  [50] = {0x1e,0x11,0x11,0x1e,0x14,0x12,0x11},
  [51] = {0x0f,0x10,0x10,0x0e,0x01,0x01,0x1e},
  [52] = {0x1f,0x04,0x04,0x04,0x04,0x04,0x04},
  [53] = {0x11,0x11,0x11,0x11,0x11,0x11,0x0e},
  [54] = {0x11,0x11,0x11,0x11,0x11,0x0a,0x04},
  [55] = {0x11,0x11,0x11,0x15,0x15,0x15,0x0a},
  [56] = {0x11,0x11,0x0a,0x04,0x0a,0x11,0x11},
  [57] = {0x11,0x11,0x0a,0x04,0x04,0x04,0x04},
  [58] = {0x1f,0x01,0x02,0x04,0x08,0x10,0x1f},
  [59] = {0x0e,0x08,0x08,0x08,0x08,0x08,0x0e},
  [60] = {0x10,0x08,0x04,0x02,0x01,0x00,0x00},
  [61] = {0x0e,0x02,0x02,0x02,0x02,0x02,0x0e},
  [62] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [63] = {0x00,0x00,0x00,0x00,0x00,0x00,0x1f},
  [64] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [65] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [66] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [67] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [68] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [69] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [70] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [71] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [72] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [73] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [74] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [75] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [76] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [77] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [78] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [79] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [80] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [81] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [82] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [83] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [84] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [85] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [86] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [87] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [88] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [89] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [90] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [91] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [92] = {0x04,0x04,0x04,0x04,0x04,0x04,0x04},
  [93] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [94] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
  [95] = {0x0e,0x11,0x01,0x02,0x04,0x00,0x04},
};

static int source_open(Source *s, const char *path) {
    struct stat st;
    uint64_t bytes = 0;
    memset(s, 0, sizeof(*s)); s->fd = -1; s->path = path;
    s->fd = open(path, O_RDONLY | O_CLOEXEC);
    if (s->fd < 0) return -1;
    if (fstat(s->fd, &st) < 0) return -1;
    if (S_ISREG(st.st_mode)) bytes = (uint64_t)st.st_size;
    else if (S_ISBLK(st.st_mode)) {
        if (ioctl(s->fd, BLKGETSIZE64, &bytes) < 0) return -1;
    } else { errno = ENOTSUP; return -1; }
    s->size = bytes;
    return 0;
}

static ssize_t source_read(const Source *s, void *buf, size_t count, uint64_t off) {
    size_t done = 0;
    if (off >= s->size) return 0;
    if ((uint64_t)count > s->size - off) count = (size_t)(s->size - off);
    while (done < count) {
        ssize_t n = pread(s->fd, (uint8_t *)buf + done, count - done, (off_t)(off + done));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return done ? (ssize_t)done : n;
        done += (size_t)n;
    }
    return (ssize_t)done;
}

static Cell byte_cell(uint8_t b) {
    static const uint8_t ring[] = {3,4,5,2,7,8};
    if (!b) return (Cell){0,"00"};
    if (b == 255) return (Cell){1,"ff"};
    if (b >= 32 && b <= 126) return (Cell){6,"text"};
    return (Cell){ring[((unsigned)b * 6u) / 256u],"byte"};
}

static Cell summary_cell(const uint8_t *p, size_t n) {
    unsigned hist[256] = {0}; size_t zero = 0, ff = 0, printable = 0, unique = 0, i;
    double entropy = 0.0;
    if (!n) return (Cell){8,"unreadable"};
    for (i=0; i<n; i++) { hist[p[i]]++; zero += p[i]==0; ff += p[i]==255;
        printable += p[i]==9 || p[i]==10 || p[i]==13 || (p[i]>=32 && p[i]<=126); }
    for (i=0; i<256; i++) if (hist[i]) { double q=(double)hist[i]/(double)n; unique++; entropy -= q*log2(q); }
    if (zero == n) return (Cell){0,"zero"};
    if (ff == n) return (Cell){1,"ff"};
    if ((double)printable/n >= .85) return (Cell){6,"text"};
    if ((double)zero/n >= .75) return (Cell){8,"sparse"};
    if (unique <= 4 || entropy < 2.0) return (Cell){3,"repeat"};
    if (entropy < 4.0) return (Cell){4,"low-H"};
    if (entropy < 5.5) return (Cell){5,"mid-H"};
    if (entropy < 7.0) return (Cell){7,"dense"};
    return (Cell){2,"high-H"};
}

/* Fine viewports get one contiguous pread. Coarse viewports get at most one
 * centered 1 KiB representative read per cell. */
static int make_grid(const Source *s, uint64_t start, uint64_t scale,
                     size_t count, Cell *cells) {
    uint8_t *batch = NULL, sample[SAMPLE_MAX]; size_t batch_n = 0, i;
    uint64_t total;
    if (!scale || count > UINT64_MAX/scale) { errno=EOVERFLOW; return -1; }
    total = scale * count;
    if (total <= BATCH_MAX && start < s->size) {
        uint64_t avail=s->size-start; batch_n=(size_t)(avail<total?avail:total);
        batch=malloc(batch_n ? batch_n : 1);
        if (!batch || source_read(s,batch,batch_n,start)!=(ssize_t)batch_n) { free(batch); return -1; }
    }
    for (i=0;i<count;i++) {
        uint64_t off, span; size_t n;
        if (i > (UINT64_MAX-start)/scale) off=UINT64_MAX; else off=start+i*scale;
        if (off >= s->size) { cells[i]=(Cell){8,"eof"}; continue; }
        span=s->size-off; if(span>scale) span=scale;
        n=(size_t)(span>SAMPLE_MAX?SAMPLE_MAX:span);
        if (batch) memcpy(sample,batch+(size_t)(off-start)+(size_t)(span-n)/2,n);
        else {
            uint64_t at=off+(span-n)/2;
            ssize_t got=source_read(s,sample,n,at);
            if(got<0) { free(batch); return -1; } n=(size_t)got;
        }
        cells[i] = span==1 && n ? byte_cell(sample[0]) : summary_cell(sample,n);
    }
    free(batch); return 0;
}

static int parse_u64(const char *text, int fractional, uint64_t *out) {
    char *end; double d; uint64_t mult=1;
    if (!fractional) {
        unsigned long long integer;
        errno=0; integer=strtoull(text,&end,0);
        if(errno||end==text)return -1;
        if(*end){switch(*end|32){case 'k':mult=1024;break;case 'm':mult=1024ULL*1024;break;
            case 'g':mult=1024ULL*1024*1024;break;case 't':mult=1024ULL*1024*1024*1024;break;default:return -1;}end++;}
        if(*end||integer>UINT64_MAX/mult)return -1;
        *out=(uint64_t)integer*mult;return 0;
    }
    errno=0; d=strtod(text,&end);
    if (errno || end==text || d<0) return -1;
    if (*end) {
        switch(*end|32) { case 'k':mult=1024;break; case 'm':mult=1024ULL*1024;break;
          case 'g':mult=1024ULL*1024*1024;break; case 't':mult=1024ULL*1024*1024*1024;break; default:return -1; }
        end++; if ((*end=='b'||*end=='B') && !end[1]) end++;
    }
    if (*end || (!fractional && d != floor(d)) || !isfinite(d) || d*mult>UINT64_MAX || d*mult != floor(d*mult)) return -1;
    *out=(uint64_t)(d*mult); return 0;
}

static uint32_t pack_pixel(const Display *d, uint32_t rgb) {
    uint32_t r=(rgb>>16)&255,g=(rgb>>8)&255,b=rgb&255;
    r=((r*((1u<<d->var.red.length)-1)+127)/255)<<d->var.red.offset;
    g=((g*((1u<<d->var.green.length)-1)+127)/255)<<d->var.green.offset;
    b=((b*((1u<<d->var.blue.length)-1)+127)/255)<<d->var.blue.offset;
    return r|g|b;
}
static void rect(Display *d,int x,int y,int w,int h,uint32_t rgb) {
    int yy,xx,bytes=d->var.bits_per_pixel/8; uint32_t px=pack_pixel(d,rgb);
    if(x<0){w+=x;x=0;} if(y<0){h+=y;y=0;} if(x+w>(int)d->var.xres)w=d->var.xres-x; if(y+h>(int)d->var.yres)h=d->var.yres-y;
    for(yy=y;yy<y+h;yy++) for(xx=x;xx<x+w;xx++) memcpy(d->back+(size_t)yy*d->fix.line_length+(size_t)xx*bytes,&px,(size_t)bytes);
}
static void text5(Display *d,int x,int y,const char *s,uint32_t rgb) {
    for(;*s;s++,x+=6) { unsigned c=(unsigned char)*s; int yy,xx; const uint8_t *glyph;
        if(c>='a'&&c<='z')c-=32;
        if(c<32||c>127)c='?';
        glyph=font5x7[c-32];
        for(yy=0;yy<7;yy++)for(xx=0;xx<5;xx++)if(glyph[yy]&(1u<<(4-xx)))rect(d,x+xx,y+yy,1,1,rgb);
    }
}

static void display_close(Display *d) {
    if(d->tty>=0) { if(d->raw)tcsetattr(d->tty,TCSAFLUSH,&d->saved_termios); if(d->kd_mode>=0)ioctl(d->tty,KDSETMODE,d->kd_mode); }
    if(d->mapped)munmap(d->map,d->map_len);
    free(d->back);
    if(d->fd>=0)close(d->fd);
    if(d->tty>=0)close(d->tty);
}
static int display_open(Display *d,const char *fb) {
    struct termios raw; memset(d,0,sizeof(*d)); d->fd=d->tty=d->kd_mode=-1;
    d->tty=open("/dev/tty",O_RDWR|O_CLOEXEC); if(d->tty<0){fprintf(stderr,"fatpix-c: cannot open controlling VT: %s\n",strerror(errno));return -1;}
    if(ioctl(d->tty,KDGETMODE,&d->kd_mode)<0){fprintf(stderr,"fatpix-c: controlling terminal is not a Linux VT: %s\n",strerror(errno));return -1;}
    if(tcgetattr(d->tty,&d->saved_termios)<0)return -1;
    raw=d->saved_termios; cfmakeraw(&raw);
    if(tcsetattr(d->tty,TCSAFLUSH,&raw)<0)return -1;
    d->raw=1;
    d->fd=open(fb,O_RDWR|O_CLOEXEC); if(d->fd<0){fprintf(stderr,"fatpix-c: cannot open %s: %s\n",fb,strerror(errno));return -1;}
    if(ioctl(d->fd,FBIOGET_FSCREENINFO,&d->fix)<0||ioctl(d->fd,FBIOGET_VSCREENINFO,&d->var)<0)return -1;
    if(d->var.bits_per_pixel!=32){fprintf(stderr,"fatpix-c: framebuffer must be 32 bpp (got %u)\n",d->var.bits_per_pixel);errno=ENOTSUP;return -1;}
    d->map_len=d->fix.smem_len; d->map=mmap(NULL,d->map_len,PROT_READ|PROT_WRITE,MAP_SHARED,d->fd,0); if(d->map==MAP_FAILED){d->map=NULL;return -1;} d->mapped=1;
    d->back=calloc(1,d->map_len); if(!d->back)return -1;
    if(ioctl(d->tty,KDSETMODE,KD_GRAPHICS)<0)return -1;
    return 0;
}

static const char *base_name(const char *p){const char *q=strrchr(p,'/');return q?q+1:p;}
static void human_scale(uint64_t n,char *buf,size_t cap) {
    const char *u[] = {"B","KiB","MiB","GiB","TiB"}; double v=n; int i=0;
    while(v>=1024&&i<4){v/=1024;i++;} if(!i)snprintf(buf,cap,"%lluB",(unsigned long long)n);else snprintf(buf,cap,"%.1f%s",v,u[i]);
}
static int render(Display *d,const Source *s,uint64_t view,uint64_t scale,uint64_t cursor,int cell) {
    int cols=d->var.xres/cell, rows=((int)d->var.yres-22)/cell,x,y; size_t count; Cell *grid; char status[512],sc[40];
    if(cols<1||rows<1)return -1;
    count=(size_t)cols*rows; grid=malloc(count*sizeof(*grid)); if(!grid)return -1;
    if(make_grid(s,view,scale,count,grid)<0){free(grid);return -1;} memset(d->back,0,d->map_len);
    for(y=0;y<rows;y++)for(x=0;x<cols;x++){size_t i=(size_t)y*cols+x;rect(d,x*cell+1,y*cell+1,cell-2,cell-2,palette[grid[i].color]);}
    if(cursor>=view && (cursor-view)/scale<count) { size_t i=(size_t)((cursor-view)/scale); x=(int)(i%cols)*cell;y=(int)(i/cols)*cell;rect(d,x,y,cell,1,0xffffff);rect(d,x,y+cell-1,cell,1,0xffffff);rect(d,x,y,1,cell,0xffffff);rect(d,x+cell-1,y,1,cell,0xffffff); }
    human_scale(scale,sc,sizeof(sc)); snprintf(status,sizeof(status),"file=%s  scale=%s  pos=0x%llx  view=literal  clarity=off",base_name(s->path),sc,(unsigned long long)cursor);
    rect(d,0,rows*cell,d->var.xres,d->var.yres-rows*cell,0x050505);text5(d,2,rows*cell+4,status,0xe0e0e0);memcpy(d->map,d->back,d->map_len);free(grid);return 0;
}

static void show_command(Display *d, int cell, const char *command, size_t n) {
    int rows=((int)d->var.yres-22)/cell; char line[132];
    if(n>sizeof(line)-2)n=sizeof(line)-2;
    line[0]=':'; memcpy(line+1,command,n); line[n+1]=0;
    rect(d,0,rows*cell,d->var.xres,d->var.yres-rows*cell,0x050505);
    text5(d,2,rows*cell+4,line,0xe0e0e0);
    memcpy(d->map,d->back,d->map_len);
}

static int read_key(int fd,char *out,size_t cap) {
    ssize_t n=read(fd,out,cap); if(n<0&&errno==EINTR)return 0; return n>0?(int)n:-1;
}
static int interactive(Source *s,const char *fb,int cell,uint64_t scale,uint64_t cursor) {
    Display d; char in[256],command[128]; size_t cmdn=0; int command_mode=0,dirty=1,n,i; uint64_t view=0;
    stopping=0;
    if(install_signal_handlers()<0)return -1;
    if(display_open(&d,fb)<0){display_close(&d);return -1;}
    while(!stopping){int cols=d.var.xres/cell,rows=((int)d.var.yres-22)/cell;uint64_t page=(uint64_t)cols*rows*scale;
        if(cursor>=s->size&&s->size)cursor=s->size-1;
        if(cursor<view)view=(cursor/scale)*scale;else if(cursor>=view+page)view=((cursor/scale)-(uint64_t)cols*rows+1)*scale;
        if(dirty){if(render(&d,s,view,scale,cursor,cell)<0)break;dirty=0;}
        n=read_key(d.tty,in,sizeof(in));if(n<0)break;
        for(i=0;i<n;i++){unsigned char k=in[i];uint64_t move=0;
            if(k==3){stopping=1;break;}
            if(command_mode){if(k==27){command_mode=0;cmdn=0;dirty=1;}else if(k=='\r'||k=='\n'){uint64_t v;command[cmdn]=0;
                    if((!strncmp(command,"g ",2)||!strncmp(command,"goto ",5))&&parse_u64(command+(command[1]==' '?2:5),0,&v)==0)cursor=v;
                    else if((!strncmp(command,"s ",2)||!strncmp(command,"scale ",6))&&parse_u64(command+(command[1]==' '?2:6),1,&v)==0&&v)scale=v;
                    command_mode=0;cmdn=0;dirty=1;
                }else if((k==127||k==8)&&cmdn)cmdn--;else if(k>=32&&k<127&&cmdn+1<sizeof(command))command[cmdn++]=k;
                if(command_mode)show_command(&d,cell,command,cmdn);
                continue;}
            if(k==':' ){command_mode=1;cmdn=0;show_command(&d,cell,command,cmdn);continue;}
            if(k=='g'){command_mode=1;memcpy(command,"g ",2);cmdn=2;show_command(&d,cell,command,cmdn);continue;}
            if(k=='q'){stopping=1;break;}
            if(k=='a')move=scale>cursor?cursor:scale,cursor-=move;else if(k=='d')cursor+=scale;else if(k=='w')move=(uint64_t)cols*scale,cursor-=move>cursor?cursor:move;else if(k=='s')cursor+=(uint64_t)cols*scale;
            else if(k=='-'||k=='='){ /* Consume adjacent repeats before rendering: final scale is the request. */
                do { if(k=='-'&&scale<=UINT64_MAX/2)scale*=2;else if(k=='='&&scale>1)scale=(scale+1)/2; if(i+1<n&&(in[i+1]=='-'||in[i+1]=='='))k=in[++i];else break; }while(1);
            } else if(k==0x1b&&i+2<n&&in[i+1]=='['){unsigned char z=in[i+2];i+=2;if(z=='A')cursor-=(uint64_t)cols*scale>cursor?cursor:(uint64_t)cols*scale;else if(z=='B')cursor+=(uint64_t)cols*scale;else if(z=='C')cursor+=scale;else if(z=='D')cursor-=scale>cursor?cursor:scale;else if((z=='5'||z=='6')&&i+1<n&&in[i+1]=='~'){uint64_t half=page/2;i++;if(z=='5')cursor-=half>cursor?cursor:half;else cursor+=half;}}
            else if(k==27){stopping=1;break;}
            dirty=1;
        }
    }
    display_close(&d);return stopping?0:-1;
}

static void usage(FILE *f){fprintf(f,"usage: fatpix-c [--fb PATH] [--cell PX] [--scale N|10K|1.5M] [--offset N] FILE\n       fatpix-c --dump-grid WIDTHxHEIGHT [--scale N] [--offset N] FILE\n");}
int main(int argc,char **argv){const char *path=NULL,*fb="/dev/fb0",*dump=NULL;uint64_t scale=1,off=0;int cell=CELL_DEFAULT,i;Source s;
    for(i=1;i<argc;i++){if(!strcmp(argv[i],"--fb")&&++i<argc)fb=argv[i];else if(!strcmp(argv[i],"--cell")&&++i<argc)cell=atoi(argv[i]);else if(!strcmp(argv[i],"--scale")&&++i<argc){if(parse_u64(argv[i],1,&scale)||!scale){fprintf(stderr,"fatpix-c: invalid scale\n");return 2;}}else if(!strcmp(argv[i],"--offset")&&++i<argc){if(parse_u64(argv[i],0,&off)){fprintf(stderr,"fatpix-c: invalid offset\n");return 2;}}else if(!strcmp(argv[i],"--dump-grid")&&++i<argc)dump=argv[i];else if(!strcmp(argv[i],"--help")){usage(stdout);return 0;}else if(argv[i][0]=='-'){usage(stderr);return 2;}else if(path){usage(stderr);return 2;}else path=argv[i];}
    if(!path||cell<4){usage(stderr);return 2;}if(source_open(&s,path)<0){fprintf(stderr,"fatpix-c: %s: %s\n",path,strerror(errno));if(s.fd>=0)close(s.fd);return 1;}
    if(dump){unsigned w,h;char tail;size_t n,j;Cell *g;if(sscanf(dump,"%ux%u%c",&w,&h,&tail)!=2||!w||!h||w>10000||h>10000){fprintf(stderr,"fatpix-c: invalid grid size\n");return 2;}n=(size_t)w*h;g=malloc(n*sizeof(*g));if(!g||make_grid(&s,off,scale,n,g)<0){fprintf(stderr,"fatpix-c: grid: %s\n",strerror(errno));return 1;}for(j=0;j<n;j++){printf("%u:%s%c",g[j].color,g[j].kind,(j+1)%w?' ':'\n');}free(g);close(s.fd);return 0;}
    i=interactive(&s,fb,cell,scale,off);if(i<0)fprintf(stderr,"fatpix-c: display failed: %s\n",strerror(errno));close(s.fd);return i<0?1:0;
}
