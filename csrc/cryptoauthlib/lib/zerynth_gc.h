
#ifndef ZERYNTH_GC_H_
#define ZERYNTH_GC_H_

#define printf(...) vbl_printf_stdout(__VA_ARGS__)

#define malloc(x) gc_malloc(x)
#define free(x)   gc_free(x)

#endif
