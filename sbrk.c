#include <sys/mman.h>

#include "sbrk.h"

static void *arena = NULL;
static void *_brk = NULL;
static const size_t arena_size = 4 * 1024 * 1024;

void *_sbrk(size_t size) {
    if (!arena) {
        arena = mmap(NULL, arena_size,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        _brk = arena;
    }
    if (size == 0)
        return _brk;
    if (_brk + size >= arena + arena_size)
        return (void *)-1;
    _brk += size;
    return (_brk - size);
}