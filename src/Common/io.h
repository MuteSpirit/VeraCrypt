/*
 * Stub io.h for embedded builds (no Windows io.h)
 */

#ifndef TC_STUB_IO_H
#define TC_STUB_IO_H

#if defined(_WIN32)
#include <io.h>
#else

/* Stub declarations for embedded builds */
static inline int _open(const char* path, int oflag, ...) { return -1; }
static inline int _close(int fd) { return -1; }
static inline int _read(int fd, void* buf, unsigned int count) { return -1; }
static inline int _write(int fd, const void* buf, unsigned int count) { return -1; }
static inline long _lseek(int fd, long offset, int whence) { return -1; }
static inline int _isatty(int fd) { return 0; }
static inline int _unlink(const char* path) { return -1; }

#endif /* _WIN32 */
#endif /* TC_STUB_IO_H */
