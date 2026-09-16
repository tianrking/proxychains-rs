#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>

extern void proxychains_track_fcntl_dup(int oldfd, int newfd);

typedef int (*fcntl_fn)(int, int, ...);

static fcntl_fn resolved_fcntl;
static pthread_once_t fcntl_once = PTHREAD_ONCE_INIT;

static void resolve_fcntl(void) {
    resolved_fcntl = (fcntl_fn)dlsym(RTLD_NEXT, "fcntl");
}

static fcntl_fn real_fcntl(void) {
    pthread_once(&fcntl_once, resolve_fcntl);
    return resolved_fcntl;
}

static bool command_uses_pointer_argument(int command) {
    switch (command) {
#ifdef F_GETLK
        case F_GETLK:
        case F_SETLK:
        case F_SETLKW:
#endif
#ifdef F_O_GETLK
        case F_O_GETLK:
        case F_O_SETLK:
        case F_O_SETLKW:
#endif
            return true;
        default:
            return false;
    }
}

static bool command_has_no_argument(int command) {
    switch (command) {
        case F_GETFD:
        case F_GETFL:
#ifdef F_GETOWN
        case F_GETOWN:
#endif
#ifdef F_GETSIG
        case F_GETSIG:
#endif
#ifdef F_GETLEASE
        case F_GETLEASE:
#endif
#ifdef F_GETPIPE_SZ
        case F_GETPIPE_SZ:
#endif
#ifdef F_GET_SEALS
        case F_GET_SEALS:
#endif
            return true;
        default:
            return false;
    }
}

#ifdef __APPLE__
#define PROXYCHAINS_FCNTL proxychains_fcntl
#else
#define PROXYCHAINS_FCNTL fcntl
#endif

int PROXYCHAINS_FCNTL(int fd, int command, ...) {
    fcntl_fn function = real_fcntl();
    if (function == NULL) {
        return -1;
    }
    va_list args;
    va_start(args, command);
    int result;
    if (command_has_no_argument(command)) {
        result = function(fd, command);
    } else if (command_uses_pointer_argument(command)) {
        void *argument = va_arg(args, void *);
        result = function(fd, command, argument);
    } else {
        int argument = va_arg(args, int);
        result = function(fd, command, argument);
    }
    va_end(args);

    if (result >= 0 &&
        (command == F_DUPFD
#ifdef F_DUPFD_CLOEXEC
         || command == F_DUPFD_CLOEXEC
#endif
        )) {
        proxychains_track_fcntl_dup(fd, result);
    }
    return result;
}
