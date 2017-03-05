/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#if !defined(BPROXY_LOG)
#define BPROXY_LOG

#include "bproxy.h"

#define __LOG_STR(x)        #x

#define LOG_MODULE(x)       static const char* const MODULE = x

#define LOG_ASSERT(x)           \
    do { if (!!!((x))) log_write(elog_critical, MODULE, "ASSERT [%s] %d @ %s", __LOG_STR(x), __LINE__, __FILE__); } while(0)

#define LOG_LEVEL_MASK(level)   \
    ( 1 << (elog_##level) )

#define LOG(level, ...)         \
    log_write(elog_##level, MODULE, __VA_ARGS__)

#define LOG_BINARY(level, buffer, length, ...)  \
    log_binary(elog_##level, MODULE, buffer, length, __VA_ARGS__)

typedef
enum {
        elog_debug          = 0
    ,   elog_verbose        = 1
    ,   elog_information    = 2
    ,   elog_warning        = 3
    ,   elog_error          = 4
    ,   elog_critical       = 5
    ,   elog_LOG_DATE
} elog;

typedef
enum {
        rlog_ok
    ,   rlog_failed
} rlog;

uint32_t
log_suppress (
        uint32_t        mask
);

uint32_t
log_unsuppress (
        uint32_t        mask
);

int
log_write (
        elog            level,
        const char*     block,
        const char*     format,
        ...
);

int
log_binary (
        elog            level,
        const char*     block,
        const void*     buffer,
        size_t          length,
        const char*     format,
        ...
);

rlog
log_startup (
        uint32_t        mask
);

rlog
log_cleanup ();

rlog
log_reopen (
        const char*     filename
);

#endif
