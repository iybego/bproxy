/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#if !defined(BPROXY_SYSCTL)
#define BPROXY_SYSCTL

#include "bproxy.h"
#include "inttypes.h"

typedef
enum {
        rsysctl_ok              = 0
    ,   rsysctl_failed
} rsysctl;

rsysctl
sysctl_path (
    OUT char*                   buffer, //OUTPUT like /proc/sys/net/ipv4/xxx/xxx
        size_t                  length,
        const char*             path    //like net.ipv4.xxx.xxx
);

rsysctl
sysctl_read_raw (
    OUT void*                   buffer,
        size_t                  length,
        const char*             path    //like net.ipv4.xxx.xxx
);

rsysctl
sysctl_read (
    OUT void*                   buffer, 
        const char*             format, //like "%"SCNu16
        const char*             path    //like net.ipv4.xxx.xxx
);

#define SYSCTL_WRAPPER(a_name, a_type)                                              \
    rsysctl a_name (                                                                \
        OUT INTTYPE_TYPE(a_type)*   value                                           \
    )

#define SYSCTL_WRAPPER_IMPLEMENT(a_name, a_type, a_path)                            \
    SYSCTL_WRAPPER(a_name, a_type) {                                                \
        static const char* const    path   = a_path;                                \
        static INTTYPE_TYPE(a_type) stored = 0;                                     \
                                                                                    \
        if ((0 != stored) && (NULL != value)) {                                     \
            (*(value)) = stored;                                                    \
            return rsysctl_ok;                                                      \
        }                                                                           \
                                                                                    \
        if (rsysctl_ok != sysctl_read(&stored, INTTYPE_FORMAT(a_type, scan), path)) \
            return rsysctl_failed;                                                  \
                                                                                    \
        if (NULL != value)                                                          \
            (*value) = stored;                                                      \
                                                                                    \
        return rsysctl_ok;                                                          \
    } BPROXY_REQUIRED_SEMICOLON(a_name)

#endif

