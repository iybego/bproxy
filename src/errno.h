/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#if !defined(BPROXY_ERRNO)
#define BPROXY_ERRNO

#include <errno.h>
#include <string.h>

#define EINTR_IS(e) (EINTR == (e))

#if defined(EWOULDBLOCK)
    #define EWOULDBLOCK_IS(e)       (EWOULDBLOCK == (e))
#else
    #define EWOULDBLOCK_IS(e)       (0)
#endif

#if defined(EAGAIN)
    #define EAGAIN_IS(e)            (EAGAIN == (e))
#else
    #define EAGAIN_IS(e)            (0)
#endif

#define PRIerrno                    "cuz' %d [%s]"
#define DPRIerrno                   errno, strerror(errno)

#endif
