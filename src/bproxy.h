/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#if !defined(BPROXY_BPROXY)
#define BPROXY_BPROXY

#include <linux/netlink.h>
#include <netinet/in.h>

#define VERSION                         "0.16.11.13"

/** CHANGELOG:
        0.16.11.13 - Bug Fix

            [+] "sink original" option
            [+] "no ip-tos" option
            [+] "no ip-ttl" option
            [+] "no ip-options" option

        0.16.11.09 - Added ip options passthrou
                   - Added security marks support

            [+] "security" option
            [+] "no passthrou-ip-options" option

        0.16.11.06 - ToS values now have human readable values
                   - fragmentation support
                   - now source descrement ttl and drop packet
                     ... if it zero

            [f] "ttl" option
            [f] "tos" option
            [+] "mtu" option
            [+] "no fragment" option
            [+] "no passthrou-ip-id" option

        0.16.10.24 - now sink is raw socket

        0.16.10.16 - added multicast subscription support
                   - added source address rewrite support
                   - dirty poll handler tick limit
                   - now using /etc/services for port specification

            [+] "m-group" option
            [+] "from" option

        0.16.10.11 - added raw source's socket option:
            [+] "source raw" option
            [+] "port-range" option

        0.16.10.10 - little code cleanup
            [+] "rate-limit" option
            [+] "join" option

        ... loosed ...

        0.16.10.01 - initial version
**/

//DEFAULTS
#define DEFAULT_BUFFER_SIZE             (64*1024)
#define LOG_BUFFER_SIZE                 (256)

#define RTLINK_MAX_EVENTS_PER_TICK      (512)
#define SOURCE_MAX_PACKETS_PER_TICK     (64)

#define LOGGING_DEFAULT_SUPPRESS        (LOG_LEVEL_MASK(debug) | LOG_LEVEL_MASK(verbose))
#define LOGGING_SILENT_SUPPRESS         (LOGGING_DEFAULT_SUPPRESS | LOG_LEVEL_MASK(information))

#define LOGGING_VERBOSE                 (LOG_LEVEL_MASK(verbose) | LOG_LEVEL_MASK(information))
#define LOGGING_DEBUG                   (LOGGING_VERBOSE | LOG_LEVEL_MASK(debug))

#define FSOCKET_DEFAULT_SOURCE          (       FSOCKET_REUSEADDR | FSOCKET_TRANSPARENT | FSOCKET_BROADCAST \
                                            |   FSOCKET_PKTINFO | FSOCKET_RECVORIGDSTADDR                   \
                                            |   FSOCKET_RECVTTL | FSOCKET_RECVTOS | FSOCKET_RECVOPTIONS     \
                                        )

#define FSOCKET_DEFAULT_SOURCE_RAW      (FSOCKET_RECVTTL | FSOCKET_RECVTOS | FSOCKET_RECVOPTIONS)

//source doesn't need IP_HDRINCL, cuz' as man raw(7) say:
// > The IPv4 layer generates an IP header when sending a packet unless
// > the IP_HDRINCL socket option is enabled on the socket.  When it is
// > enabled, the packet must contain an IP header.  For receiving, the IP
// > header is always included in the packet.

#define FSOCKET_DEFAULT_SINK_RAW        (FSOCKET_HDRINCL | FSOCKET_BROADCAST)
//END OF DEFAULTS

//#define _CMSG_NEED_SPACE(_type)         (sizeof(struct cmsghdr) +  CMSG_ALIGN(sizeof(_type)))
#define _CMSG_NEED_SPACE(_type)         (CMSG_SPACE(sizeof(_type)))

#define SOURCE_SIMPLE_CONTROL_LENGTH                \
    (       _CMSG_NEED_SPACE(struct in_pktinfo)     \
        +   _CMSG_NEED_SPACE(struct sockaddr_in)    \
        +   _CMSG_NEED_SPACE(uint8_t /* ttl */)     \
        +   _CMSG_NEED_SPACE(uint8_t /* tos */)     \
    )

#include <stdlib.h>
#include <stdint.h>
//#include <net/if.h>     //IFNAMSIZ
#include <linux/if.h>


#define IN
#define OUT
#define BTH

#define FOREVER     while(1)

#define NULL_IS(x)                                                  \
    ( NULL == (x) )

#define NOT_NULL_IS(x)                                              \
    ( NULL != (x) )

#define STRING_NULL_IS(x)                                           \
    ( NULL_IS(x) || ('\0' == (x)[0]) )

#define STRING_NOT_NULL_IS(x)                                       \
    ( NOT_NULL_IS(x) && ('\0' != (x)[0]) )

#define OFFSETOF(_structure, _member)                               \
    ((size_t)&(((_structure *)0)->_member))

#define CONTAINEROF_UNSAFE(_ptr, _type, _member)                    \
    ( (_type*)( ((uintptr_t)(_ptr)) - OFFSETOF(_type, _member) ) )
    
#define CONTAINEROF(_ptr, _type, _member)                           \
    ( NULL_IS((_ptr))?NULL:CONTAINEROF_UNSAFE((_ptr), _type, _member) )

#define SWAP16(x)                                           \
    (       (((uint32_t)(x) & 0x00ff) <<  8)                \
        |   (((uint32_t)(x) & 0xff00) >>  8)                \
    )

#define SWAP32(x)                                           \
    (       (((uint32_t)((x) & 0x0000ff00)) <<  8)            \
        |   (((uint32_t)((x) & 0x00ff0000)) >>  8)            \
        |   (((uint32_t)((x) & 0xff000000)) >> 24)            \
        |   (((uint32_t)((x) & 0x000000ff)) << 24)            \
    )

#define ITERATOR_DIRECT(iterator, size)                     \
    (size_t iterator = 0; iterator < (size); ++(iterator))

#define ITERATOR_REVERSE(iterator, size)                    \
    (size_t iterator = (size); iterator--; )

#define BPROXY_CONCAT(x, y)                                 \
    x##y    

#define _BPROXY_STR(x)                                      \
    #x
    
#define BPROXY_STR(x)                                       \
    _BPROXY_STR(x)

#define BPROXY_REQUIRED_SEMICOLON(name)                     \
    typedef struct { int nothing;} BPROXY_CONCAT(__required_semicolon##name##_, __LINE__)

#define ENDIAN_BIG       (4321)
#define ENDIAN_LITTLE    (1234)

#if     defined(__x86_64__) || defined(__amd64__)
    #define ENDIAN  (ENDIAN_LITTLE)

#elif   defined(__i386__) || defined(__i686__) || defined(_X86_) || defined(_M_IX86)
    #define ENDIAN  (ENDIAN_LITTLE)

#elif   defined(__mips__) || defined(__mips) || defined(mips) || defined (__mips64)
        #if     defined(MIPSEB) || defined(_MIPSEB) || defined(__MIPSEB)
            #define ENDIAN  (ENDIAN_BIG)
        #elif   defined(MIPSEL) || defined(_MIPSEL) || defined(__MIPSEL)
            #define ENDIAN  (ENDIAN_LITTLE)
        #endif
#else
    #error Unknown architecture
#endif

#if     (ENDIAN == ENDIAN_LITTLE)
    #define ENDIAN_ITERATOR_LITTLE(iterator, size)          \
        ITERATOR_DIRECT(iterator, size)

    #define ENDIAN_ITERATOR_BIG(iterator, size)          \
        ITERATOR_REVERSE(iterator, size)

#elif   (ENDIAN == ENDIAN_BIG)
    #define ENDIAN_ITERATOR_LITTLE(iterator, size)          \
        ITERATOR_REVERSE(iterator, size)

    #define ENDIAN_ITERATOR_BIG(iterator, size)          \
        ITERATOR_DIRECT(iterator, size)

#else
    #error Unknown byte endian 
#endif

#if     !defined(IF_NAMESIZE)
    #if !defined(IFNAMSIZ)
        #warning IFNAMSIZE unknown

        #define IFNAMSIZ        (16)
    #endif

    #define IF_NAMESIZE     (IFNAMSIZ)
#elif   !defined(IFNAMSIZ)
    #define IFNAMSIZ        (IF_NAMESIZE)
#endif

typedef
unsigned char       ubyte_t;

#include "errno.h"

#endif
