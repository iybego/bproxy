/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#if !defined(BPROXY_SOCKET)
#define BPROXY_SOCKET

#include "bproxy.h"
#include "ipv4.h"

typedef
int                     socket_t;

typedef
int                     device_index_t;

typedef
uint32_t                device_mtu_t;

typedef
uint32_t                fwmark_t;

typedef
uint8_t                 ttl_t;

typedef
uint8_t                 tos_t;

#define SOCKET_INVALID_IS(x)            ( 0 > (x) )
#define SOCKET_INVALID                  (-1)

#define FSOCKET_BROADCAST               (1 << 0)
#define FSOCKET_REUSEADDR               (1 << 1)
#define FSOCKET_PKTINFO                 (1 << 2)
#define FSOCKET_TRANSPARENT             (1 << 3)
#define FSOCKET_RECVORIGDSTADDR         (1 << 4)
#define FSOCKET_HDRINCL                 (1 << 5)
#define FSOCKET_RECVTTL                 (1 << 6)
#define FSOCKET_RECVTOS                 (1 << 7)
#define FSOCKET_DONTROUTE               (1 << 8)
#define FSOCKET_RECVOPTIONS             (1 << 9)

typedef
enum {
        rsocket_ok          = 0
    ,   rsocket_failed
} rsocket;

socket_t
socket_open (
        uint32_t                flags,
        struct sockaddr*        binding,
        const char*             device
);

socket_t
socket_raw (
        uint32_t                flags,
        const char*             device
);

rsocket
socket_fwmark_set (
        socket_t                socket,
        fwmark_t                fwmark
);

rsocket
socket_mgroup_join (
        socket_t                socket,
        ipv4_t                  group,
        ipv4_t                  local,
        device_index_t          device
);

rsocket
socket_mgroup_leave (
        socket_t                socket,
        ipv4_t                  group,
        ipv4_t                  local,
        device_index_t          device
);

void
socket_close (
        socket_t                socket
);

#endif

