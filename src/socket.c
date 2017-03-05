/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#include "socket.h"

#include "utils.h"
#include "log.h"

#include <string.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>

#if     !defined(IP_TRANSPARENT)
    #warning hardcoded value used [IP_TRANSPARENT]
    #define IP_TRANSPARENT      (19)
#endif

#if     !defined(IP_ORIGDSTADDR)
    #warning hardcoded value used [IP_ORIGDSTADDR]
    #define IP_ORIGDSTADDR      (20)
#endif

#if     !defined(IP_RECVORIGDSTADDR)
    #warning hardcoded value used [IP_RECVORIGDSTADDR]
    #define IP_RECVORIGDSTADDR  (IP_ORIGDSTADDR)
#endif

LOG_MODULE("socket");

#define __SOCKOPT(t, f, x, y, z, s, n, o)                                                               \
    do { if (0 > setsockopt(t, x, y, z, s)) {                                                           \
        LOG(error, "can't set socket option [" n ", " o "], cuz' %d [%s]", errno, strerror(errno));     \
        f;                                                                                              \
    } } while (0) 

#define SOCKOPT(x, y, z)        \
    __SOCKOPT(socket, return rsocket_failed, x, y, &z, sizeof(z), #x, #y)

#define _SOCKOPT(x, y, z, s)    \
    __SOCKOPT(socket, return rsocket_failed, x, y, z, s, #x, #y)

#define SOCKFLG(x) \
    ( (0 != (flags & (FSOCKET_##x))) )

rsocket
socket_mgroup_join (
        socket_t                socket,
        ipv4_t                  group,
        ipv4_t                  local,
        device_index_t          device      
) {
    struct ip_mreqn _request;

    memcpy(&(_request.imr_multiaddr.s_addr),    &group,     sizeof(group)); 
    memcpy(&(_request.imr_address.s_addr),      &local,     sizeof(local));
    _request.imr_ifindex = device;

    SOCKOPT(IPPROTO_IP, IP_ADD_MEMBERSHIP, _request);
    return rsocket_ok;
}

rsocket
socket_mgroup_leave (
        socket_t                socket,
        ipv4_t                  group,
        ipv4_t                  local,
        device_index_t          device
) {
    struct ip_mreqn _request;

    memcpy(&(_request.imr_multiaddr.s_addr),    &group,     sizeof(group)); 
    memcpy(&(_request.imr_address.s_addr),      &local,     sizeof(local));
    _request.imr_ifindex = device;

    SOCKOPT(IPPROTO_IP, IP_DROP_MEMBERSHIP, _request);
    return rsocket_ok;
}

static rsocket
_socket_flags (
        socket_t                socket,
        uint32_t                flags
) {
    int _enable = 1;

    if SOCKFLG(HDRINCL)
        SOCKOPT(SOL_IP,     IP_HDRINCL,         _enable);

    if SOCKFLG(DONTROUTE)
        SOCKOPT(SOL_SOCKET, SO_DONTROUTE,       _enable);

    if SOCKFLG(TRANSPARENT)
        SOCKOPT(SOL_IP,     IP_TRANSPARENT,     _enable);

    if SOCKFLG(RECVORIGDSTADDR)
        SOCKOPT(SOL_IP,     IP_RECVORIGDSTADDR, _enable);

    if SOCKFLG(PKTINFO)
        SOCKOPT(SOL_IP,     IP_PKTINFO,         _enable);

    if SOCKFLG(BROADCAST)
        SOCKOPT(SOL_SOCKET, SO_BROADCAST,       _enable);

    if SOCKFLG(REUSEADDR)
        SOCKOPT(SOL_SOCKET, SO_REUSEADDR,       _enable);

    if SOCKFLG(DONTROUTE)
        SOCKOPT(SOL_SOCKET, SO_DONTROUTE,       _enable);

    if SOCKFLG(RECVTTL)
        SOCKOPT(SOL_IP,     IP_RECVTTL,         _enable);

    if SOCKFLG(RECVTOS)
        SOCKOPT(SOL_IP,     IP_RECVTOS,         _enable);

    if SOCKFLG(RECVOPTIONS)
        SOCKOPT(SOL_IP,     IP_RECVOPTS,        _enable);

    return rsocket_ok;
}

static rsocket
_socket_device (
        socket_t                socket,
        const char*             device
) {
    if STRING_NOT_NULL_IS(device)
        _SOCKOPT(SOL_SOCKET, SO_BINDTODEVICE, device, strlen_l(device, IFNAMSIZ));

    return rsocket_ok;
}

socket_t
socket_raw (
        uint32_t                flags,
        const char*             device
) {
    socket_t _socket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);

    if SOCKET_INVALID_IS(_socket) {
        LOG(error, "can't open raw socket, cuz' %d [%s]", errno, strerror(errno));
        goto _failure;
    }
    
    //cleanup flags wich have no sence
    uint32_t _flags = (flags & (~(FSOCKET_RECVOPTIONS | FSOCKET_RECVTTL | FSOCKET_RECVTOS))); 

    if (rsocket_ok != _socket_flags(_socket, _flags))
        goto _failure_close;

    if (rsocket_ok != _socket_device(_socket, device))
        goto _failure_close;

    return _socket;

    _failure_close:
        close(_socket);

    _failure:
        return SOCKET_INVALID;
}

socket_t
socket_open (
        uint32_t                flags,
        struct sockaddr*        binding,
        const char*             device
) {
    socket_t _socket = socket(AF_INET, SOCK_DGRAM, 0);

    if SOCKET_INVALID_IS(_socket) {
        LOG(error, "can't open socket, cuz' %d [%s]", errno, strerror(errno));
        goto _failure;
    }

    if (rsocket_ok != _socket_flags(_socket, flags))
        goto _failure_close;

    if (rsocket_ok != _socket_device(_socket, device))
        goto _failure_close;

    if NOT_NULL_IS(binding)
        if (0 > bind(_socket, binding, sizeof(struct sockaddr))) {
            LOG(error, "can't bind cuz' %d [%s]", errno, strerror(errno));
            goto _failure_close;
        }

    return _socket;

    _failure_close:
        close(_socket);

    _failure:
        return SOCKET_INVALID;
}

rsocket
socket_fwmark_set (
        socket_t                socket,
        fwmark_t                fwmark
) {
    SOCKOPT(SOL_SOCKET, SO_MARK, fwmark);
    return rsocket_ok;
}

void
socket_close (
        socket_t                socket
) { close(socket); }

