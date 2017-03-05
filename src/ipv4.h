/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#if !defined(BPROXY_IPV4)
#define BPROXY_IPV4

#include "bproxy.h"
#include "sysctl.h"

#define IPV4_MAX_OPTIONS_LENGTH     (40) // = minimux header length (60 bytes) - minimum (20 bytes)

#if     (ENDIAN == ENDIAN_LITTLE)
    #define IPV4_DPRIADDR(x) (((x) >> 0) & 0xFF), (((x) >> 8) & 0xFF), (((x) >> 16) & 0xFF), (((x) >> 24) & 0xFF)

    #define IPV4_ADDRESS(x, y, z, h)                        \
        ((((uint32_t)h) << 24) | (((uint32_t)z) << 16) | (((uint32_t)y) << 8) | ((uint32_t)x))

    #define IPV4_MASK(bits)                                 \
        (((bits) == 0)?0:(SWAP32(((uint32_t)~0) << (32 - (bits)))))

#elif   (ENDIAN == ENDIAN_BIG)
    #define IPV4_DPRIADDR(x) (((x) >> 24) & 0xFF), (((x) >> 16) & 0xFF), (((x) >> 8) & 0xFF), (((x) >> 0) & 0xFF)

    #define IPV4_ADDRESS(x, y, z, h)                        \
        ((((uint32_t)h) << 0) | (((uint32_t)z) << 8) | (((uint32_t)y) << 16) | (((uint32_t)x) << 24))

    #define IPV4_MASK(bits)                                 \
         (((bits) == 0)?0:(((uint32_t)~0) << (32 - (bits))))

#else
    #error Unknown byte endian 
#endif

#define IPV4_NETWORK(x, y, z, h, m)     \
    { IPV4_ADDRESS(x, y, z, h), IPV4_MASK(m) }

#define IPV4_UNKNOWN_MTU        (576) //according to RFC 791

typedef
uint32_t                ipv4_t;

typedef
struct _ipv4_destination {
    ipv4_t              address;
    uint16_t            port;
} sipv4_destination;

typedef
struct _ipv4_allow              sipv4_allow;

typedef
struct _ipv4_allow_to           sipv4_allow_to;

typedef
struct _ipv4_portrange          sipv4_portrange;

typedef
struct _ipv4_network {
    ipv4_t                      address;
    ipv4_t                      mask;
} sipv4_network;

extern const sipv4_network IPV4_NETWORK_ALL_MULTICAST;
extern const sipv4_network IPV4_NETWORK_ANY          ;
extern const sipv4_network IPV4_NETWORK_BROADCAST    ;

struct _ipv4_allow {
    sipv4_network               address;
    sipv4_allow_to*             allow_to;

    sipv4_allow*                next;
};

struct _ipv4_allow_to {
    sipv4_network               address;

    sipv4_portrange*            portrange;

    sipv4_allow_to*             next;
};

struct _ipv4_portrange {
    uint16_t                    first;
    uint16_t                    last;

    sipv4_portrange*            next;
};

#define IPV4_PRIADDR    "%d.%d.%d.%d"

typedef
enum {
        ripv4_ok        = 0
    ,   ripv4_failed
} ripv4;

static inline ripv4
ipv4_address_in_network (
        ipv4_t                      address,
    IN  const sipv4_network*        network
) { return ((address & network->mask) == (network->address & network->mask))?ripv4_ok:ripv4_failed; }

static inline ipv4_t
ipv4_broadcast (
        ipv4_t                      address,
        ipv4_t                      mask
) { return (address & mask) + (~ mask); }

static inline ipv4_t
ipv4_network_broadcast (
    IN  const sipv4_network*        network
) { return ipv4_broadcast(network->address, network->mask); }

static inline ripv4
ipv4_portrange_check (
    IN  const sipv4_portrange*      portrange,
        uint16_t                    port
) {
    if NULL_IS(portrange)
        return ripv4_ok;

    for (const sipv4_portrange* _range = portrange; NULL != _range; _range = _range->next)
        if ((port >= _range->first) && (port <= _range->last))
            return ripv4_ok;

    return ripv4_failed;
}

ripv4
ipv4_allow_allowed_is (
    IN  const sipv4_allow*          allow,
        ipv4_t                      from,
        sipv4_destination*          destination
);

/// === sysctl wrappers

SYSCTL_WRAPPER(ipv4_default_ttl,        u8  );
SYSCTL_WRAPPER(ipv4_minimum_pmtu,       u32 );

static inline uint32_t
ipv4_unknown_mtu (
) {
    uint32_t _mtu = IPV4_UNKNOWN_MTU;
    ipv4_minimum_pmtu(&_mtu);
    return _mtu;
}

#endif

