/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#if !defined(BPROXY_TYPES)
#define BPROXY_TYPES

#include "bproxy.h"
#include "ipv4.h"
#include "socket.h"
#include "poll.h"
#include "rtlink.h"
#include "ratelimit.h"

typedef
struct _source          ssource;

typedef
struct _sink            ssink;

typedef
enum {
        esource_type_simple     = 0
    ,   esource_type_raw
} esource_type;

typedef
struct _mgroup          smgroup;

struct _mgroup {
    ipv4_t                      group;

    smgroup*                    next;
};

struct _source {
    esource_type                type;
    uint32_t                    flg_socket;

    sipv4_network               binding;
    uint16_t                    port;       //listen port

    union {
        struct {
            srtlink_listener            device;
            spollable                   pollable;
        } runtime;

        struct {
            char                        device[IFNAMSIZ];
        } configuration;

    } ss;   //state specific

    sratelimit*                 ratelimit;

    sipv4_allow*                allow;
    sipv4_portrange*            portrange;

    smgroup*                    mgroups;

    ssink*                      sinks;

    ssource*                    next;
};

typedef
enum {
        rsource_ok              = 0
    ,   rsource_failed          
} rsource;

rsource
source_start (
    BTH ssource*                source
);

rsource
source_stop (
    BTH ssource*                source
);

static inline rsource
source_restart (
    BTH ssource*                source
) {
    if (rsource_ok != source_stop(source))
        return rsource_failed;

    return source_start(source);
}

rsource
source_state (
    BTH ssource*                source
);

rsource
sources_bootup (
    BTH ssource*                source,
    BTH srtlink*                rtlink,
    BTH spoll*                  poll
);

rsource 
sources_restart (
    BTH ssource*                source
);

rsource 
sources_start (
    BTH ssource*                source
);

rsource
sources_cleanup (
    BTH ssource*                source,
        ssource*                until
);

typedef
enum {
        esink_type_simple        = 0
    ,   esink_type_join
} esink_type;

#define FSINK_REWRITE_FROM                      (1 <<  0)
#define FSINK_REWRITE_DESTINATION_ORIGINAL      (1 <<  1)

#define FSINK_REWRITE_NO_FRAGMENT               (1 <<  4)
#define FSINK_REWRITE_NO_IP_ID                  (1 <<  5)
#define FSINK_REWRITE_NO_IP_OPTIONS             (1 <<  6)
#define FSINK_REWRITE_NO_ICMP_TTL               (1 <<  7)
#define FSINK_REWRITE_NO_ICMP_FRAGMENTATION     (1 <<  8)

#define FSINK_REWRITE_FWMARK                    (1 << 11)
#define FSINK_REWRITE_TTL                       (1 << 12)
#define FSINK_REWRITE_TOS                       (1 << 13)
#define FSINK_REWRITE_MTU                       (1 << 14)

#define FSINK_REWRITE_SECURITY                  (1 << 20)
#define FSINK_REWRITE_SECURITY_DROP             (1 << 21)

typedef
struct _ipv4_option sipv4_option;

struct _ipv4_option {
    sipv4_option*       next;
    size_t              length;
    ubyte_t             data[];
};

struct _sink {
    esink_type          type;
    uint32_t            flg_socket;

    socket_t            socket;

    uint16_t            last_ip_id;

    union {
        struct {
            sipv4_network               target;

            union {
                char                        configuration[IFNAMSIZ];
                srtlink_listener            runtime;
            } device;

        } simple;

        union {
            struct {
                srtlink_listener            device;
            } runtime;

            struct {
                char                        device[IFNAMSIZ];
            } configuration;

        } join; //state specific

    } ts;   //type specific

    uint32_t                    rewrite;    //FSINK_REWRITE_xxx

    sipv4_destination           from;       //from address & port rewrite
    uint16_t                    port;       //destination port

    ttl_t                       ttl;
    tos_t                       tos;
    fwmark_t                    fwmark;
    device_mtu_t                mtu;

    uint8_t                     security_level;
    uint64_t                    security_categories;

    sipv4_option*               option;

    sipv4_allow*                allow;
    sipv4_portrange*            portrange;

    ssink*                      next;
};

#endif
