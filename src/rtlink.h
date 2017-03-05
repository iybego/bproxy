/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#if !defined(BPROXY_RTLINK)
#define BPROXY_RTLINK

#include "bproxy.h"
#include "poll.h"
#include "hashmap.h"
#include "list.h"
#include "ipv4.h"

typedef
enum {
        rnetlink_ok         = 0
    ,   rnetlink_failed
} rnetlink;

typedef
enum {
        ertlink_state_up
    ,   ertlink_state_starting
    ,   ertlink_state_down
    ,   ertlink_state_removed
} ertlink_state;

#define RTLINK_DEVICE_IDX_INVALID   (0)

typedef
struct _rtlink_listener srtlink_listener;

#define FRTLINK_NOTIFY_INDEX            (1)
#define FRTLINK_NOTIFY_INDEX_RELAXED    (2) //index changed from RTLINK_DEVICE_IDX_INVALID

#define FRTLINK_NOTIFY_STATE            (5)

typedef
void (*frtlink_notify) (
        srtlink_listener*                   listener,
        uint32_t                            flags
);

typedef
struct _rtlink {
    spollable                               pollable;

    shashmap*                               hashmap;    //srtlink_device/hash
    slist                                   devices;    //srtlink_device/rtlink

    size_t                                  touched;
    size_t                                  touched_done;
} srtlink;

typedef
struct _rtlink_device_address {
    sipv4_network                           network;
    ipv4_t                                  broadcast;

    size_t                                  touched;

    slist_entry                             entry;      //addresses@srtlink_device
} srtlink_device_address;

typedef
struct _rtlink_device {
    shashmap_entry                          hash;       //hashmap@srtlink
    slist_entry                             entry;      //devices@rtlink

    char                                    name[IFNAMSIZ];
    ertlink_state                           state;
    device_index_t                          index;
    device_mtu_t                            mtu;

    size_t                                  touched;

    slist                                   listeners;
    slist                                   addresses;
} srtlink_device;

struct _rtlink_listener {
    slist_entry                             entry;      //listeners@srtlink_device
    frtlink_notify                          callback;
};

static inline srtlink_device*
rtlink_listener_device (
    IN  srtlink_listener*                   listener
) {
    if LIST_ENTRY_NOT_ATTACHED(&(listener->entry))
        return NULL;

    return CONTAINEROF(list_entry_head(&(listener->entry)), srtlink_device, listeners);
}

static inline const char*
rtlink_listener_device_name (
    IN  const srtlink_listener*             listener
) {
    srtlink_device* _device = rtlink_listener_device((srtlink_listener*)listener);

    if NULL_IS(_device)
        return NULL;

    return _device->name;
}

static inline ertlink_state
rtlink_listener_state (
    IN  srtlink_listener*                   listener
) {
    srtlink_device* _device = rtlink_listener_device(listener);

    if NULL_IS(_device)
        return ertlink_state_removed;

    return _device->state;
}

static inline device_index_t
rtlink_listener_index (
    IN  srtlink_listener*                   listener
) {
    srtlink_device* _device = rtlink_listener_device(listener);

    if NULL_IS(_device)
        return RTLINK_DEVICE_IDX_INVALID;

    return _device->index;
}

static inline device_mtu_t
rtlink_listener_mtu (
    IN  srtlink_listener*                   listener
) {
    srtlink_device* _device = rtlink_listener_device(listener);

    if NULL_IS(_device)
        return ipv4_unknown_mtu();

    return _device->mtu;
}

static inline srtlink_device_address*
rtlink_listener_address (
    IN  srtlink_listener*                   listener
) {
    srtlink_device* _device = rtlink_listener_device(listener);

    if NULL_IS(_device)
        return NULL;

    return LIST_FIRST(&(_device->addresses), srtlink_device_address, entry); 
}

static inline srtlink_device_address*
rtlink_device_address_next (
    srtlink_device_address*                 address
) { return LIST_NEXT(address, srtlink_device_address, entry); }

socket_t
netlink_open (
        int                                 type,
        int                                 groups,
        pid_t                               pid
);

void
netlink_close (
        socket_t                            socket
);

rnetlink
rtlink_create (
    OUT srtlink*                            rtlink,
    BTH spoll*                              poll,
        size_t                              hashmap_factor
);

rnetlink
rtlink_attach (
    BTH srtlink*                            rtlink
);

rnetlink
rtlink_detach (
    BTH srtlink*                            rtlink
);

rnetlink
rtlink_reload (
    BTH srtlink*                            rtlink
);

rnetlink
rtlink_destroy (
    BTH srtlink*                            rtlink
);

#define RTLINK_LISTENER_ATTACHED(x)             \
    ( !!  LIST_ENTRY_ATTACHED(&((x)->entry)) )

#define RTLINK_LISTENER_NOT_ATTACHED(x)         \
    ( !!! LIST_ENTRY_ATTACHED(&((x)->entry)) )

rnetlink
rtlink_listener_attach (
    OUT srtlink_listener*                   listener,
    BTH srtlink*                            rtlink,
    IN  const char*                         name,
        frtlink_notify                      callback
);

rnetlink
rtlink_listener_detach (
    BTH srtlink_listener*                   listener
);

#endif

