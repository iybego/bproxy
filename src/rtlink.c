/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#include "rtlink.h"
#include "log.h"
#include "jenkins.h"
#include "utils.h"
#include "errno.h"

#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>

//netlink
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>
// * netlink

LOG_MODULE("netlink");

//cuz' we doesn't communicate kernel to create objects
// ... we can use seq as request identifier

typedef
enum {
        SEQ_BROADCAST       = 0
    ,   SEQ_RELOAD_LINK
    ,   SEQ_RELOAD_ADDR
} ertlink_sequence;

static rnetlink
_rtlink_reload_send (
    BTH srtlink*                        rtlink,
        int                             type,
        int                             sequence
);

static inline void
_rtlink_device_addresses_cleanup (
    BTH srtlink_device*                 device
);

//--------------------------------------------- netlink
socket_t
netlink_open (
        int                             type,
        int                             groups,
        pid_t                           pid
) {
    socket_t _netlink = socket(AF_NETLINK, SOCK_RAW, type);

    if SOCKET_INVALID_IS(_netlink) {
        LOG(error, "can't open " PRIerrno, DPRIerrno);
        goto _failure;
    }

    struct sockaddr_nl _binding;
    memset(&_binding, 0, sizeof(_binding));

    _binding.nl_family  = AF_NETLINK;
    _binding.nl_pid     = pid;
    _binding.nl_groups  = groups;

    if (0 > bind(_netlink, (struct sockaddr*)&_binding, sizeof(_binding))) {
        LOG(error, "can't bind "PRIerrno, DPRIerrno);
        goto _failure_close;
    }

    return _netlink;

    _failure_close:
        close(_netlink);

    _failure:
        return SOCKET_INVALID;
}

void
netlink_close (
        socket_t                        socket
) { close(socket); }

//--------------------------------------------- srtlink

static inline socket_t
_rtlink_socket (
    IN  srtlink*                        rtlink
) { return pollable_socket(&(rtlink->pollable)); }

static pid_t
_rtlink_pid (
    BTH srtlink*                        rtlink
) { return (((pid_t)((uintptr_t)rtlink)) << 16) | getpid(); 

    /** KIM: man 2 getpid
        Since glibc version 2.3.4, the glibc wrapper function for getpid()
        caches PIDs, so as to avoid additional system calls when a process
        calls getpid() repeatedly.  Normally this caching is invisible, but
        its correct operation relies on support in the wrapper functions for
        fork(2), vfork(2), and clone(2): if an application bypasses the glibc
        wrappers for these system calls by using syscall(2), then a call to
        getpid() in the child will return the wrong value (to be precise: it
        will return the PID of the parent process).  See also clone(2) for
        discussion of a case where getpid() may return the wrong value even
        when invoking clone(2) via the glibc wrapper function.
    **/
}

//--------------------------------------------- srtlink_device

static srtlink_device*  //find or allocate srtlink_device by name
_rtlink_device_lazy_lookup (
    BTH srtlink*                        rtlink,
        const char*                     name
) {
    shashmap_cursor _cursor;

    if (rhashmap_not_found != hashmap_lookup(&_cursor, rtlink->hashmap, name, IFNAMSIZ))
        return CONTAINEROF(hashmap_cursor(&_cursor), srtlink_device, hash);

    srtlink_device* _rtdev = (srtlink_device*)malloc(sizeof(srtlink_device));

    if NULL_IS(_rtdev) {
        LOG(critical, "out of memory, rtlink device [%lu bytes]", sizeof(srtlink_device));
        return NULL;
    }

    hashmap_insert(&_cursor, &_rtdev->hash);
    list_append(&(rtlink->devices), &(_rtdev->entry));

    memcpy(_rtdev->name, name, IFNAMSIZ);

    _rtdev->state   = ertlink_state_removed;
    _rtdev->index   = RTLINK_DEVICE_IDX_INVALID;
    _rtdev->touched = 0;
    _rtdev->mtu     = ipv4_unknown_mtu();

    list_initialize(&(_rtdev->listeners));
    list_initialize(&(_rtdev->addresses));

    LOG(debug, "rtlink device %p allocated", _rtdev);

    return _rtdev;
}

static inline rnetlink
_rtlink_device_remove (
    BTH srtlink_device*                 device
) {
    LOG(debug, "rtlink device %p destroyed", device);

    LOG_ASSERT(LIST_EMPTY(&(device->listeners)));

    hashmap_remove(&device->hash);
    list_detach(&device->entry);

    _rtlink_device_addresses_cleanup(device);

    free(device);
    return rnetlink_ok;
}

//--------------------------------------------- srtlink_device_address

static srtlink_device_address*
_rtlink_address_find (
    BTH srtlink_device*             device,
        sipv4_network*              network,
        ipv4_t                      broadcast
) {
    LIST_FOREACH(_a, srtlink_device_address, entry, &(device->addresses)) {
        if (0 == memcmp(network, &(_a->network), sizeof(sipv4_network)))
            if (0 == memcmp(&broadcast, &(_a->broadcast), sizeof(ipv4_t)))
                return _a;
    }

    return NULL;
}

static inline void
_rtlink_device_address_free (
    BTH srtlink_device_address*         address
) {
    LOG(debug, "address destroyed %p", address);

    list_detach(&(address->entry));
    free(address);
}

static inline void
_rtlink_device_addresses_cleanup (
    BTH srtlink_device*                 device
) {
    LIST_FOREACH_SAFE(_address, srtlink_device_address, entry, &(device->addresses))
        _rtlink_device_address_free(_address);
}

//--------------------------------------------- 

static rnetlink
_rtlink_device_notify (
    BTH srtlink_device*                 device,
        ertlink_state                   state,
        device_index_t                  index
) {
    uint32_t _flags = 0;

    _flags |= (state != device->state)?FRTLINK_NOTIFY_STATE:0;
    _flags |= (index != device->index)?FRTLINK_NOTIFY_INDEX:0;

    if (0 == _flags) {
        LOG(debug, "...nothing changed");
        return rnetlink_ok;
    }

    if (0 != (_flags & FRTLINK_NOTIFY_INDEX)) {
        //if index changed from RTLINK_DEVICE_IDX_INVALID to correct device index,
        //we MUST set RELAXED change flag
        if ((RTLINK_DEVICE_IDX_INVALID == device->index) && (RTLINK_DEVICE_IDX_INVALID != index)) {
            LOG(debug, "...relaxed index change");

            _flags |= FRTLINK_NOTIFY_INDEX_RELAXED;
        }

        //if device's index changed, we mainway lose all it addresses
        //but we ignore change if relaxed change occured
        if (0 == (_flags & FRTLINK_NOTIFY_INDEX_RELAXED))
            _rtlink_device_addresses_cleanup(device);
    }

    switch (state) {
        case ertlink_state_removed:
            LOG(verbose, "...removed");

            _rtlink_device_addresses_cleanup(device);

            if LIST_EMPTY(&(device->listeners))
                return _rtlink_device_remove(device);

            device->index = RTLINK_DEVICE_IDX_INVALID; //@index MUST be RTLINK_DEVICE_IDX_INVALID
            device->state = ertlink_state_removed;
            break;

        case ertlink_state_up:
            LOG(verbose, "...up");

            device->index = index;
            device->state = ertlink_state_up;
            break;

        case ertlink_state_down:
            if (device->index != index) {
                LOG(verbose, "...starting");
                device->state = ertlink_state_starting;

            } else {
                LOG(verbose, "...down");
                device->state = ertlink_state_down;
            }

            device->index = index;
            break;

        case ertlink_state_starting:
            LOG(critical, "notify with state %d, this should not occure!", (int)state);
            return rnetlink_failed;
    }

    LIST_FOREACH_SAFE(_listener, srtlink_listener, entry, &(device->listeners))
        _listener->callback(_listener, _flags);

    return rnetlink_ok;
}

static rnetlink
_rtlink_handler_msg_addr (
    BTH srtlink*                    rtlink,
    BTH struct nlmsghdr*            hdr
) {
    struct ifaddrmsg*   _info   = (struct ifaddrmsg*)NLMSG_DATA(hdr);
    size_t              _length = (hdr->nlmsg_len - NLMSG_LENGTH(sizeof(*_info)));

    char*               _label        = NULL;
    struct sipv4_t*     _t_address    = NULL;
    struct sipv4_t*     _t_local      = NULL;
    struct sipv4_t*     _t_broadcast  = NULL;

    for (struct rtattr* _attr = IFA_RTA(_info); RTA_OK(_attr, _length); _attr = RTA_NEXT(_attr, _length))
        switch (_attr->rta_type) {
            case IFA_LABEL: {
                _label = RTA_DATA(_attr);
                break;
            }

            case IFA_LOCAL: {
                _t_local = RTA_DATA(_attr);
                break;
            }

            case IFA_BROADCAST: {
                _t_broadcast = RTA_DATA(_attr);
                break;
            }

            case IFA_ADDRESS: {
                _t_address = RTA_DATA(_attr);
                break;
            }
        }

    if (NULL_IS(_label) || (NULL_IS(_t_local) && NULL_IS(_t_address)))
        return rnetlink_failed;

    char _device[IFNAMSIZ + 1];

    memset(_device, 0, sizeof(_device));

    for (size_t _i = 0; _i < IFNAMSIZ; _i++) {
        if ('\0' == _label[_i])
            break;

        if (':'  == _label[_i])
            if (0 != (_info->ifa_flags & IFA_F_SECONDARY))
                break;

        _device[_i] = _label[_i];
    }

    shashmap_cursor _cursor;

    if (rhashmap_not_found == hashmap_lookup(&_cursor, rtlink->hashmap, _device, IFNAMSIZ)) {
        LOG(warning, "received address request without corresponding device [%s] registred, ignored", _device);
        LOG(warning, "^ if this message repeat, decrease reload interval");
        return rnetlink_ok;
    }

    sipv4_network   _network = {0, IPV4_MASK(_info->ifa_prefixlen)};
    ipv4_t          _broadcast;

    if (NULL != _t_local) {
        memcpy(&(_network.address), _t_local,   sizeof(ipv4_t));
    } else {
        memcpy(&(_network.address), _t_address, sizeof(ipv4_t));
    }

    if (NULL != _t_broadcast) {
        memcpy(&_broadcast, _t_broadcast, sizeof(_broadcast));
    } else {
        if (NULL != _t_address) {
            memcpy(&_broadcast, _t_address, sizeof(ipv4_t));
        } else {
            _broadcast = ipv4_network_broadcast(&_network);
        }
    }

    LOG(verbose, "device %-5d [%-16s] address %s", _info->ifa_index, _device, 
        (hdr->nlmsg_type == RTM_NEWADDR)?((hdr->nlmsg_seq == SEQ_BROADCAST)?"added":"found"):"removed"
    );

    LOG(verbose, "... "IPV4_PRIADDR"/"IPV4_PRIADDR" ["IPV4_PRIADDR"]"
        ,   IPV4_DPRIADDR(_network.address), IPV4_DPRIADDR(_network.mask), IPV4_DPRIADDR(_broadcast)
    );

    srtlink_device* _rtdev = CONTAINEROF(hashmap_cursor(&_cursor), srtlink_device, hash);
    srtlink_device_address* _address = _rtlink_address_find(_rtdev, &_network, _broadcast);

    switch (hdr->nlmsg_type) {
        case RTM_DELADDR:
            if NULL_IS(_address) {
                LOG(warning, "can't remove address cuz' it don't exists");
                return rnetlink_failed;
            }

            _rtlink_device_address_free(_address);
            return rnetlink_ok;

        case RTM_NEWADDR:
            if NULL_IS(_address) {
                if NULL_IS(_address = malloc(sizeof(srtlink_device_address))) {
                    LOG(critical, "out of memory, device address [%lu]", sizeof(srtlink_device_address));
                    return rnetlink_failed;
                }

                LOG(debug, "address allocated %p", _address);

                memcpy(&(_address->network), &_network, sizeof(sipv4_network));
                memcpy(&(_address->broadcast), &_broadcast, sizeof(ipv4_t));

                list_entry_initialize(&(_address->entry));
                list_append(&(_rtdev->addresses), &(_address->entry));
            }

            _address->touched = rtlink->touched;
            return rnetlink_ok;
    }

    return rnetlink_ok;
}

#define _FMSG_LINK_DATA_RESOLVED_IFNAME     (1)
#define _FMSG_LINK_DATA_RESOLVED_MTU        (2)

static rnetlink
_rtlink_handler_msg_link_data (
    BTH struct ifinfomsg*           info,
    BTH struct nlmsghdr*            hdr,
    OUT char*                       ifname,
    OUT device_mtu_t*               mtu
) {
    uint32_t _resolved  = 0;
    size_t   _length    = (hdr->nlmsg_len - NLMSG_LENGTH(sizeof(*info)));

    for (struct rtattr* _attr = IFLA_RTA(info); RTA_OK(_attr, _length); _attr = RTA_NEXT(_attr, _length))
        switch (_attr->rta_type) {
            case IFLA_IFNAME: 
                if (0 != (_resolved & _FMSG_LINK_DATA_RESOLVED_IFNAME))
                    LOG(warning, "... duplicated IFLA_IFNAME");

                _resolved |= _FMSG_LINK_DATA_RESOLVED_IFNAME;

                strcpy_l(ifname, RTA_DATA(_attr), IFNAMSIZ);
                break;

            case IFLA_MTU:
                if (0 != (_resolved & _FMSG_LINK_DATA_RESOLVED_MTU))
                    LOG(warning, "... duplicated IFLA_MTU");

                _resolved |= _FMSG_LINK_DATA_RESOLVED_MTU;

                (*mtu) = *((unsigned int*)RTA_DATA(_attr));
                break;
        }

    if (0 == (_resolved & _FMSG_LINK_DATA_RESOLVED_IFNAME))
        return rnetlink_failed;

    if (0 == (_resolved & _FMSG_LINK_DATA_RESOLVED_MTU)) {
        LOG(warning, "mtu left unresolved, using default");
        (*mtu) = ipv4_unknown_mtu();
    }

    return rnetlink_ok;
}

static rnetlink
_rtlink_device_touch (
    BTH srtlink*                    rtlink,
        char*                       device,
        struct ifinfomsg*           info,
        device_mtu_t                mtu
) {
    if (0 == (IFF_LOWER_UP & info->ifi_flags))
        info->ifi_flags &= (~(IFF_UP | IFF_RUNNING));

    ertlink_state   _state = (0 != (info->ifi_flags & (IFF_UP | IFF_RUNNING)))?ertlink_state_up:ertlink_state_down;
    srtlink_device* _rtdev = _rtlink_device_lazy_lookup(rtlink, device);

    if NULL_IS(_rtdev) {
        LOG(verbose, "lazy device allocation failed");
        return rnetlink_failed;
    }

    _rtdev->mtu     = mtu;
    _rtdev->touched = rtlink->touched;

    return _rtlink_device_notify(_rtdev, _state, info->ifi_index);
}

static inline void
_rtlink_handler_msg_link_dump (
    IN  const struct ifinfomsg*     info,
        const char*                 name,
        const char*                 changed
) {
    LOG(debug, "device %-5d [%-16s] is %s: flags %8x & %-8x", info->ifi_index, name, changed, (unsigned)info->ifi_flags, (unsigned)info->ifi_change);
    
    #define __DUMP_FLAG(x)  \
        LOG(debug, "  %-20s [%s] [%s]", "" BPROXY_STR(x), (0 != (IFF_##x & info->ifi_flags))?"+":" ", (0 != (IFF_##x & info->ifi_change))?"+":" ")

    __DUMP_FLAG(UP          );
    __DUMP_FLAG(BROADCAST   );
    __DUMP_FLAG(DEBUG       );
    __DUMP_FLAG(LOOPBACK    );
    __DUMP_FLAG(POINTOPOINT );
    __DUMP_FLAG(NOTRAILERS  );
    __DUMP_FLAG(RUNNING     );
    __DUMP_FLAG(NOARP       );
    __DUMP_FLAG(PROMISC     );
    __DUMP_FLAG(ALLMULTI    );
    __DUMP_FLAG(MASTER      );
    __DUMP_FLAG(SLAVE       );
    __DUMP_FLAG(MULTICAST   );
    __DUMP_FLAG(PORTSEL     );
    __DUMP_FLAG(AUTOMEDIA   );
    __DUMP_FLAG(DYNAMIC     );
    __DUMP_FLAG(LOWER_UP    );
    __DUMP_FLAG(DORMANT     );
    __DUMP_FLAG(ECHO        );
}

static rnetlink
_rtlink_handler_msg_link (
    BTH srtlink*                    rtlink,
    BTH struct nlmsghdr*            hdr
) {
    struct ifinfomsg* _info = (struct ifinfomsg*)NLMSG_DATA(hdr);

    device_mtu_t _device_mtu = 0;
    char         _device[IFNAMSIZ + 1];

    memset(_device, 0, sizeof(_device));

    if (rnetlink_ok != _rtlink_handler_msg_link_data(_info, hdr, _device, &_device_mtu)) {
        LOG(error, "can't resolve device (idx: %d) name, ignoring", _info->ifi_index);
        return rnetlink_failed;
    }

    switch (hdr->nlmsg_type) {
        case RTM_DELLINK: {
            LOG(verbose, "device %-5d [%-16s] is removed", _info->ifi_index, _device);

            shashmap_cursor _cursor;

            if (rhashmap_not_found == hashmap_lookup(&_cursor, rtlink->hashmap, _device, IFNAMSIZ)) {
                LOG(warning, "received DELLINK without corresponding device registred, ignored");
                LOG(warning, "^ if this message repeat, decrease reload interval");
                return rnetlink_ok;
            }

            srtlink_device* _rtdev = CONTAINEROF(hashmap_cursor(&_cursor), srtlink_device, hash);

            _rtdev->touched = rtlink->touched;
            return _rtlink_device_notify(_rtdev, ertlink_state_removed, RTLINK_DEVICE_IDX_INVALID);
        }

        case RTM_NEWLINK:
            switch ((ertlink_sequence)(hdr->nlmsg_seq)) {
                case SEQ_BROADCAST:
                    _rtlink_handler_msg_link_dump(_info, _device, "changed");
                    return _rtlink_device_touch(rtlink, _device, _info, _device_mtu);

                case SEQ_RELOAD_LINK: 
                    LOG(verbose, "device %-5d [%-16s] is reported", _info->ifi_index, _device);
                    return _rtlink_device_touch(rtlink, _device, _info, _device_mtu);

                case SEQ_RELOAD_ADDR:
                    LOG(error, "unexcepted sequence number in handler!");
                    break;
            }

            LOG(warning, "unknown sequence %d", (int)hdr->nlmsg_seq);
            return rnetlink_failed;
    }

    return rnetlink_failed;
}

static rnetlink
_rtlink_handler_msg_done (
    BTH srtlink*                    rtlink,
    BTH int                         sequence
) {
    switch (sequence) {
        case SEQ_BROADCAST:
            return rnetlink_ok;

        case SEQ_RELOAD_LINK:
            return _rtlink_reload_send(rtlink, RTM_GETADDR, SEQ_RELOAD_ADDR);

        case SEQ_RELOAD_ADDR: {
            rtlink->touched_done = rtlink->touched;

            LOG(verbose, "reload done, applying");

            LIST_FOREACH_SAFE(_device, srtlink_device, entry, &(rtlink->devices)) {
                if (_device->touched != rtlink->touched) {  
                    //device doen't exists in reloading, set it to removed state

                    _device->touched = rtlink->touched;
                    _rtlink_device_notify(_device, ertlink_state_removed, RTLINK_DEVICE_IDX_INVALID);

                    continue;
                }

                //device exists, check it's addresses
                LIST_FOREACH_SAFE(_address, srtlink_device_address, entry, &(_device->addresses)) {            
                    if (_address->touched != rtlink->touched)
                        _rtlink_device_address_free(_address);
                }
            }

            LOG(verbose, "...done");
            return rnetlink_ok;
        }
    }

    LOG(warning, "unknown sequence (%d)", sequence);
    return rnetlink_failed;
}

static rpoll_handler
_rtlink_handler (
    BTH spollable*                  pollable,
        uint32_t                    flags,
    BTH spoll_passthrou*            passthrou
) {
    srtlink* _rtlink = CONTAINEROF(pollable, srtlink, pollable);

    if (flags & (FPOLLABLE_HUP | FPOLLABLE_ERR)) {
        //TODO: restart netlink rtlink

        return rpoll_handler_failed;
    }

    struct iovec     _iov[1] = {{passthrou->buffer, passthrou->length}};
    struct msghdr    _msg    = {NULL, 0, _iov, 1, NULL, 0, 0 };

    for (size_t _current_packet_per_tick = RTLINK_MAX_EVENTS_PER_TICK; _current_packet_per_tick--; ) {
        int _r_recvmsg = recvmsg(pollable_socket(pollable), &_msg, MSG_DONTWAIT | MSG_TRUNC);

        if (0  > _r_recvmsg) {
            if EAGAIN_IS(errno)        return rpoll_handler_ok;
            if EWOULDBLOCK_IS(errno)   return rpoll_handler_ok;
            if EINTR_IS(errno)         continue;

            LOG(error, "error occured " PRIerrno, DPRIerrno);
            //TODO: restart netlink rtlink
            return rpoll_handler_failed;
        }

        if (0 == _r_recvmsg) continue; //EOF on non-stream socket?

        if (passthrou->length < (unsigned)_r_recvmsg) {
            LOG(warning, "truncation occured, please increase buffer size to %d [at least]", _r_recvmsg);
            return rpoll_handler_ok;
        }

        for (struct nlmsghdr* _h = (struct nlmsghdr*)passthrou->buffer; NLMSG_OK(_h, (unsigned)_r_recvmsg); _h = NLMSG_NEXT(_h, _r_recvmsg))
            switch (_h->nlmsg_type) {
                case RTM_DELLINK:
                case RTM_NEWLINK:
                    _rtlink_handler_msg_link(_rtlink, _h);
                    break;

                case RTM_DELADDR:
                case RTM_NEWADDR:
                    _rtlink_handler_msg_addr(_rtlink, _h);
                    break;

                case NLMSG_DONE:
                    _rtlink_handler_msg_done(_rtlink, _h->nlmsg_seq);
                    break;

                case NLMSG_ERROR: {
                    struct nlmsgerr* _error = (struct nlmsgerr*)NLMSG_DATA(_h);
                    LOG(error, "netlink error received: %d", _error->error);
                    //TODO: restart netlink rtlink
                    break;
                }

                default:
                    LOG(warning, "unknown message type: %d", _h->nlmsg_type);
                    //TODO: restart netlink rtlink
            }
    }

    LOG(verbose, "%p events per tick limit exceeded", _rtlink);
    return rpoll_handler_ok;
}

//--------------------------------------------- 

static rnetlink
_rtlink_send (
    BTH srtlink*                    rtlink,
        int                         type,
        int                         sequence,
        void*                       extension,
        size_t                      length  
) {
    struct nlmsghdr     _hdr;
    struct sockaddr_nl  _address;

    memset(&_hdr,     0, sizeof(_hdr));
    memset(&_address, 0, sizeof(_address));

    struct iovec        _iov[2]  = {{ &_hdr, sizeof(_hdr) }, { extension, length }};
    struct msghdr       _msg     = { &_address, sizeof(_address), _iov, 2, NULL, 0, 0};

    _hdr.nlmsg_pid      = _rtlink_pid(rtlink);
    _hdr.nlmsg_type     = type;
    _hdr.nlmsg_seq      = sequence;
    _hdr.nlmsg_flags    = NLM_F_REQUEST | NLM_F_DUMP;
    _hdr.nlmsg_len      = NLMSG_LENGTH(length);

    _address.nl_family  = AF_NETLINK;

    FOREVER {
        if (0 < sendmsg(_rtlink_socket(rtlink), &_msg, 0))
            return rnetlink_ok;

        if EINTR_IS(errno) continue;

        LOG(error, "can't communicate kernel "PRIerrno, DPRIerrno);
        return rnetlink_failed;
    }
}

static rnetlink
_rtlink_reload_send (
    BTH srtlink*                    rtlink,
        int                         type,
        int                         sequence
) {
    switch (type) {
        case RTM_GETLINK: {
            LOG(verbose, "requesting links reload");

            struct rtgenmsg _gen;
            memset(&_gen, 0, sizeof(_gen));
            _gen.rtgen_family = AF_PACKET;

            return _rtlink_send(rtlink, type, sequence, &_gen, sizeof(_gen));
        }

        case RTM_GETADDR: {
            LOG(verbose, "requesting addresses reload");

            struct ifaddrmsg _addr;
            memset(&_addr, 0, sizeof(_addr));
            _addr.ifa_family = AF_INET;

            return _rtlink_send(rtlink, type, sequence, &_addr, sizeof(_addr));
        }
    }

    return rnetlink_failed;
}

rnetlink
rtlink_reload (
    BTH srtlink*                    rtlink
) {
    if (((rtlink->touched)++) != (rtlink->touched_done)) {
        LOG(error, "last reload freeze, restarting rtlink");
        
    }

    return _rtlink_reload_send(rtlink, RTM_GETLINK, SEQ_RELOAD_LINK);
}

static inline int
_rtlink_compare (
    IN  shashmap_entry*             target,
    IN  const void*                 buffer,
        size_t                      length
) { return memcmp(CONTAINEROF(target, srtlink_device, hash)->name, buffer, length); }

rnetlink
rtlink_create (
    OUT srtlink*                    rtlink,
    BTH spoll*                      poll,
        size_t                      hashmap_factor
) {
    static const shashmap_interface _interface = {
            hash32_jenkins
        ,   _rtlink_compare
    };

    socket_t _socket = netlink_open(NETLINK_ROUTE, RTMGRP_LINK | RTMGRP_IPV4_IFADDR, _rtlink_pid(rtlink));

    if SOCKET_INVALID_IS(_socket)
        goto _failed;

    if NULL_IS(rtlink->hashmap = hashmap_allocate(hashmap_factor, &_interface))
        goto _failed_hashmap;

    pollable_initialize(&(rtlink->pollable), poll, _rtlink_handler, _socket, FPOLLABLE_IN);

    list_initialize(&(rtlink->devices));

    rtlink->touched         = 0;
    rtlink->touched_done    = 0;

    return rnetlink_ok;

    _failed_hashmap:
        netlink_close(_socket);

    _failed:
        return rnetlink_failed;
}

rnetlink
rtlink_destroy (
    BTH srtlink*                    rtlink
) {
    netlink_close(rtlink->pollable.socket);

    hashmap_free(rtlink->hashmap);

    pollable_clear(&(rtlink->pollable));

    rtlink->hashmap = NULL;

    return rnetlink_ok;
}

rnetlink
rtlink_attach (
    BTH srtlink*                    rtlink
) {
    if (rpoll_ok != poll_attach(&(rtlink->pollable)))
        return rnetlink_failed;

    return rnetlink_ok;
}

rnetlink
rtlink_detach (
    BTH srtlink*                    rtlink
) {
    if (rpoll_ok != poll_detach(&(rtlink->pollable)))
        return rnetlink_failed;

    return rnetlink_ok;
}

rnetlink
rtlink_listener_attach (
    OUT srtlink_listener*           listener,
    BTH srtlink*                    rtlink,
    IN  const char*                 name,
        frtlink_notify              callback
) {
    if STRING_NULL_IS(name) {
        list_entry_initialize(&(listener->entry));
        listener->callback = NULL;

        return rnetlink_ok;
    }

    char _name[IFNAMSIZ + 1];
    memset(_name, 0, IFNAMSIZ);
    strcpy_l(_name, name, IFNAMSIZ);

    LOG(debug, "listener %p is joining %s", listener, _name);

    srtlink_device* _rtdev = _rtlink_device_lazy_lookup(rtlink, _name);
    if NULL_IS(_rtdev) {
        LOG(error, "lazy device lookup failed");
        return rnetlink_failed;
    }

    LOG(debug, "^ joining %p", _rtdev);

    list_entry_initialize(&(listener->entry));
    listener->callback = callback;

    list_append(&(_rtdev->listeners), &(listener->entry));
    return rnetlink_ok;
}

rnetlink
rtlink_listener_detach (
    BTH srtlink_listener*           listener
) {
    if RTLINK_LISTENER_NOT_ATTACHED(listener)
        return rnetlink_ok;

    LOG(debug, "listener %p is leaving", listener);

    srtlink_device* _rtdev = rtlink_listener_device(listener);
    if NULL_IS(_rtdev) {
        LOG(error, "can't get rtlink device from listener");
        return rnetlink_failed;
    }

    LOG(debug, "^ leaving %p", _rtdev);

    list_detach(&(listener->entry));

    if LIST_EMPTY(&(_rtdev->listeners)) {
        if (ertlink_state_removed == _rtdev->state)
            _rtlink_device_remove(_rtdev);
    }

    return rnetlink_ok;
}

