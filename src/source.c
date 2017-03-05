/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#include "source.h"
#include "log.h"

#include "utils.h"

#include <string.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>

#define IP_DONTFRAGMENT (0x4000)          /* Flag: "Don't Fragment"       */
#define IP_FRAGMENT     (0x2000)          /* Flag: "More Fragments"       */
#define IP_OFFSET       (0x1FFF)          /* "Fragment Offset" part       */
#define IP_FLAGS        (0xE000)          /* "Flags" part                 */

#include <netinet/ip.h>
#include <netinet/udp.h>

#include "swap.h"
#include "ipv4-option.h"

LOG_MODULE("source");

static rsource
_sink_start (
    BTH ssink*                          sink
);

static rsource
_sink_stop (
    BTH ssink*                          sink
);

static inline rsource
_sink_restart (
    BTH ssink*                          sink
) {
    if (rsource_ok != _sink_stop(sink))
        return rsource_failed;

    return _sink_start(sink);
}

typedef
struct __source_udp_packet {
    void*                               buffer;
    size_t                              length;

    void*                               options;
    size_t                              options_length;

    struct sockaddr_in                  from;

    uint16_t                            id;

    uint8_t                             tos;
    uint8_t                             ttl;

    sipv4_destination                   destination;
} _ssource_udp_packet;

rsource
_control_information (
    IN  struct msghdr*          msg,
    OUT _ssource_udp_packet*    packet
) {
    #define _RESOLVED_PKTINFO       (1 << 0)
    #define _RESOLVED_ORIGDSTADDR   (1 << 1)
    #define _RESOLVED_TTL           (1 << 2)
    #define _RESOLVED_TOS           (1 << 3)
    #define _RESOLVED_OPTIONS       (1 << 4)

    int _resolved = 0;

    for (struct cmsghdr* _cmsg = CMSG_FIRSTHDR(msg); NULL != _cmsg; _cmsg = CMSG_NXTHDR(msg, _cmsg)) {
        LOG(debug, "cmsg [level: %d, type: %d]", _cmsg->cmsg_level, _cmsg->cmsg_type);

        if ( (SOL_IP == _cmsg->cmsg_level) && (IP_PKTINFO == _cmsg->cmsg_type) ) {
            if (0 != (_RESOLVED_ORIGDSTADDR & _resolved))
                continue;

            if (0 != (_RESOLVED_PKTINFO & _resolved)) {
                LOG(warning, "duplicated PKTINFO found!");
                continue;
            }

            _resolved |= _RESOLVED_PKTINFO;

            struct in_pktinfo* _info = (struct in_pktinfo*)CMSG_DATA(_cmsg);

            memcpy(&(packet->destination.address), &(_info->ipi_addr.s_addr), sizeof(_info->ipi_addr.s_addr));
            packet->destination.port = 0;

            continue;
        }

        if ( (SOL_IP == _cmsg->cmsg_level) && (IP_ORIGDSTADDR == _cmsg->cmsg_type) ) {
            if (0 != (_RESOLVED_ORIGDSTADDR & _resolved)) {
                LOG(warning, "duplicated ORIGDSTADDR found!");
                continue; 
            }

            _resolved |= _RESOLVED_ORIGDSTADDR;

            struct sockaddr_in* _dst = (struct sockaddr_in*)CMSG_DATA(_cmsg);

            memcpy(&(packet->destination.address), &(_dst->sin_addr.s_addr), sizeof(_dst->sin_addr.s_addr));
            memcpy(&(packet->destination.port),    &(_dst->sin_port),        sizeof(_dst->sin_port)       );

            LOG(debug, "resolved "IPV4_PRIADDR":%"PRIu16, IPV4_DPRIADDR(packet->destination.address), ntohs(packet->destination.port));

            continue;
        }

        if ( (SOL_IP == _cmsg->cmsg_level) && (IP_TTL == _cmsg->cmsg_type) ) {
            if (0 != (_RESOLVED_TTL & _resolved)) {
                LOG(warning, "duplicated TTL found!");
                continue;
            }

            _resolved |= _RESOLVED_TTL;

            memcpy(&(packet->ttl), CMSG_DATA(_cmsg), sizeof(packet->ttl));
            continue;
        }

        if ( (SOL_IP == _cmsg->cmsg_level) && (IP_TOS == _cmsg->cmsg_type) ) {
            if (0 != (_RESOLVED_TOS & _resolved)) {
                LOG(warning, "duplicated TOS found!");
                continue;
            }

            _resolved |= _RESOLVED_TOS;

            memcpy(&(packet->tos), CMSG_DATA(_cmsg), sizeof(packet->tos));
            continue;
        }   

        if ( (SOL_IP == _cmsg->cmsg_level) && (IP_OPTIONS == _cmsg->cmsg_type) ) {
            if (0 != (_RESOLVED_OPTIONS & _resolved)) {
                LOG(warning, "duplicated OPTIONS found!");
                continue;
            }

            _resolved |= _RESOLVED_OPTIONS;

            packet->options        = CMSG_DATA(_cmsg);
            packet->options_length = _cmsg->cmsg_len;
            continue;
        }   

        LOG(debug, "^ unknown");
    }

    if (0 == ((_RESOLVED_PKTINFO | _RESOLVED_ORIGDSTADDR) & _resolved)) {
        LOG(warning, "can't resolve packet destination address");
        return rsource_failed;
    }

    if (0 == (_RESOLVED_TTL & _resolved))
        if (rsysctl_ok != ipv4_default_ttl(&(packet->ttl))) {
            LOG(error, "TTL unresolved, but can't get default ttl");
            return rsource_failed;
        }

    if (0 == (_RESOLVED_TOS & _resolved))
        packet->tos = 0x00;

    if (0 == (_RESOLVED_OPTIONS & _resolved)) {
        LOG(debug, "no options cmsg found");
        packet->options         = NULL;
        packet->options_length  = 0;
    }

    return rsource_ok;
}

static spollable*
_source_pollable (
    BTH ssource*                        source
) { return &(source->ss.runtime.pollable); }

static inline void
_sink_rtlink_handler (
    BTH srtlink_listener*               listener,
    BTH ssink*                          sink,
        uint32_t                        flags
) {
    switch (rtlink_listener_state(listener)) {
        case ertlink_state_removed:
            _sink_stop(sink);
            break;

        default:
            if (0 != (FRTLINK_NOTIFY_INDEX & flags) )
                if (0 == (FRTLINK_NOTIFY_INDEX_RELAXED & flags))
                    _sink_stop(sink);

            _sink_start(sink);
            break;
    }
}

static void
_sink_rtlink_handler_simple (
    BTH srtlink_listener*               listener,
        uint32_t                        flags
) {
    ssink* _sink = CONTAINEROF(listener, ssink, ts.simple.device.runtime);
    _sink_rtlink_handler(listener, _sink, flags);
}

static void
_sink_rtlink_handler_join (
    BTH srtlink_listener*               listener,
        uint32_t                        flags
) {
    ssink* _sink = CONTAINEROF(listener, ssink, ts.join.runtime.device);
    _sink_rtlink_handler(listener, _sink, flags);
}

static void
_source_rtlink_handler (
    BTH srtlink_listener*               listener,
        uint32_t                        flags
) {
    ssource* _source = CONTAINEROF(listener, ssource, ss.runtime.device);

    switch (rtlink_listener_state(listener)) {
        case ertlink_state_removed:
            source_stop(_source);
            break;

        default:
            if (0 != (FRTLINK_NOTIFY_INDEX & flags) )
                if (0 == (FRTLINK_NOTIFY_INDEX_RELAXED & flags))
                    source_stop(_source);

            source_start(_source);
            break;
    }
}

static rsource
_sink_stop (
    BTH ssink*                          sink
);

static rsource
_sink_start (
    BTH ssink*                          sink
) {
    if (! SOCKET_INVALID_IS(sink->socket)) return rsource_ok;

    const char* _device = NULL;

    switch (sink->type) {
        case esink_type_simple:
            _device = rtlink_listener_device_name(&(sink->ts.simple.device.runtime));
            break;

        case esink_type_join:
            _device = rtlink_listener_device_name(&(sink->ts.join.runtime.device));
            break;
    }

    if SOCKET_INVALID_IS(sink->socket = socket_raw(sink->flg_socket, _device))
        return rsource_failed;

    if (0 != (FSINK_REWRITE_FWMARK & sink->fwmark))
        if (rsocket_ok != socket_fwmark_set(sink->socket, sink->fwmark))
            goto _failed_close;

    return rsource_ok;

    _failed_close:
        _sink_stop(sink);
        return rsource_failed;
}

static rsource
_sink_stop (
    BTH ssink*                          sink
) {
    if SOCKET_INVALID_IS(sink->socket) return rsource_ok;

    socket_close(sink->socket);
    sink->socket = SOCKET_INVALID;

    return rsource_ok;
}

static device_mtu_t
_sink_mtu (
    IN  ssink*                          sink
) {
    if (0 != (FSINK_REWRITE_MTU & sink->rewrite))
        return sink->mtu;

    switch (sink->type) {
        case esink_type_simple:
            return rtlink_listener_mtu(&(sink->ts.simple.device.runtime));

        case esink_type_join:
            return rtlink_listener_mtu(&(sink->ts.join.runtime.device));
    }

    LOG(critical, "_sink_mtu wrong sink type, check code");
    return ipv4_unknown_mtu();
}


static rsource
_source_relay_sink_ip_options_copy (
    BTH sipv4_option_cursor*            destination,
    IN  ssink*                          sink,
    BTH _ssource_udp_packet*            packet,
        uint8_t                         mask
) {
    sipv4_option_iterator _iterator;
    ipv4_option_iterator(&_iterator, packet->options, packet->options_length);

    LOG(debug, "iterating over received options");
    
    while (ripv4_ok == ipv4_option_next(&_iterator)) {
        uint8_t _type; 

        if (ripv4_ok != ipv4_option_type(&_type, &_iterator))
            return rsource_failed;

        LOG(debug, "option %d found", (int)_type);

        if (IPV4_OPTION_ID_EOOL     == _type)
            break;

        if (IPV4_OPTION_ID_NOP      == _type)
            continue;

        if (IPV4_OPTION_ID_SECURITY == _type)
            if (0 != (FSINK_REWRITE_SECURITY & sink->rewrite))
                continue;
        
        if (mask != (FIPV4_OPTION_COPY & _type))
            continue;
   
        if (ripv4_ok != ipv4_option_copy(destination, &_iterator))
            return rsource_failed;

        LOG(debug, "^ copied");
    }

    return rsource_ok;
}

static rsource
_source_relay_sink_ip_options (
    IN  ssink*                          sink,
    BTH _ssource_udp_packet*            packet,
    OUT void*                           options,
        size_t*                         length,
        ubyte_t**                       fragments
) {
    sipv4_option_cursor _cursor;
    ipv4_option_cursor(&_cursor, options, IPV4_MAX_OPTIONS_LENGTH);

    if (0 != (FSINK_REWRITE_SECURITY & sink->rewrite)) {
        if (0 == (FSINK_REWRITE_SECURITY_DROP & sink->rewrite)) {
            LOG(debug, "rewriting security");

            if (ripv4_ok != ipv4_security_option(&_cursor, sink->security_level, sink->security_categories)) {
                LOG(error, "can't fill ip security option");
                return rsource_failed;
            }
        }

        (*fragments) = ipv4_option_cursor_position(&_cursor);
    }

    if (0 == (FSINK_REWRITE_NO_IP_OPTIONS & sink->rewrite))
        if (NULL != packet->options) {
            if (rsource_ok != _source_relay_sink_ip_options_copy(&_cursor, sink, packet, FIPV4_OPTION_COPY  ))
                LOG(debug, "^ failed");

            (*fragments) = ipv4_option_cursor_position(&_cursor);

            if (rsource_ok != _source_relay_sink_ip_options_copy(&_cursor, sink, packet, 0                  ))
                LOG(debug, "^ failed");
        }

    if (ripv4_ok != ipv4_option_cursor_close(&_cursor)) {
        LOG(debug, "can't close cursor");
        return rsource_failed;
    }

    (*length) = (sizeof(struct iphdr) + ipv4_option_cursor_used(&_cursor));
    return rsource_ok;
}

static rsource
_source_relay_sink_send (
    IN  ssink*                          sink,
    BTH _ssource_udp_packet*            packet,
        struct sockaddr_in*             target
) {
    //----- first, fast check mtu
    uint32_t _mtu_sink = _sink_mtu(sink);

    ubyte_t  _ip_options[IPV4_MAX_OPTIONS_LENGTH];
    ubyte_t* _ip_fragments = _ip_options;  

    size_t   _ip_hlength   = sizeof(struct iphdr); //in 32bits

    if (rsource_ok != _source_relay_sink_ip_options(sink, packet, &_ip_options, &_ip_hlength, &_ip_fragments)) {
        LOG(error, "can't fill ip options");
        return rsource_failed;
    }

    LOG_BINARY(debug, _ip_options, _ip_hlength - sizeof(struct iphdr), "starting with ip options");

    LOG(debug, "sink %p: mtu is %"PRIu32, sink, (uint32_t)_mtu_sink);

    if (_mtu_sink <= (_ip_hlength + sizeof(struct udphdr))) {
        LOG(error, "sink %p: mtu too small to fit atleast headers", sink);
        LOG(warning, " ^ increase mtu to atleast %"PRIu32, (uint32_t)(_ip_hlength + sizeof(struct udphdr)));

        return rsource_failed;
    }

    uint32_t _mtu = (_mtu_sink - (_ip_hlength + sizeof(struct udphdr)));

    if (packet->length > _mtu)
        if (0 != (FSINK_REWRITE_NO_FRAGMENT & sink->rewrite)) {
            LOG(verbose, "sink: %p message rejected, cuz' fragmentation required", sink);

            if (0 == (FSINK_REWRITE_NO_ICMP_FRAGMENTATION & sink->rewrite)) {

            }

            return rsource_ok;
        }

    //----- restore sink's socket
    if (rsource_ok != _sink_start(sink)) {
        LOG(verbose, "sink: %p can't start sink", sink);
        return rsource_failed;
    }

    //----- resolve source address
    ipv4_t   _from_address = packet->from.sin_addr.s_addr;
    uint16_t _from_port    = packet->from.sin_port;

    if (0 != (FSINK_REWRITE_FROM & sink->rewrite)) {
        _from_address = sink->from.address;

        if (0 != (sink->from.port))
            _from_port = sink->from.port;
    }

    //----- fill headers
    struct iphdr  _iphdr;
    struct udphdr _udphdr;

    htons_unaligned(&(_iphdr.check),  0); //calculate by kernel
    htons_unaligned(&(_udphdr.check), 0); //calculate by kernel

    _iphdr.version  = 4;
    _iphdr.protocol = IPPROTO_UDP;

    uint16_t _ip_id = packet->id;

    if (0 != (FSINK_REWRITE_NO_IP_ID & sink->rewrite)) {
        _ip_id = htons(sink->last_ip_id);

        if (0 == (++(sink->last_ip_id)))
            sink->last_ip_id = 1;
    }

    u16_unaligned(&(_iphdr.id), _ip_id);

    if (0 != (FSINK_REWRITE_TOS & sink->rewrite)) {
        _iphdr.tos = sink->tos;
    } else {
        _iphdr.tos = packet->tos;
    }

    if (0 != (FSINK_REWRITE_TTL & sink->rewrite)) {
        if (0 == (_iphdr.ttl = sink->ttl))
            if (rsysctl_ok != ipv4_default_ttl(&(_iphdr.ttl))) {
                LOG(error, "sink: %p can't resolve system's default ttl", sink);
                return rsource_failed;
            }

    } else {
        uint8_t _ttl = packet->ttl;

        if (_ttl < 2) {
            LOG(verbose, "sink: %p message rejected due to low ttl", sink);

            if (0 == (FSINK_REWRITE_NO_ICMP_TTL & sink->rewrite)) {

            }

            return rsource_ok; //this isn't failure
        }

        _iphdr.ttl = (_ttl - 1);
    }

    u32_unaligned(  &(_iphdr.saddr),    _from_address                                               );
    u16_unaligned(  &(_udphdr.source),  _from_port                                                  );

    u32_unaligned(  &(_iphdr.daddr),    target->sin_addr.s_addr                                     );
    u16_unaligned(  &(_udphdr.dest),    target->sin_port                                            );

    htons_unaligned(&(_iphdr.tot_len),  (_ip_hlength + sizeof(struct udphdr) + packet->length)      );
    htons_unaligned(&(_udphdr.len),     (sizeof(_udphdr) + packet->length)                          );

    //----- sending fragmented[if needed] packet
    ubyte_t* _buffer   = packet->buffer;
    size_t   _length   = packet->length;
    uint16_t _offset   = 0;
    size_t   _overhead = 0;

    LOG(verbose, "sink %p: sending from "IPV4_PRIADDR":%"PRIu16" to "IPV4_PRIADDR":%"PRIu16, sink, 
            IPV4_DPRIADDR(_from_address), htons(_from_port)
        ,   IPV4_DPRIADDR(target->sin_addr.s_addr), htons(target->sin_port)
    );
    
    _iphdr.ihl = (_ip_hlength >> 2);

    do { //if packet have zero size, we anyway should send it
        #define __LOG_FRAGMENT()    \
            LOG(debug, "sending fragment %10"PRIu32" [%6"PRIu32" = data %6"PRIu32" + head %3"PRIu32"]", (uint32_t)(_offset), (uint32_t)(_ip_hlength + sizeof(_udphdr) + _sending), (uint32_t)_sending, (uint32_t)(_ip_hlength + sizeof(_udphdr)))

        uint16_t _flags   = 0x0;
        size_t   _sending = (_length > _mtu)?_mtu:_length;

        _overhead += (_ip_hlength + sizeof(_udphdr));

        if (0 == (_length - _sending)) {
            if (0 == _offset) {
                if (0 != (FSINK_REWRITE_NO_FRAGMENT & sink->rewrite))
                    _flags  |= IP_DONTFRAGMENT;

            } else {
                __LOG_FRAGMENT();
            }

        } else {
            /*  cuz' we do fragmentation, we must align sended data to 8 bytes boundary
                just zero last 3 bits and set IP_FRAGMENT flag  */

            _flags   |= IP_FRAGMENT;
            _sending &= ~0x07;

            __LOG_FRAGMENT();
        }

        htons_unaligned(&(_iphdr.frag_off), (uint16_t)((_flags & IP_FLAGS) | ((_offset >> 3) & IP_OFFSET)));

        struct iovec   _iov[] = {{ &_iphdr, sizeof(_iphdr) }, { _ip_options, (_ip_hlength - sizeof(struct iphdr))}, { &_udphdr, sizeof(_udphdr) }, { _buffer, _sending }};
        struct msghdr  _msg   = { target, sizeof(*target), _iov, 4, NULL, 0, 0 };

        FOREVER {
            int _r_sendto = sendmsg(sink->socket, &_msg, 0);

            if (0 > _r_sendto) {
                if EINTR_IS(errno) continue; 

                LOG(error, "sendto failed cuz' %d [%s]", errno, strerror(errno));

                switch (errno) {
                    case EPERM:
                        LOG(warning, "... may be you want to remove \"no broadcast\" option");
                        break;

                    case EMSGSIZE:
                        LOG(warning, "... may be you want to use \"mtu\" option");
                        break;

                    default:
                        _sink_stop(sink);
                        break;
                }

                return rsource_failed;
            }

            break;
        }

        if ((0 == _offset) && (0 != (_flags & IP_FRAGMENT)) && (_ip_fragments != _ip_options)) {
            //first fragment sended, correct mtu space and ip header length       
            if (ripv4_ok != ipv4_option_padding(_ip_options, sizeof(_ip_options), &_ip_fragments)) {
                LOG(debug, "can't pad fragment's options");
                return rsource_failed;
            }

            _ip_hlength = (sizeof(struct iphdr) + (_ip_fragments - _ip_options));
            _mtu        = (_mtu_sink - (_ip_hlength + sizeof(struct udphdr)));
            _iphdr.ihl  = (_ip_hlength >> 2);

            LOG_BINARY(debug, _ip_options, _ip_hlength - sizeof(struct iphdr), "first fragment sended, ip options recalculated");
        }

        /** ok, we send fragment, so strafe agains buffer **/
        _length -= _sending;
        _offset += _sending;
        _buffer += _sending;

    } while (_length > 0);

    LOG(verbose, "sink: %p relayed, overhead %"PRIu32" bytes", sink, (uint32_t)_overhead);
    return rsource_ok;
}

static rsource
_source_relay_sink (
    IN  ssink*                          sink,
    BTH _ssource_udp_packet*            packet,
        uint16_t                        port
) {
    if (ripv4_ok != ipv4_portrange_check(sink->portrange, ntohs(packet->destination.port))) {
        LOG(verbose, "sink: %p rejected by port-range", sink);
        return rsource_ok;
    }

    switch (sink->type) {
        case esink_type_simple: {
            struct sockaddr_in  _target;
            _target.sin_family      = AF_INET;
            _target.sin_port        = port;

            if (0 == (FSINK_REWRITE_DESTINATION_ORIGINAL & sink->rewrite)) {
                _target.sin_addr.s_addr = sink->ts.simple.target.address;
            } else {
                _target.sin_addr.s_addr = packet->destination.address;
            }

            return _source_relay_sink_send(sink, packet, &_target);
        }

        case esink_type_join: {
            rsource _return = rsource_failed;

            //now we should check all addresses agains
            for (srtlink_device_address* _address = rtlink_listener_address(&(sink->ts.join.runtime.device)); NULL != _address; _address = rtlink_device_address_next(_address)) {
                if (ripv4_ok == ipv4_address_in_network(packet->destination.address, &(_address->network))) {
                    LOG(verbose, "sink: rejected loop in %p", sink);
                    _return = rsource_ok;
                    continue;
                }

                struct sockaddr_in  _target;
                _target.sin_family      = AF_INET;
                _target.sin_addr.s_addr = _address->broadcast;
                _target.sin_port        = port;

                if (rsource_ok != _source_relay_sink_send(sink, packet, &_target)) {
                    LOG(verbose, "sink: relay failed %p", sink);
                    continue;
                }

                _return = rsource_ok;
            }

            return _return;
        }
    }

    return rsource_failed;
}

static rsource
_source_relay_sink_allowed (
    IN  ssink*                          sink,
    BTH _ssource_udp_packet*            packet
) {
    if (NULL != sink->allow) {
        if (ripv4_ok != ipv4_allow_allowed_is(sink->allow, packet->from.sin_addr.s_addr, &(packet->destination))) {
            LOG(verbose, "sink: rejected by allow in %p", sink);
            return rsource_failed;
        }

        return rsource_ok;
    }

    switch (sink->type) {
        case esink_type_simple:
            if (0 == (FSINK_REWRITE_DESTINATION_ORIGINAL & sink->rewrite))
                if (ripv4_ok == ipv4_address_in_network(packet->destination.address, &(sink->ts.simple.target))) {
                    LOG(verbose, "sink: rejected loop in %p", sink);
                    return rsource_failed;
                }

            return rsource_ok;

        case esink_type_join:
            //KIM: will be checked in _source_relay_sink while iterating via addresses
            return rsource_ok;
    }

    return rsource_failed;
}

static rsource
_source_relay (
    BTH ssource*                        source,
    BTH _ssource_udp_packet*            packet,
    BTH spoll_passthrou*                passthrou
) {
    //now, as packet allowed, we should check for ratelimit
    if (NULL != source->ratelimit)
        if (rratelimit_allowed != ratelimit(source->ratelimit, 1, &(passthrou->time))) {
            LOG(verbose, "source: %p rejected by rate-limit", source); //TODO(iybego#0): protect itself with ratelimit and change to warning
            return rsource_ok;
        }

    for (ssink* _target = source->sinks; NULL != _target; _target = _target->next) {
        if (rsource_ok != _source_relay_sink_allowed(_target, packet))
            continue;

        uint16_t _port = _target->port;

        if (0 == _port)
            _port = packet->destination.port;

        if (0 == _port)
            _port = source->port;

        if (0 == _port) {
            LOG(warning, "sink: %p left port unresolved!");
            continue;
        }

        if (rsource_ok != _source_relay_sink(_target, packet, _port))
            LOG(verbose, "sink: %p relay failed", source);
    }

    return rsource_ok;
}

static rsource
_source_proceed_listener_addresses (
    BTH ssource*                        source,
    BTH _ssource_udp_packet*            packet,
    BTH spoll_passthrou*                passthrou,
    BTH srtlink_listener*               listener
) {
    for (srtlink_device_address* _address = rtlink_listener_address(listener); NULL != _address; _address = rtlink_device_address_next(_address)) {
        LOG(debug, "... network "IPV4_PRIADDR"/"IPV4_PRIADDR, IPV4_DPRIADDR(_address->network.address), IPV4_DPRIADDR(_address->network.mask));

        if (ripv4_ok == ipv4_address_in_network(packet->from.sin_addr.s_addr, &(_address->network))) {
            LOG(debug, "... from network");

            if (packet->destination.address == _address->broadcast) {
                LOG(debug, "... to broadcast");
                return _source_relay(source, packet, passthrou);
            }
        }
    }

    LOG(debug, "addresses iterating failed");
    return rsource_ok;
}

static rsource
_source_proceed (
    BTH ssource*                        source,
    BTH _ssource_udp_packet*            packet,
    BTH spoll_passthrou*                passthrou
) {
    if (ripv4_ok != ipv4_portrange_check(source->portrange, ntohs(packet->destination.port))) {
        LOG(verbose, "source: rejected by port-range");
        return rsource_ok;
    }

    if (NULL != source->allow) {
        if (ripv4_ok == ipv4_allow_allowed_is(source->allow, packet->from.sin_addr.s_addr, &(packet->destination)))
            return _source_relay(source, packet, passthrou);

        LOG(verbose, "source: rejected by allow");
        return rsource_ok;
    }

    //if we subscribe to multicast check if packet targeted to subscribed networks and allow it

    if (NULL != source->mgroups) {
        if (ripv4_ok == ipv4_address_in_network(packet->destination.address, &IPV4_NETWORK_ALL_MULTICAST))
            for (smgroup* _mgroup = source->mgroups; NULL != _mgroup; _mgroup = _mgroup->next)
                if (_mgroup->group == packet->destination.address) {
                    LOG(debug, "source: accepted by m-group "IPV4_PRIADDR, IPV4_DPRIADDR(_mgroup->group));
                    return _source_relay(source, packet, passthrou);
                }
    }

    //if no allow declaration avalible we must use sinks as allow list:
    //  find allowed networks and check for martians packets - ...
    //  ... packets wich received from non-connected network
    // but if we binded to device, we can check only its addresses

    if RTLINK_LISTENER_ATTACHED(&(source->ss.runtime.device)) {
        if (rsource_ok != _source_proceed_listener_addresses(source, packet, passthrou, &(source->ss.runtime.device)))
            return rsource_failed;

        LOG(verbose, "source: rejected martian");
        return rsource_ok;
    }

    if (ripv4_ok == ipv4_address_in_network(packet->from.sin_addr.s_addr, &(source->binding)))
        for (ssink* _sink = source->sinks; NULL != _sink; _sink = _sink->next)
            switch (_sink->type) {
                case esink_type_simple:
                    //if sink is simple, use its target itself as allow

                    LOG(debug, "sink "IPV4_PRIADDR"/"IPV4_PRIADDR, IPV4_DPRIADDR(_sink->ts.simple.target.address), IPV4_DPRIADDR(_sink->ts.simple.target.mask));

                    if (ripv4_ok == ipv4_address_in_network(packet->from.sin_addr.s_addr, &(_sink->ts.simple.target))) {
                        LOG(debug, "... from network");

                        if (packet->destination.address == ipv4_network_broadcast(&(_sink->ts.simple.target))) {
                            LOG(debug, "... to broadcast");
                            return _source_relay(source, packet, passthrou);
                        }
                    }

                    break;

                case esink_type_join:
                    LOG(debug, "join, checking addresses");

                    if (rsource_ok != _source_proceed_listener_addresses(source, packet, passthrou, &(_sink->ts.join.runtime.device)))
                        return rsource_failed;

                    break;
            }

    LOG(verbose, "source: rejected by sinks");
    return rsource_ok;
}

static rpoll_handler
_source_poll_handler_simple (
    BTH ssource*                        source,
    BTH spollable*                      pollable,
    BTH spoll_passthrou*                passthrou
) {
    LOG(debug, "source simple %p", source);

    for (size_t _current_packet_per_tick = SOURCE_MAX_PACKETS_PER_TICK; _current_packet_per_tick--; ) {
        _ssource_udp_packet _packet;

        char                _control[SOURCE_SIMPLE_CONTROL_LENGTH];

        struct iovec        _iov = {passthrou->buffer, passthrou->length};
        struct msghdr       _msg = { &(_packet.from), sizeof(_packet.from), &_iov, 1, _control, sizeof(_control), 0};

        int _length = recvmsg(pollable_socket(pollable), &_msg, (MSG_DONTWAIT | MSG_TRUNC | MSG_CTRUNC));

        if (0  > _length) {
            if EINTR_IS      (errno) continue;

            if EWOULDBLOCK_IS(errno) return rpoll_handler_ok;
            if EAGAIN_IS     (errno) return rpoll_handler_ok;

            LOG(error, "recvmsg failed, cuz' %d [%s]", errno, strerror(errno));
            return rpoll_handler_failed;
        }

        if (0 != _msg.msg_flags) {
            if (0 != (_msg.msg_flags & MSG_CTRUNC)) {
                LOG(error, "control truncated, please check SOURCE_SIMPLE_CONTROL_LENGTH constant!");
            }

            if (0 != (_msg.msg_flags & MSG_TRUNC)) {
                LOG(warning, "message truncated! increase buffer size to %d [at least]", _length);
                continue;
            }
        }

        if (rsource_ok != _control_information(&_msg, &_packet)) {
            LOG(error, "message ignored, cuz' unable to resolve required control information");
            continue;
        }

        LOG(verbose, "simple: %p received %d bytes, from "IPV4_PRIADDR":%"PRIu16" to "IPV4_PRIADDR":%"PRIu16
            , source, _length, IPV4_DPRIADDR(_packet.from.sin_addr.s_addr), ntohs(_packet.from.sin_port)
            , IPV4_DPRIADDR(_packet.destination.address), ntohs(_packet.destination.port)
        );

        _packet.id              = 0;
        _packet.buffer          = passthrou->buffer;
        _packet.length          = (unsigned)_length;

        if (rsource_ok != _source_proceed(source, &_packet, passthrou))
            return rpoll_handler_failed;
    }

    LOG(verbose, "simple: %p packet per tick limit exceeded", source);
    return rpoll_handler_ok;
}

static rpoll_handler
_source_poll_handler_raw (
    BTH ssource*                        source,
    BTH spollable*                      pollable,
    BTH spoll_passthrou*                passthrou
) {
    for (size_t _current_packet_per_tick = SOURCE_MAX_PACKETS_PER_TICK; _current_packet_per_tick--; ) {
        _ssource_udp_packet _packet;

        struct iovec        _iov = {passthrou->buffer, passthrou->length};
        struct msghdr       _msg = { &(_packet.from), sizeof(_packet.from), &_iov, 1, NULL, 0, 0};

        int _length = recvmsg(pollable_socket(pollable), &_msg, (MSG_DONTWAIT | MSG_TRUNC));

        if (0  > _length) {
            if EINTR_IS      (errno) continue;
            if EWOULDBLOCK_IS(errno) return rpoll_handler_ok;
            if EAGAIN_IS     (errno) return rpoll_handler_ok;

            LOG(error, "recvmsg failed, cuz' %d [%s]", errno, strerror(errno));
            return rpoll_handler_failed;
        }

        if (0 != _msg.msg_flags)
            if (0 != (_msg.msg_flags & MSG_TRUNC)) {
                LOG(warning, "message truncated! increase buffer size to %d [at least]", _length);
                continue;
            }

        //this is little paranoic, cuz' system must not send packet to userspace if it broken
        // but it add so small overhead, so i don't remove it
        if (20 > _length) {
            LOG(error, "data too small to be packet");
            continue;
        }

        struct iphdr* _iphdr = (struct iphdr*)passthrou->buffer;

        if (unaligned_htons(&(_iphdr->tot_len)) != _length) {
            LOG(error, "wrong packet size");
            continue;
        }

        if (5 > _iphdr->ihl) {
            LOG(error, "wrong ihl value %u", (unsigned int)_iphdr->ihl);
            continue;
        }

        _packet.options         = NULL;
        _packet.options_length  = 0;

        if (5 < _iphdr->ihl)
            if (0 != (source->flg_socket & FSOCKET_RECVOPTIONS)) {
                _packet.options         = (passthrou->buffer + sizeof(struct iphdr));
                _packet.options_length  = (_iphdr->ihl - 5) * 4;
            }

        /*ubyte_t _ip_options_test[] = {0x09, 0x02, 0x09, 0x02, 0x09, 0x02, 0x09, 0x02, 0x09, 0x20, 0x09, 0x02};
        _packet.options         = _ip_options_test;
        _packet.options_length  = sizeof(_ip_options_test);
        */

        size_t _shift = (_iphdr->ihl * 4);

        if ((unsigned)_length < (_shift + sizeof(struct udphdr))) {
            LOG(error, "udp header doesn't fit to buffer");
            continue;
        }

        struct udphdr* _udphdr = (struct udphdr*)(passthrou->buffer + _shift);

        uint16_t _udphdr_length = unaligned_htons(&(_udphdr->len));

        if (sizeof(struct udphdr) > _udphdr_length) {
            LOG(error, "wrong udp length");
            continue;
        }

        if ((unsigned)_length < (_shift + _udphdr_length - sizeof(struct udphdr))) {
            LOG(error, "udp data doesn't fit to buffer");
            continue;
        }

        _shift += sizeof(struct udphdr);

        _packet.buffer = passthrou->buffer + _shift;
        _packet.length = _length - _shift;

        _packet.id     = unaligned_u16(&(_iphdr->id));

        _packet.tos    = _iphdr->tos;
        if (0 == (source->flg_socket & FSOCKET_RECVTOS))
            _packet.tos = 0x00;

        _packet.ttl    = _iphdr->ttl;
        if (0 == (source->flg_socket & FSOCKET_RECVTTL))
            if (rsysctl_ok != ipv4_default_ttl(&(_packet.ttl))) {
                LOG(error, "receiving of ttl disabled, but default ttl resolving failed");
                continue;
            }

        _packet.destination.address = unaligned_u32(&(_iphdr->daddr));
        _packet.destination.port    = unaligned_u16(&(_udphdr->dest));

        //this is strange, but we should fix it
        if (0 == _packet.from.sin_addr.s_addr)
            _packet.from.sin_addr.s_addr = unaligned_u32(&(_iphdr->saddr));

        if (0 == _packet.from.sin_port)
            _packet.from.sin_port = unaligned_u16(&(_udphdr->source));

        if (AF_INET != _packet.from.sin_family)
            _packet.from.sin_family = AF_INET;

        LOG(verbose, "raw: %p received %d bytes, from "IPV4_PRIADDR":%"PRIu16" to "IPV4_PRIADDR":%"PRIu16
            , source, _length, IPV4_DPRIADDR(_packet.from.sin_addr.s_addr), ntohs(_packet.from.sin_port)
            , IPV4_DPRIADDR(_packet.destination.address), ntohs(_packet.destination.port)
        );

        if (rsource_ok != _source_proceed(source, &_packet, passthrou))
            return rpoll_handler_failed;
    }

    LOG(verbose, "raw: %p packet per tick limit exceeded", source);
    return rpoll_handler_ok;
}

static rpoll_handler
_source_poll_handler (
    BTH spollable*                      pollable,
        uint32_t                        flags,
    BTH spoll_passthrou*                passthrou
) {
    ssource* _source = CONTAINEROF(pollable, ssource, ss.runtime.pollable);

    if (0 != (flags & (FPOLLABLE_ERR | FPOLLABLE_HUP))) {
        LOG(verbose, "source %p failed", _source);
        source_stop(_source);
        return rpoll_handler_ok;
    }

    switch (_source->type) {
        case esource_type_simple:
            return _source_poll_handler_simple(_source, pollable, passthrou);

        case esource_type_raw:
            return _source_poll_handler_raw(_source, pollable, passthrou);
    }

    return rpoll_handler_failed;
}

rsource
source_start (
    BTH ssource*                        source
) { 
    if (rsource_ok == source_state(source))
        return rsource_ok;

    LOG(verbose, "starting source %p", source);

    socket_t _socket = SOCKET_INVALID;

    switch (source->type) {
        case esource_type_simple: {
            struct sockaddr_in _binding;
            _binding.sin_family      = AF_INET;
            _binding.sin_port        = source->port;
            _binding.sin_addr.s_addr = source->binding.address;

            LOG(debug, IPV4_PRIADDR":%d", IPV4_DPRIADDR(source->binding.address), (int)ntohs(source->port));

            _socket = socket_open (
                    source->flg_socket
                ,   (struct sockaddr*)&_binding
                ,   rtlink_listener_device_name(&(source->ss.runtime.device))
            );

            break;
        }

        case esource_type_raw: {
            _socket = socket_raw(source->flg_socket, rtlink_listener_device_name(&(source->ss.runtime.device)));
            break;
        }
    }

    if SOCKET_INVALID_IS(_socket) {
        LOG(verbose, "source socket restarting failed"); 
        return rsource_failed;
    }

    for (smgroup* _mgroup = source->mgroups; NULL != _mgroup; _mgroup = _mgroup->next) 
        if (rsocket_ok != socket_mgroup_join(_socket, _mgroup->group, source->binding.address, rtlink_listener_index(&(source->ss.runtime.device)))) {
            LOG(verbose, "can't join multicast group");
            socket_close(_socket);
            return rsource_failed;
        }

    pollable_socket_set(_source_pollable(source), _socket);

    if (rpoll_ok != poll_attach(_source_pollable(source))) {
        LOG(verbose, "can't add source to poll");

        socket_close(_socket);
        pollable_socket_set(_source_pollable(source), SOCKET_INVALID);
        return rsource_failed;
    }

    LOG(verbose, "source %p alive", source);

    return rsource_ok;
}

rsource
source_stop (
    BTH ssource*                        source
) {
    if (rsource_ok != source_state(source))
        return rsource_ok;

    LOG(verbose, "stoping source %p", source);

    if (rpoll_ok != poll_detach(_source_pollable(source)))
        return rsource_failed;

    socket_close(pollable_socket(_source_pollable(source)));

    pollable_socket_set(_source_pollable(source), SOCKET_INVALID);
    return rsource_ok;
}

rsource
source_state (
    BTH ssource*                source
) {
    if SOCKET_INVALID_IS(pollable_socket(_source_pollable(source)))
        return rsource_failed;

    return rsource_ok;
}

static void
_sinks_cleanup (
    BTH ssource*                        source,
    BTH ssink*                          until
) {
    for (ssink* _sink = source->sinks; _sink != until; _sink = _sink->next) {
        if (rsource_ok != _sink_stop(_sink))
            LOG(error, "can't stop sink while cleanup");

        switch (_sink->type) {
            case esink_type_simple:
                if (rnetlink_ok != rtlink_listener_detach(&(_sink->ts.simple.device.runtime)))
                    LOG(error, "can't detach listener while cleaning up");

                break;

            case esink_type_join:
                if (rnetlink_ok != rtlink_listener_detach(&(_sink->ts.join.runtime.device)))
                    LOG(error, "can't detach listener while cleaning up");

                break;
        }
    }
}

static rsource
_source_bootup (
    BTH ssource*                        source,
    BTH srtlink*                        rtlink,
    BTH spoll*                          poll
) {
    LOG(verbose, "bootup source %p", source);

    if (rnetlink_ok != rtlink_listener_attach(&(source->ss.runtime.device), rtlink, source->ss.configuration.device, _source_rtlink_handler))
        return rsource_failed;

    pollable_initialize(_source_pollable(source), poll, _source_poll_handler, SOCKET_INVALID, FPOLLABLE_IN);

    //bootup sinks
    for (ssink* _sink = source->sinks; NULL != _sink; _sink = _sink->next)
        switch (_sink->type) {
            case esink_type_simple:
                if (rnetlink_ok != rtlink_listener_attach(&(_sink->ts.simple.device.runtime), rtlink, _sink->ts.simple.device.configuration, _sink_rtlink_handler_simple)) {
                    _sinks_cleanup(source, _sink);
                    return rsource_failed;
                }

                break;

            case esink_type_join: {
                if (rnetlink_ok != rtlink_listener_attach(&(_sink->ts.join.runtime.device), rtlink, _sink->ts.join.configuration.device, _sink_rtlink_handler_join)) {
                    _sinks_cleanup(source, _sink);
                    return rsource_failed;
                }

                break;
            }
        }

    return rsource_ok;
}

static rsource
_source_cleanup (
    BTH ssource*                        source
) {
    LOG(verbose, "cleanup source %p", source);

    rtlink_listener_detach(&(source->ss.runtime.device));
    pollable_clear(_source_pollable(source));
    _sinks_cleanup(source, NULL);

    return rsource_ok;
}

rsource
sources_cleanup (
    BTH ssource*                        source,
        ssource*                        until
) {
    for (ssource* _current = source; until != _current; _current = _current->next) {
        if (rsource_ok != source_stop(_current)) {
            LOG(critical, "source stop failed, ignored");
        }

        if (rsource_ok != _source_cleanup(_current)) {
            LOG(critical, "source cleanup failed, ignored");
        }
    }

    return rsource_ok;
}

rsource
sources_restart (
    BTH ssource*                source
) {
    LOG(debug, "restarting sources");

    for (ssource* _current = source; NULL != _current; _current = _current->next)
        if (rsource_ok != source_restart(_current)) {
            LOG(verbose, "source restart failed, ignored");
        }

    return rsource_ok;
}

rsource 
sources_start (
    BTH ssource*                source
) {
    for (ssource* _current = source; NULL != _current; _current = _current->next)
        if (rsource_ok != source_start(_current)) {
            LOG(verbose, "source start failed, ignored");
        }

    return rsource_ok;
}

rsource
sources_bootup (
    BTH ssource*                        source,
    BTH srtlink*                        rtlink,
    BTH spoll*                          poll
) {
    for (ssource* _current = source; NULL != _current; _current = _current->next)
        if (rsource_ok != _source_bootup(_current, rtlink, poll)) {
            LOG(error, "can't bootup all sources, rollback");
            sources_cleanup(source, _current);
            return rsource_failed;
        }

    return rsource_ok;
}

