/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#include "ipv4.h"

#include "log.h"

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

LOG_MODULE("ipv4");

const sipv4_network IPV4_NETWORK_ALL_MULTICAST = IPV4_NETWORK(224,  0,  0,  0,  4);
const sipv4_network IPV4_NETWORK_ANY           = IPV4_NETWORK(0,    0,  0,  0,  0);
const sipv4_network IPV4_NETWORK_BROADCAST     = IPV4_NETWORK(255,255,255,255, 32);

ripv4
ipv4_allow_allowed_is (
    IN  const sipv4_allow*          allow,
        ipv4_t                      from,
        sipv4_destination*          destination
) {
    uint16_t _port = ntohs(destination->port);

    for (const sipv4_allow* _current = allow; _current != NULL; _current = _current->next)
        if (ripv4_ok == ipv4_address_in_network(from, &(_current->address))) {
            if (NULL != _current->allow_to) {
                for (const sipv4_allow_to* _to = _current->allow_to; NULL != _to; _to = _to->next)
                    if (ripv4_ok == ipv4_address_in_network(destination->address, &(_to->address)))
                        return ipv4_portrange_check(_to->portrange, _port);

                continue;
            }

            //recalculate broadcast from network
            if (destination->address == ipv4_network_broadcast(&(_current->address)))
                return ripv4_ok;

            return ripv4_failed;
        }

    return ripv4_failed;
}

SYSCTL_WRAPPER_IMPLEMENT(ipv4_default_ttl,      u8,     "net.ipv4.ip_default_ttl"     );
SYSCTL_WRAPPER_IMPLEMENT(ipv4_minimum_pmtu,     u32,    "net.ipv4.route.min_pmtu"     );


