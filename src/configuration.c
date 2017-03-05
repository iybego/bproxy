/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#include "configuration.h"
#include "log.h"
#include "utils.h"

#include <inttypes.h>
#include <string.h>
#include <getopt.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netdb.h>

LOG_MODULE("configuration");

typedef
struct _configuration_opts sconfiguration_opts;

struct _configuration_opts {
    char*                   name;
    size_t                  name_length;

    char*                   value;
    size_t                  value_length;

    sconfiguration_opts*    next;
};

static void
configuration_help (
        const char*                   self
) {
    LOG(information, "bproxy, version " VERSION);
    LOG(information, "");
    LOG(information, "Usage: %s", self);
    LOG(information, "   --configuration | -c <file>    - specify configuration file");
    LOG(information, "   --log           | -l <file>    - specify log file");
    LOG(information, "   --directory     | -d <dir>     - specify working directory");
    LOG(information, "");
    LOG(information, "   --version       | -v           - show this help");
    LOG(information, "   --usage         | -u           - show this help");
    LOG(information, "   --help          | -h           - show this help");
    LOG(information, "");
    LOG(information, "   --debug                        - enable debug logging");
    LOG(information, "   --verbose                      - enable verbose logging");
    LOG(information, "   --silent                       - disable verbose logging");
    LOG(information, "   --log-no-date                  - do not output date to log");
    LOG(information, "");
    LOG(information, "   --define        | -Dname=value - define variable <name> with <value>");
    LOG(information, "");
    LOG(information, "Syntax:");
    LOG(information, "   All lines: option <spacing> \"value\"");
    LOG(information, "      within string block, \"{variable}\" will be replace with <value>");
    LOG(information, "");
    LOG(information, "   Commentary starts from # to end of line");
    LOG(information, "");
    LOG(information, "Configuration file, options:");
    LOG(information, "   log         [filename]                - output log to file");
    LOG(information, "   directory   [directory]               - change working directory");
    LOG(information, "");
    LOG(information, "   include     [filename]               *- include options from file");
    LOG(information, "   let         VARIABLE=VALUE           *- define $VARIABLE with VALUE");
    LOG(information, "");
    LOG(information, "   be          silent                    - disable verbose logging");
    LOG(information, "               verbose                   - enable verbose logging");
    LOG(information, "               debug                     - enable debug logging");
    LOG(information, "");
    LOG(information, "   restore     [second]                  - try to restore sources every X seconds");
    LOG(information, "   reload      [second]                  - reload devices list every X seconds");
    LOG(information, "");
    LOG(information, "   buffer      [bytes]                   - packet buffer size");
    LOG(information, "   rtlink-hash [factor]                  - rtlink hash size factor");
    LOG(information, "   events      [count]                   - epoll events buffer");
    LOG(information, "               automatic                 - determinate events size by sources count");    
    LOG(information, "");
    LOG(information, "   source      [port]                   *- start source at port");
    LOG(information, "               raw                      *- start raw source [you must specify port-range]");
    LOG(information, "");
    LOG(information, "       device     [name]                 - device binding");
    LOG(information, "       binding    [address/mask]         - address binding");
    LOG(information, "       m-group    [address]             *- subscribe to multicast group");
    LOG(information, "");
    LOG(information, "       no         broadcast              - disable broadcast");
    LOG(information, "                  reuseaddr              - disable address reusing      [have no sence for raw]");
    LOG(information, "                  transparent            - disable transparent binding  [have no sence for raw]");
    LOG(information, "                  ip-options             - disable ip options receiving");
    LOG(information, "                  ip-tos                 - disable ip tos receiving");
    LOG(information, "                  ip-ttl                 - disable ip ttl receiving");
    LOG(information, "");
    LOG(information, "       rate-limit [rate:window]          - drop packets if rate-limit exceeded [window in ms]");
    LOG(information, "       port-range [from:to]             *- allow receiving to port range");
    LOG(information, "                  any                    - synonim for 0:65535");
    LOG(information, "");
    LOG(information, "       allow      [address/mask]        *- allow receiving from network");
    LOG(information, "           to       [address/mask]      *- allow receiving to network");
    LOG(information, "              port-range [from:to]      *- allow receiving to port range");
    LOG(information, "                         any             - synonim for 0:65535");
    LOG(information, "");
    LOG(information, "     / sink       [address/mask]        *- forward address");
    LOG(information, "                  original              *- forward to original dgram address [usable for multicast]");
    LOG(information, "");
    LOG(information, "     \\ join       [device]              *- forward device");
    LOG(information, "           device   [name]               - device binding [only for sink!]");
    LOG(information, "");
    LOG(information, "           from     [address:port]       - forward from address");
    LOG(information, "                    inherit              - forward from source's binding address");
    LOG(information, "");
    LOG(information, "           port     [port]               - forward to port");
    LOG(information, "                    inherit              - force use source's port");
    LOG(information, "");
    LOG(information, "           fwmark   [value]              - set fwmark when forwarding");
    LOG(information, "           ttl      [value]              - override received ttl when forwarding");
    LOG(information, "                    default              - set ttl to system's default ttl");
    LOG(information, "");
    LOG(information, "           mtu      [value]              - override default mtu");
    LOG(information, "           tos      [value]              - override received tos when forwarding");
    LOG(information, "");
    LOG(information, "           security [level:categories]   - set ip security");
    LOG(information, "                    drop                 - remove security mark");
    LOG(information, "");
    LOG(information, "           no       route                - send only to directly connected hosts");
    LOG(information, "                    broadcast            - disable sending to broadcast addresses");
    LOG(information, "                    fragment             - disable messages fragmentation");
    LOG(information, "                    passthrou-ip-id      - rewrite IP packet id");
    LOG(information, "                    passthrou-ip-options - drop ip options from received packet");
    LOG(information, "");
    LOG(information, "           allow    [address/mask]      *- allow forwarding from network");
    LOG(information, "               to      [address/mask]   *- allow forwarding to network");
    LOG(information, "                  port-range [from:to]  *- allow receiving to port range");
    LOG(information, "                             any         - synonim for 0:65535");
    LOG(information, "");
    LOG(information, " * - can be specified many times as you need");
    LOG(information, "");
    LOG(information, " ToS [DiffServ] value can be:");
    LOG(information, "  CS0, CS1, CS2, CS3, CS4, CS5, CS6, CS7");
    LOG(information, "  AF11 - AF13, AF21 - AF23, AF31 - AF33, AF41 - AF43");
    LOG(information, "");
    LOG(information, "[address/mask] - aka \"network\", can be:");
    LOG(information, "  any       - 0.0.0.0/0");
    LOG(information, "  multicast - 224.0.0.0/4");
    LOG(information, "  broadcast - 255.255.255.255/32");
    LOG(information, "");
    LOG(information, "from's description:");
    LOG(information, "  if specified port isn't 0 it will be rewrited");
    LOG(information, "  if specified address is 0.0.0.0, address will be rewrited to");
    LOG(information, "  ... correct machine's source address");
    LOG(information, "");
    LOG(information, "Keep in mind, when you use raw source, host can generate icmp with");
    LOG(information, "  ... destination port unreachable, cuz' raw receive copy of packet");
    LOG(information, "");
    LOG(information, "Packet \"allowing to accept\" ritual:");
    LOG(information, "  if exists \"allow\"/\"allow to\" record - use it");
    LOG(information, "  if exists \"m-group\" record - accept if:");
    LOG(information, "      dgram target address equal one of \"m-group\" addresses");
    LOG(information, "  if exists \"device\" - check against it's addresses:");
    LOG(information, "      dgram source address in one of device networks");
    LOG(information, "      dgram target address equal this network broadcast");
    LOG(information, "  finally, iterate over \"sinks\"/\"joins\" and check it's networks:");
    LOG(information, "      dgram source address in one of \"sink's\"/\"join's\" networks");
    LOG(information, "      dgram target address equal this network broadcast");
    LOG(information, "");
    LOG(information, "Packet \"forward\" ritual:");
    LOG(information, "  check source's \"rate-limit\", if specified");
    LOG(information, "  iterate over \"sinks\" and \"joins\"");
    LOG(information, "      check against \"allow\"/\"allow to\" record, if exists");
    LOG(information, "      if sink - send, if dgram source NOT in sink's network");
    LOG(information, "      if join - iterate over device networks and send to it");
    LOG(information, "          ... if dgram source NOT in this address network");
    LOG(information, "");
    LOG(information, "You can use names like \"kermit\", \"netbios-ns\", etc as ports value");
    LOG(information, "");
    LOG(information, "Port fallback order:");
    LOG(information, "  try:     sink specific port              [if specified]");
    LOG(information, "  try:     original dgram destination port [if resolved ]");
    LOG(information, "  finally: source's binding port");
    LOG(information, "");
    LOG(information, "Signals:");
    LOG(information, "  HUP     - reload configuration");
    LOG(information, "  USR1    - reopen log file");
    LOG(information, "  USR2    - restart sources");
    LOG(information, "");
    LOG(information, "Send bugs to Alexander V. Belyaev <iybego@ocihs.spb.ru>");
    LOG(information, "");
}

static rconfiguration
_configuration_token_network (
    OUT sipv4_network*          network,
        char*                   value
);

static rconfiguration
_configuration_token_address (
    OUT ipv4_t*                 address,
        char*                   value
);

static rconfiguration
_configuration_token_destination (
    OUT sipv4_destination*      address,
        char*                   value
);

static rconfiguration
_configuration_token_port (
    OUT uint16_t*               port,
        char*                   value
);

static rconfiguration
configuration_token_be (
        char*                   value,
    BTH sconfiguration*         cfg
) {
    (void)cfg;

    if (0 == strcasecmp(value, "silent")) {
        log_suppress(LOGGING_SILENT_SUPPRESS);
        return rconfiguration_ok;
    }

    if (0 == strcasecmp(value, "verbose")) {
        log_unsuppress(LOGGING_VERBOSE);
        return rconfiguration_ok;
    }

    if (0 == strcasecmp(value, "debug")) {
        log_unsuppress(LOGGING_DEBUG);
        return rconfiguration_ok;
    }

    LOG(error, "wrong \"be\" value specified %s", value);
    return rconfiguration_failed;
}

static rconfiguration
configuration_token_buffer (
        char*                   value,
    BTH sconfiguration*         cfg
) {
    unsigned long _size;

    if (1 > sscanf(value, "%lu", &_size)) {
        LOG(error, "wrong \"buffer\" size %s", value);
        return rconfiguration_failed;
    }

    if (1 > (cfg->buffer_size = _size)) {
        LOG(error, "wrong \"buffer\" size, should be at least 1");
        return rconfiguration_failed;
    }

    return rconfiguration_ok;
}

static rconfiguration
configuration_token_events (
        char*                   value,
    BTH sconfiguration*         cfg
) {
    if (0 == strcasecmp(value, "automatic")) {
        cfg->events = 0;
        return rconfiguration_ok;
    }

    unsigned long _events;

    if (1 > sscanf(value, "%lu", &_events)) {
        LOG(error, "wrong \"events\" size %s", value);
        return rconfiguration_failed;
    }

    if (1 > (cfg->events = _events)) {
        LOG(error, "wrong \"events\" size, should be at least 1 or auto");
        return rconfiguration_failed;
    }

    return rconfiguration_ok;
}

static rconfiguration
configuration_token_rtlink_hash (
        char*                   value,
    BTH sconfiguration*         cfg
) {
    unsigned long _hash;

    if (1 > sscanf(value, "%lu", &_hash)) {
        LOG(error, "wrong \"rtlink-hash\" size %s", value);
        return rconfiguration_failed;
    }

    if (1 > (cfg->rtlink_hash = _hash)) {
        LOG(error, "wrong \"rtlink-hash\" size, should be at least 1");
        return rconfiguration_failed;
    }

    return rconfiguration_ok;
}

static rconfiguration
configuration_token_statistics (
        char*                   value,
    BTH sconfiguration*         cfg
) {
    unsigned long _seconds;

    if (1 > sscanf(value, "%lu", &_seconds)) {
        LOG(error, "wrong \"statistics\" delay %s", value);
        return rconfiguration_failed;
    }

    cfg->statistics = _seconds;
    return rconfiguration_ok;
}

static rconfiguration
configuration_token_reload (
        char*                   value,
    BTH sconfiguration*         cfg
) {
    unsigned long _seconds;

    if (1 > sscanf(value, "%lu", &_seconds)) {
        LOG(error, "wrong \"reload\" delay %s", value);
        return rconfiguration_failed;
    }

    cfg->reload = _seconds;
    return rconfiguration_ok;
}


static rconfiguration
configuration_token_restore (
        char*                   value,
    BTH sconfiguration*         cfg
) {
    unsigned long _seconds;

    if (1 > sscanf(value, "%lu", &_seconds)) {
        LOG(error, "wrong \"restore\" delay %s", value);
        return rconfiguration_failed;
    }

    cfg->restore = _seconds;
    return rconfiguration_ok;
}

static rconfiguration
_configuration_token_port (
    OUT uint16_t*               port,
        char*                   value
) {
    uint16_t _port;

    if (0 < sscanf(value, "%"SCNu16, &_port)) {
        (*port) = htons(_port);
        return rconfiguration_ok;
    }

    struct servent* _servent = getservbyname(value, "udp");
    if NULL_IS(_servent) {
        LOG(error, "port value %s doesn't found in /etc/services", value);
        return rconfiguration_failed;
    }

    (*port) = _servent->s_port;
    return rconfiguration_ok;
}

static rconfiguration
configuration_token_source (
        char*                   value,
    BTH sconfiguration*         cfg
) {
    if (NULL != cfg->sources)
        if NULL_IS(cfg->sources->sinks) {
            LOG(error, "empty \"source\" specified");
            return rconfiguration_failed;
        }

    ssource* _source = NULL;

    if (0 == strcasecmp("raw", value)) {
        if NULL_IS(_source = (ssource*)malloc(sizeof(ssource))) {
            LOG(critical, "out of memory: source [%lu]", (unsigned long)(sizeof(ssource)));
            return rconfiguration_failed;
        }

        _source->type       = esource_type_raw;
        _source->flg_socket = FSOCKET_DEFAULT_SOURCE_RAW;
        _source->port       = 0;

    } else {
        uint16_t _port = 0;

        if ((rconfiguration_ok != _configuration_token_port(&_port, value)) || (0 == _port)) {
            LOG(error, "wrong \"source\" port value %s", value);
            return rconfiguration_failed;
        }

        if NULL_IS(_source = (ssource*)malloc(sizeof(ssource))) {
            LOG(critical, "out of memory: source [%lu]", (unsigned long)(sizeof(ssource)));
            return rconfiguration_failed;
        }

        _source->type       = esource_type_simple;
        _source->flg_socket = FSOCKET_DEFAULT_SOURCE;
        _source->port       = _port;
    }

    memset(_source->ss.configuration.device, 0, IFNAMSIZ);

    _source->sinks      = NULL;
    _source->allow      = NULL;
    _source->ratelimit  = NULL;
    _source->portrange  = NULL;
    _source->mgroups    = NULL;

    _source->binding.address = IPV4_ADDRESS(0, 0, 0, 0);
    _source->binding.mask    = IPV4_ADDRESS(0, 0, 0, 0);

    _source->next = cfg->sources;
    cfg->sources = _source;

    return rconfiguration_ok;
}

static rconfiguration
configuration_token_mgroup (
        char*                   value,
    BTH sconfiguration*         cfg
) {
    if ( NULL_IS(cfg->sources) || (NULL != cfg->sources->sinks)) {
        LOG(error, "\"m-group\" only allowed if \"source\" specified before");
        return rconfiguration_failed;
    }

    ipv4_t _group;

    if (rconfiguration_ok != _configuration_token_address(&_group, value)) {
        LOG(error, "\"wrong group vales specified as address for \"m-group\"");
        return rconfiguration_failed;
    }

    if (ripv4_ok != ipv4_address_in_network(_group, &IPV4_NETWORK_ALL_MULTICAST)) {
        LOG(error, "\"m-group\" address must be multicast address in ["IPV4_PRIADDR"/"IPV4_PRIADDR"]", IPV4_DPRIADDR(IPV4_NETWORK_ALL_MULTICAST.address), IPV4_DPRIADDR(IPV4_NETWORK_ALL_MULTICAST.mask));
        return rconfiguration_failed;
    }

    smgroup* _mgroup = (smgroup*)malloc(sizeof(smgroup));
    if NULL_IS(_mgroup) {
        LOG(critical, "out of memory: m-group [%lu]", (long unsigned)sizeof(smgroup));
        return rconfiguration_failed;
    }

    memcpy(&(_mgroup->group), &_group, sizeof(_group));

    _mgroup->next = cfg->sources->mgroups;
    cfg->sources->mgroups = _mgroup;

    return rconfiguration_ok;
}

static rconfiguration
configuration_token_ratelimit (
        char*                   value,
    BTH sconfiguration*         cfg
) {
    if ( NULL_IS(cfg->sources) || (NULL != cfg->sources->sinks)) {
        LOG(error, "\"rate-limit\" only avalible if source specified before");
        return rconfiguration_failed;
    }

    if (NULL != cfg->sources->ratelimit) {
        LOG(error, "\"rate-limit\" already specified before");
        return rconfiguration_failed;
    }

    uint32_t _rate;
    uint64_t _window;

    if (2 > sscanf(value, "%"SCNu32":%"SCNu64, &_rate, &_window)) {
        LOG(error, "wrong \"rate-limit\" value specified, try to read --help");
        return rconfiguration_failed;
    }

    sratelimit* _ratelimit = (sratelimit*)malloc(sizeof(sratelimit));
    if NULL_IS(_ratelimit) {
        LOG(critical, "out of memory: ratelimit [%lu]", (unsigned long)(sizeof(sratelimit)));
        return rconfiguration_failed;
    }

    ratelimit_initialize(_ratelimit, _rate, _window);

    cfg->sources->ratelimit = _ratelimit;
    return rconfiguration_ok;
}

static rconfiguration
_configuration_token_network (
    OUT sipv4_network*          network,
        char*                   value
) {
    if (0 == strcasecmp(value, "any")) {
        memcpy(network, &IPV4_NETWORK_ANY, sizeof(sipv4_network));
        return rconfiguration_ok;
    }

    if (0 == strcasecmp(value, "broadcast")) {
        memcpy(network, &IPV4_NETWORK_BROADCAST, sizeof(sipv4_network));
        return rconfiguration_ok;
    }

    if (0 == strcasecmp(value, "multicast")) {
        memcpy(network, &IPV4_NETWORK_ALL_MULTICAST, sizeof(sipv4_network));
        return rconfiguration_ok;
    }

    uint16_t _a[5];

    switch (sscanf(value, "%"SCNu16".%"SCNu16".%"SCNu16".%"SCNu16"/%"SCNu16"", &_a[0], &_a[1], &_a[2], &_a[3], &_a[4])) {
        case 5:
            break;

        case 4:
            _a[4] = 32;
            break;

        default: return rconfiguration_failed;
    }

    network->address = IPV4_ADDRESS(_a[0], _a[1], _a[2], _a[3]);
    network->mask    = IPV4_MASK(_a[4]);

    return rconfiguration_ok;
}

static rconfiguration
_configuration_token_address (
    OUT ipv4_t*                 address,
        char*                   value
) {
    uint16_t _a[4];

    if (4 != sscanf(value, "%"SCNu16".%"SCNu16".%"SCNu16".%"SCNu16, &_a[0], &_a[1], &_a[2], &_a[3]))
        return rconfiguration_failed;

    (*address) = IPV4_ADDRESS(_a[0], _a[1], _a[2], _a[3]);
    return rconfiguration_ok;
}

static rconfiguration
_configuration_token_destination (
    OUT sipv4_destination*      destination,
        char*                   value
) {
    uint16_t _a[5];

    switch (sscanf(value, "%"SCNu16".%"SCNu16".%"SCNu16".%"SCNu16":%"SCNu16, &_a[0], &_a[1], &_a[2], &_a[3], &_a[4])) {
        case 5:
            break;

        case 4:
            _a[4] = 0;

            for (size_t _i = 0; '\0' != value[_i]; _i++) 
                if (':' == value[_i]) {
                    struct servent* _servent = getservbyname(&(value[_i + 1]), "udp");

                    if NULL_IS(_servent) {
                        LOG(error, "port value %s doesn't found in /etc/services", &(value[_i + 1]));
                        return rconfiguration_failed;
                    }

                    _a[4] = ntohs(_servent->s_port);
                    break;
                }

            break;

        default:
            return rconfiguration_failed;
    }

    destination->address = IPV4_ADDRESS(_a[0], _a[1], _a[2], _a[3]);
    destination->port    = htons(_a[4]);

    return rconfiguration_ok;
}

static rconfiguration
configuration_token_no (
        char*                   value,
    BTH sconfiguration*         cfg
) {
    if NULL_IS(cfg->sources) {
        LOG(error, "\"no\" avalible only after \"sink\" or \"source\" specified");
        return rconfiguration_failed;
    }

    uint32_t* _flags = &(cfg->sources->flg_socket);

    if NULL_IS(cfg->sources->sinks) {
        if (0 == strcasecmp("ip-options", value)) {
            (*_flags) &= ~(FSOCKET_RECVOPTIONS);
            return rconfiguration_ok;
        }

        if (0 == strcasecmp("ip-tos", value)) {
            (*_flags) &= ~(FSOCKET_RECVTOS);
            return rconfiguration_ok;
        }

        if (0 == strcasecmp("ip-ttl", value)) {
            (*_flags) &= ~(FSOCKET_RECVTTL);
            return rconfiguration_ok;
        }

        if (esource_type_simple != cfg->sources->type) {
            LOG(verbose, "[no %s] will be ignored", value);
        }

        if (0 == strcasecmp("transparent", value)) {
            (*_flags) &= ~(FSOCKET_TRANSPARENT);
            return rconfiguration_ok;
        }

        if (0 == strcasecmp("reuseaddr", value)) {
            (*_flags) &= ~(FSOCKET_REUSEADDR);
            return rconfiguration_ok;
        }

    } else {
        _flags = &(cfg->sources->sinks->flg_socket);

        if (0 == strcasecmp("route", value)) {
            (*_flags) |= FSOCKET_DONTROUTE;
            return rconfiguration_ok;
        }

        if (0 == strcasecmp("fragment", value)) {
            cfg->sources->sinks->rewrite |= FSINK_REWRITE_NO_FRAGMENT;
            return rconfiguration_ok;
        }

        if (0 == strcasecmp("passthrou-ip-id", value)) {
            cfg->sources->sinks->rewrite |= FSINK_REWRITE_NO_IP_ID;
            return rconfiguration_ok;
        }

        if (0 == strcasecmp("passthrou-ip-options", value)) {
            cfg->sources->sinks->rewrite |= FSINK_REWRITE_NO_IP_OPTIONS;
            return rconfiguration_ok;
        }
    }

    // shared socket options

    if (0 == strcasecmp("broadcast", value)) {
        (*_flags) &= ~(FSOCKET_BROADCAST);
        return rconfiguration_ok;
    }

    LOG(error, "unknown \"no\" flags specified");
    return rconfiguration_failed;
}

static rconfiguration
configuration_token_binding (
        char*                   value,
    BTH sconfiguration*         cfg
) {
    if ( NULL_IS(cfg->sources) || (NULL != cfg->sources->sinks) ) {
        LOG(error, "\"binding\" avalible only after \"source\" specified");
        return rconfiguration_failed;
    }

    sipv4_network _network;

    if (rconfiguration_ok != _configuration_token_network(&_network, value)) {
        LOG(error, "wrong \"binding\" address specified %s, must be \"ipaddress/mask\"", value);
        return rconfiguration_failed;
    }

    if (ripv4_ok == ipv4_address_in_network(_network.address, &IPV4_NETWORK_ALL_MULTICAST)) {
        LOG(error, "bad idea to use multicast address as binding, use \"m-group\" instead");
        return rconfiguration_failed;
    }

    memcpy(&(cfg->sources->binding), &_network, sizeof(_network));

    return rconfiguration_ok;
}

static rconfiguration
configuration_token_sink (
        char*                   value,
    BTH sconfiguration*         cfg
) {
    if NULL_IS(cfg->sources) {
        LOG(error, "\"sink\" only avalible if \"source\" specified before");
        return rconfiguration_failed;
    }

    uint32_t      _rewrite = 0;
    sipv4_network _network;

    if (0 == strcmp("original", value)) {
        _rewrite |= FSINK_REWRITE_DESTINATION_ORIGINAL;

        memcpy(&_network, &IPV4_NETWORK_ANY, sizeof(IPV4_NETWORK_ANY));

    } else {
        if (rconfiguration_ok != _configuration_token_network(&_network, value)) {
            LOG(error, "wrong \"sink\" address specified %s, must be \"ipaddress/mask\"", value);
            return rconfiguration_failed;
        }

    }

    ssink* _sink = (ssink*)malloc(sizeof(ssink));
    if NULL_IS(_sink) {
        LOG(critical, "out of memory: sink [%lu]", (unsigned long)(sizeof(ssink)));
        return rconfiguration_failed;
    }

    _sink->type         = esink_type_simple;
    _sink->flg_socket   = FSOCKET_DEFAULT_SINK_RAW;

    _sink->socket       = SOCKET_INVALID;

    memcpy(&(_sink->ts.simple.target), &_network, sizeof(_network));

    memset(_sink->ts.simple.device.configuration, 0, IFNAMSIZ);

    memset(&(_sink->from), 0, sizeof(sipv4_destination));
    _sink->port         = 0;    //use fallback

    _sink->allow        = NULL;
    _sink->portrange    = NULL;

    _sink->last_ip_id   = 1;
    _sink->rewrite      = _rewrite;
    _sink->ttl          = 0;
    _sink->tos          = 0;
    _sink->fwmark       = 0;
    _sink->mtu          = 0;

    _sink->security_level       = 0;
    _sink->security_categories  = 0;

    _sink->allow        = NULL;
    _sink->portrange    = NULL;

    _sink->next = cfg->sources->sinks;
    cfg->sources->sinks = _sink;
    return rconfiguration_ok;
}

static rconfiguration
configuration_token_join (
        char*                   value,
    BTH sconfiguration*         cfg
) {
    if NULL_IS(cfg->sources) {
        LOG(error, "\"join\" only avalible if \"source\" specified before");
        return rconfiguration_failed;
    }

    ssink* _sink = (ssink*)malloc(sizeof(ssink));

    if NULL_IS(_sink) {
        LOG(critical, "out of memory: join [%lu]", (unsigned long)(sizeof(ssink)));
        return rconfiguration_failed;
    }

    _sink->type         = esink_type_join;
    _sink->flg_socket   = FSOCKET_DEFAULT_SINK_RAW;

    _sink->socket       = SOCKET_INVALID;

    strcpy_l(_sink->ts.join.configuration.device, value, IFNAMSIZ);   

    memset(&(_sink->from), 0, sizeof(sipv4_destination));
    _sink->port         = 0;    //use fallback

    _sink->last_ip_id   = 1;
    _sink->rewrite      = 0;
    _sink->ttl          = 0;
    _sink->tos          = 0;
    _sink->fwmark       = 0;
    _sink->mtu          = 0;

    _sink->security_level       = 0;
    _sink->security_categories  = 0;

    _sink->allow        = NULL;
    _sink->portrange    = NULL;

    _sink->next = cfg->sources->sinks;
    cfg->sources->sinks = _sink;
    return rconfiguration_ok;
}

static rconfiguration
configuration_token_allow (
        char*                   value,
    BTH sconfiguration*         cfg
) {
    if NULL_IS(cfg->sources) {
        LOG(error, "\"allow\" only avalible if \"source\" or \"sink\" specified before");
        return rconfiguration_failed;
    }

    sipv4_allow** _p = NULL;

    if (NULL != cfg->sources->sinks) {
        _p = &(cfg->sources->sinks->allow);
    } else {
        _p = &(cfg->sources->allow);
    }

    sipv4_network _network;

    if (rconfiguration_ok != _configuration_token_network(&_network, value)) {
        LOG(error, "wrong \"allow\" address specified %s, must be \"ipaddress/mask\"", value);
        return rconfiguration_failed;
    }

    sipv4_allow* _allow = (sipv4_allow*)malloc(sizeof(sipv4_allow));
    if NULL_IS(_allow) {
        LOG(critical, "out of memory: allow [%lu]", (unsigned long)(sizeof(sipv4_allow)));
        return rconfiguration_failed;
    }

    memcpy(&(_allow->address), &_network, sizeof(_network));
    _allow->allow_to = NULL;

    _allow->next = (*_p);
    (*_p) = _allow;

    return rconfiguration_ok;
}

static inline sipv4_allow*
_configuration_last_allow (
        sconfiguration*         cfg
) {
    if NULL_IS(cfg->sources)
        return NULL;

    if (NULL != cfg->sources->sinks) {
        return cfg->sources->sinks->allow;
    }

    return cfg->sources->allow;
}

static rconfiguration
configuration_token_to (
        char*                   value,
    BTH sconfiguration*         cfg
) {
    if NULL_IS(cfg->sources)
        goto _error;

    sipv4_allow* _p = _configuration_last_allow(cfg);
    if NULL_IS(_p)
        goto _error;

    sipv4_network _network;

    if (rconfiguration_ok != _configuration_token_network(&_network, value)) {
        LOG(error, "wrong \"to\" address specified %s, must be \"ipaddress/mask\"", value);
        return rconfiguration_failed;
    }

    sipv4_allow_to* _to = (sipv4_allow_to*)malloc(sizeof(sipv4_allow_to));
    if NULL_IS(_to) {
        LOG(critical, "out of memory: allow, to [%lu]", (unsigned long)(sizeof(sipv4_allow_to)));
        return rconfiguration_failed;
    }

    memcpy(&(_to->address), &_network, sizeof(_network));

    _to->portrange = NULL;

    _to->next = _p->allow_to;
    _p->allow_to = _to;

    return rconfiguration_ok;

    _error:
        LOG(error, "\"to\" allowed only after \"allow\" specified");
        return rconfiguration_failed;
}

static sipv4_portrange**
_configuration_last_portrange (
    BTH sconfiguration*         cfg
) {
    if NULL_IS(cfg->sources)
        return NULL;

    if (NULL != cfg->sources->sinks) {
        if NULL_IS(cfg->sources->sinks->allow)
            return &(cfg->sources->sinks->portrange);

        if (NULL != cfg->sources->sinks->allow->allow_to)
            return &(cfg->sources->sinks->allow->allow_to->portrange);

        return NULL; //cuz allow defined, but not to
    }

    if NULL_IS(cfg->sources->allow)
        return &(cfg->sources->portrange);

    if (NULL != cfg->sources->allow->allow_to)
        return &(cfg->sources->allow->allow_to->portrange);

    return NULL;
}

static rconfiguration
configuration_token_portrange (
        char*                   value,
    BTH sconfiguration*         cfg
) {
    sipv4_portrange** _p = _configuration_last_portrange(cfg);

    if NULL_IS(_p)
        goto _error;

    uint16_t _ports[2] = {0, 65535};

    if (0 != strcasecmp(value, "any"))
        switch (sscanf(value, "%"SCNu16":%"SCNu16, &_ports[0], &_ports[1])) {
            case 1:
                _ports[1] = _ports[0];
                break;

            case 2:
                if (_ports[1] < _ports[0]) {
                    LOG(error, "second \"port-range\" port value, litter that the first");
                    return rconfiguration_failed;
                }

                break;

            default: {
                struct servent* _servent = getservbyname(value, "udp");

                if NULL_IS(_servent) {
                    LOG(error, "\"port-range\" value %s doesn't found in /etc/services", value);
                    return rconfiguration_failed;
                }

                _ports[0] = ntohs(_servent->s_port);
                _ports[1] = ntohs(_servent->s_port);
                break;
            }
        }

    sipv4_portrange* _portrange = (sipv4_portrange*)malloc(sizeof(sipv4_portrange));
    if NULL_IS(_portrange) {
        LOG(critical, "out of memory: port-range [%lu]", sizeof(sipv4_portrange));
        return rconfiguration_failed;
    }

    _portrange->first = _ports[0];
    _portrange->last  = _ports[1];

    _portrange->next = (*_p);
    (*_p) = _portrange;

    return rconfiguration_ok;

    _error:
        LOG(error, "\"port-range\" only avalible on \"to\" or \"sink\" or \"source\" context");
        return rconfiguration_failed;
}

static rconfiguration
configuration_token_device (
        char*                   value,
    BTH sconfiguration*         cfg
) {
    if NULL_IS(cfg->sources) {
        LOG(error, "\"device\" only avalible if \"source\" or \"sink\" specified before");
        return rconfiguration_failed;
    }

    if (NULL != cfg->sources->sinks) {
        if (esink_type_simple != cfg->sources->sinks->type) {
            LOG(error, "\"device only avalible if \"sink\" specified via \"sink\"");
            return rconfiguration_failed;
        }

        strcpy_l(cfg->sources->sinks->ts.simple.device.configuration, value, IFNAMSIZ);
        return rconfiguration_ok;
    }

    strcpy_l(cfg->sources->ss.configuration.device, value, IFNAMSIZ);
    return rconfiguration_ok;
}

static rconfiguration
configuration_token_port (
        char*                   value,
    BTH sconfiguration*         cfg
) {
    if (NULL_IS(cfg->sources) || NULL_IS(cfg->sources->sinks)) {
        LOG(error, "\"port\" only avalible if \"sink\" specified before");
        return rconfiguration_failed;
    }

    if (0 == strcasecmp("inherit", value)) {
        cfg->sources->sinks->port = cfg->sources->port;
        return rconfiguration_ok;
    }

    if (rconfiguration_ok != _configuration_token_port(&(cfg->sources->sinks->port), value)) {
        LOG(error, "wrong \"port\" value specified %s", value);
        return rconfiguration_failed;
    }

    return rconfiguration_ok;
}

static rconfiguration
configuration_token_from (
        char*                   value,
    BTH sconfiguration*         cfg
) {
    if (NULL_IS(cfg->sources) || NULL_IS(cfg->sources->sinks)) {
        LOG(error, "\"port\" only avalible if \"sink\" specified before");
        return rconfiguration_failed;
    }

    if (0 != (FSINK_REWRITE_FROM & cfg->sources->sinks->rewrite)) {
        LOG(error, "\"from\" value already specified");
        return rconfiguration_failed;
    }

    if (0 == strcasecmp("inherit", value)) {
        memcpy(&(cfg->sources->sinks->from.address), &(cfg->sources->binding.address), sizeof(ipv4_t));
        cfg->sources->sinks->from.port = cfg->sources->port;

        cfg->sources->sinks->rewrite |= FSINK_REWRITE_FROM;
        return rconfiguration_ok;
    }

    if (rconfiguration_ok != _configuration_token_destination(&(cfg->sources->sinks->from), value)) {
        LOG(error, "wrong \"from\" \"address\" value %s", value);
        return rconfiguration_failed;
    }

    cfg->sources->sinks->rewrite |= FSINK_REWRITE_FROM;
    return rconfiguration_ok;
}

static rconfiguration
configuration_token_fwmark (
        char*                   value,
    BTH sconfiguration*         cfg
) {
    if (NULL_IS(cfg->sources) || NULL_IS(cfg->sources->sinks)) {
        LOG(error, "\"fwmark\" only avalible if \"sink\" specified before");
        return rconfiguration_failed;
    }

    if (0 != (FSINK_REWRITE_FWMARK & cfg->sources->sinks->rewrite)) {
        LOG(error, "\"fwmark\" value already specified");
        return rconfiguration_failed;
    }

    if (1 > sscanf(value, "%"SCNu32, &(cfg->sources->sinks->fwmark))) {
        LOG(error, "wrong \"sink\" \"fwmark\" value %s", value);
        return rconfiguration_failed;
    }

    cfg->sources->sinks->rewrite |= FSINK_REWRITE_FWMARK;
    return rconfiguration_ok;
}

static rconfiguration
configuration_token_security (
        char*                   value,
    BTH sconfiguration*         cfg
) {
    if (NULL_IS(cfg->sources) || NULL_IS(cfg->sources->sinks)) {
        LOG(error, "\"security\" only avalible if \"sink\" specified before");
        return rconfiguration_failed;
    }

    if (0 != (FSINK_REWRITE_SECURITY & cfg->sources->sinks->rewrite)) {
        LOG(error, "\"security\" value already specified");
        return rconfiguration_failed;
    }

    if (0 == strcasecmp("drop", value)) {
        cfg->sources->sinks->rewrite |= (FSINK_REWRITE_SECURITY | FSINK_REWRITE_SECURITY_DROP);
        return rconfiguration_ok;
    }

    switch (sscanf(value, "%"SCNu8":%"SCNu64, &(cfg->sources->sinks->security_level), &(cfg->sources->sinks->security_categories))) {
        case 1:
            cfg->sources->sinks->security_categories = 0;
            break;

        case 2:
            break;

        default:
            LOG(error, "wrong \"sink\" \"security\" value %s", value);
            return rconfiguration_failed;
    }

    cfg->sources->sinks->rewrite |= FSINK_REWRITE_SECURITY;
    return rconfiguration_ok;
}

static rconfiguration
configuration_token_mtu (
        char*                   value,
    BTH sconfiguration*         cfg
) {
    if (NULL_IS(cfg->sources) || NULL_IS(cfg->sources->sinks)) {
        LOG(error, "\"mtu\" only avalible if \"sink\" specified before");
        return rconfiguration_failed;
    }

    if (0 != (FSINK_REWRITE_MTU & cfg->sources->sinks->rewrite)) {
        LOG(error, "\"mtu\" value already specified");
        return rconfiguration_failed;
    }

    if (1 > sscanf(value, "%"SCNu32, &(cfg->sources->sinks->mtu))) {
        LOG(error, "wrong \"sink\" \"mtu\" value %s", value);
        return rconfiguration_failed;
    }

    if (28 > cfg->sources->sinks->mtu) {
        LOG(error, "mtu must be greater that 28 [udp header + ip header]");
        return rconfiguration_failed;
    }

    if (576 > cfg->sources->sinks->mtu) {
        LOG(warning, "mtu should be at least 576, as say RFC 791");
    }

    cfg->sources->sinks->rewrite |= FSINK_REWRITE_MTU;
    return rconfiguration_ok;
}

static rconfiguration
configuration_token_tos (
        char*                   value,
    BTH sconfiguration*         cfg
) {
    if (NULL_IS(cfg->sources) || NULL_IS(cfg->sources->sinks)) {
        LOG(error, "\"tos\" only avalible if \"sink\" specified before");
        return rconfiguration_failed;
    }

    if (0 != (FSINK_REWRITE_TOS & cfg->sources->sinks->rewrite)) {
        LOG(error, "\"tos\" value already specified");
        return rconfiguration_failed;
    }

    if (1 > sscanf(value, "%"SCNu8, &(cfg->sources->sinks->tos))) {
        static const struct _tos_class {
            const char*     name;
            uint8_t         value;
        } _classes[] = {
                {   "CS0",       0  }
            ,   {   "CS1",       8  }
            ,   {   "AF11",     10  }
            ,   {   "AF12",     12  }
            ,   {   "AF13",     14  }
            ,   {   "CS2",      16  }
            ,   {   "AF21",     18  }
            ,   {   "AF22",     20  }
            ,   {   "AF23",     22  }
            ,   {   "CS3",      24  }
            ,   {   "AF31",     26  }
            ,   {   "AF32",     28  }
            ,   {   "AF33",     30  }
            ,   {   "CS4",      32  }
            ,   {   "AF41",     34  }
            ,   {   "AF42",     36  }
            ,   {   "AF43",     38  }
            ,   {   "CS5",      40  }
            ,   {   "CS6",      48  }
            ,   {   "CS7",      56  }
            ,   {    NULL,    0xFF  }
        };

        for (const struct _tos_class* _c = _classes; NULL != _c->name; ++_c)
            if (0 == strcasecmp(_c->name, value)) {
                cfg->sources->sinks->tos      = (_c->value << 2);
                cfg->sources->sinks->rewrite |= FSINK_REWRITE_TOS;
                return rconfiguration_ok;
            }

        LOG(error, "unknown \"sink\"'s \"tos\" value %s", value);
        return rconfiguration_failed;
    }

    cfg->sources->sinks->rewrite |= FSINK_REWRITE_TOS;
    return rconfiguration_ok;
}

static rconfiguration
configuration_token_ttl (
        char*                   value,
    BTH sconfiguration*         cfg
) {
    if (NULL_IS(cfg->sources) || NULL_IS(cfg->sources->sinks)) {
        LOG(error, "\"ttl\" only avalible if \"sink\" specified before");
        return rconfiguration_failed;
    }

    if (0 != (FSINK_REWRITE_TTL & cfg->sources->sinks->rewrite)) {
        LOG(error, "\"ttl\" value already specified");
        return rconfiguration_failed;
    }

    if (0 == strcasecmp(value, "default")) {
        cfg->sources->sinks->ttl      = 0;
        cfg->sources->sinks->rewrite |= FSINK_REWRITE_TTL;
        return rconfiguration_ok;
    }

    if ((1 > sscanf(value, "%"SCNu8, &(cfg->sources->sinks->ttl))) || (1 > cfg->sources->sinks->ttl)) {
        LOG(error, "wrong \"sink\" \"ttl\" value %s", value);
        return rconfiguration_failed;
    }

    cfg->sources->sinks->rewrite |= FSINK_REWRITE_TTL;
    return rconfiguration_ok;
}

static rconfiguration
configuration_token_log (
        char*                   value,
    BTH sconfiguration*         cfg
) {
    if (NULL != cfg->log) {
        LOG(error, "\"log\" already specified");
        return rconfiguration_failed;
    }

    cfg->log = strdup(value);
    return rconfiguration_ok;
}

static rconfiguration
configuration_token_directory (
        char*                   value,
    BTH sconfiguration*         cfg
) {
    if (NULL != cfg->directory) {
        LOG(error, "\"directory\" already specified");
        return rconfiguration_failed;
    }

    cfg->directory = strdup(value);
    return rconfiguration_ok;
}

static rconfiguration
configuration_token_echo (
        char*                   value,
    BTH sconfiguration*         cfg
) {
    (void)cfg;

    LOG(warning, "%s", value);
    return rconfiguration_ok;
}

static rconfiguration
configuration_token_noop (
        char*                   value,
    BTH sconfiguration*         cfg
) {
    (void)value;
    (void)cfg;
    return rconfiguration_ok;
}

static rconfiguration
configuration_file (
        const char*             filename,
    BTH sconfiguration*         cfg,
    BTH sconfiguration_opts**   opts
);

static sconfiguration_opts*
_configuration_token_value_raw (
        char*                   value,
    BTH sconfiguration_opts**   opts
) {
    for (sconfiguration_opts* _opt = (*opts); NULL != _opt; _opt = _opt->next)
        if (0 == strcasecmp(_opt->name, value))
            return _opt;

    return NULL;
}

static char*
_configuration_token_value (
        char*                   value,
    BTH sconfiguration_opts**   opts
) {
    if ('$' != value[0])
        return value;

    sconfiguration_opts* _opt = _configuration_token_value_raw(&(value[1]), opts);
    if NULL_IS(_opt)
        return NULL;

    return _opt->value;
}

static char*
_configuration_token_let_parse (
    IN  char*                   value
) {
   for (char* _t = value; '\0' != (*_t); ++_t)
        if ('=' == (*_t)) {
            (*_t) = '\0';
            return (_t+1);
        }

    return NULL;
}

static rconfiguration
_configuration_token_let_push (
    BTH sconfiguration_opts**   opts,
        char*                   name,
        char*                   value
) {
    sconfiguration_opts* _opt = (sconfiguration_opts*)malloc(sizeof(sconfiguration_opts));

    if NULL_IS(_opt) {
        LOG(critical, "out of memory: variable push [%lu]", (unsigned long)(sizeof(sconfiguration_opts)));
        return rconfiguration_failed;
    }

    _opt->name          = name;
    _opt->name_length   = strlen(name);
    _opt->value         = value;
    _opt->value_length  = strlen(value);

    _opt->next = (*opts);
    (*opts) = _opt;

    return rconfiguration_ok;
}

static rconfiguration
configuration_token_let (
    IN  char*                   value,
    BTH sconfiguration_opts**   opts
) {
    char* _val = _configuration_token_let_parse(value);

    if NULL_IS(_val) {
        LOG(error, "\"let\" have syntax like \"let VARIABLE=VALUE\"");
        return rconfiguration_failed;
    }

    char* _name = _configuration_token_value(value, opts);
    if NULL_IS(_name) {
        LOG(error, "unknown variable %s specified as name for let", value);
        return rconfiguration_failed;
    }

    char* _value = _configuration_token_value(_val, opts);
    if NULL_IS(_value) {
        LOG(error, "unknown variable %s specified as value for let", _val);
        return rconfiguration_failed;
    }

    return _configuration_token_let_push(opts, _name, _value);
}

typedef
struct _configuration_parser {
    size_t                  current;
    char*                   tokens  [2];
    uint32_t                cleanup [2];
} sconfiguration_parser;

static inline void
configuration_parser_initialize (
    OUT sconfiguration_parser*  parser
) { memset(parser, 0, sizeof(sconfiguration_parser)); }

static inline void
configuration_parser_cleanup (
    BTH sconfiguration_parser*  parser
) {
    for (size_t _i = 0; _i < 2; ++_i) 
        if (parser->cleanup[_i])
            free(parser->tokens[_i]);

    configuration_parser_initialize(parser);
}

static inline rconfiguration
__hex (
    IN  const char              value,
    OUT char*                   output
) {
    if ( (value >= 0x30) && (value <= 0x39) ) {
        (*output) = (value - 0x30);
        return rconfiguration_ok;
    }

    if ( (value >= 0x41) && (value <= 0x5A) ) {
        (*output) = (value - 0x41 + 10);
        return rconfiguration_ok;
    }

    if ( (value >= 0x61) && (value <= 0x7A) ) {
        (*output) = (value - 0x61 + 10);
        return rconfiguration_ok;
    }

    return rconfiguration_failed;
}

static inline rconfiguration
hex (
    IN  const char*             value,
    OUT char*                   output
) {
    char _t[2];

    for (size_t _i = 0; _i < 2; ++_i)
        if (rconfiguration_ok != __hex(value[_i], &_t[_i])) {
            LOG(error, "unexcepted hex value at %u", (unsigned int)_i);
            return rconfiguration_failed;
        }

    if (NULL != output)
        (*output) = (_t[0] << 4) | _t[1];

    return rconfiguration_ok;
}

static rconfiguration
configuration_prepaire_unescape (
    BTH char*                   data,
        size_t                  length,
    BTH size_t*                 shift,
    BTH sconfiguration_opts**   opts,
    BTH sconfiguration_parser*  parser
) {
    char*   _output     = &(data[(*shift)]);
    char*   _begin      = &(data[(*shift) + 1]);

    size_t  _length     = 0;

    char*   _variable   = NULL;

    while (1) {
        if ((++(*shift)) >= length) {
            LOG(error, "unexcepted end of file while parsing string block");
            return rconfiguration_failed;
        }

        if ('"' == data[*shift])
            break;

        switch (data[*shift]) {
            case '\n':
            case '\r':
                LOG(error, "unexcepted line carriage within string block");
                return rconfiguration_failed;

            case '\\':
                if ((++(*shift)) >= length) {
                    LOG(error, "unexcepted end of file after \\ symbol");
                    return rconfiguration_failed;
                }

                switch (data[(*shift)]) {
                    case 'h':
                        if (((*shift) + 2) >= length) {
                            LOG(error, "unexcepted end of file after \\hXX symbol");
                            return rconfiguration_failed;
                        }

                        rconfiguration _r = hex(&data[(*shift) + 1], NULL);
                        if (rconfiguration_ok != _r) {
                            LOG(error, "unexcepted value after \\hXX symbol");
                            return _r;
                        }

                        (*shift) += 2;
                        break;
                }

                break;

            case '{' : //variable
                if (NULL != _variable) {
                    LOG(error, "syntax error, string block containe start of variable within variable");
                    return rconfiguration_failed;
                }

                _variable = &data[(*shift) + 1];
                _output   = NULL;
                break;

            case '}':
                if NULL_IS(_variable) {
                    LOG(error, "syntax error, string block containe end of variable without it start");
                    return rconfiguration_failed;
                }

                char _tmp = data[*shift];

                data[*shift] = '\0';

                sconfiguration_opts* _opt = _configuration_token_value_raw(_variable, opts);

                if NULL_IS(_opt) {
                    LOG(error, "unknown variable {%s} within string block", _variable);
                    return rconfiguration_failed;
                }

                data[*shift] = _tmp;

                _length += (_opt->value_length);
                _length -= (_opt->name_length + 2);

                _variable    = NULL;
                break;
        }

        ++_length;
    }

    if NULL_IS(_output) {
        if NULL_IS(_output = (char*)malloc(_length + 1)) {
            LOG(critical, "out of memory: string unescape [%lu]", (unsigned long)(_length + 1));
            return rconfiguration_failed;
        }

        parser->cleanup[parser->current] = 1;
    }

    parser->tokens[parser->current] = _output;

    size_t _length_raw = (size_t)(&data[*shift] - _begin);

    for (size_t _i = 0, _current = 0, _current_variable = 0; _i < _length_raw; ++_i)
        switch (_begin[_i]) {
            case '\\': 
                switch (_begin[++_i]) {
                    case 'n':
                        _begin[_i] = '\n';
                        break;

                    case 'r':
                        _begin[_i] = '\r';
                        break;

                    case 't':
                        _begin[_i] = '\t';
                        break;

                    case 'h':
                        hex(&(_begin[_i + 1]), &(_begin[_i + 2]));

                        _i += 2;
                        break;
                }

                _output[_current++] = _begin[_i];
                break;

            case '{' :
                _variable = &_begin[_i + 1];
                _current_variable = _current;
                break;

            case '}' : {
                _begin[_i] = '\0';

                sconfiguration_opts* _opt = _configuration_token_value_raw(_variable, opts);
                memcpy(&_output[_current_variable], _opt->value, _opt->value_length);
                _current = _current_variable + _opt->value_length;
                break;
            }

            default  :
                _output[_current++] = _begin[_i];
        }

    _output[_length] = '\0';
    return rconfiguration_ok;
}


static rconfiguration
configuration_line (
    BTH char**                  token,
    BTH sconfiguration*         cfg,
    BTH sconfiguration_opts**   opts
) {
    static const struct _token {
        char*           name;

        rconfiguration (*fnc) (
            char*               value,
            sconfiguration*     cfg
        );

    }  _tokens[] = {
            { "be",             configuration_token_be              }
        ,   { "statistics",     configuration_token_statistics      }
        ,   { "rtlink-hash",    configuration_token_rtlink_hash     }
        ,   { "reload",         configuration_token_reload          }
        ,   { "restore",        configuration_token_restore         }
        ,   { "buffer",         configuration_token_buffer          }
        ,   { "events",         configuration_token_events          }
        ,   { "source",         configuration_token_source          }
        ,   { "rate-limit",     configuration_token_ratelimit       }
        ,   { "m-group",        configuration_token_mgroup          }
        ,   { "no",             configuration_token_no              }
        ,   { "binding",        configuration_token_binding         }
        ,   { "sink",           configuration_token_sink            }
        ,   { "join",           configuration_token_join            }
        ,   { "allow",          configuration_token_allow           }
        ,   { "to",             configuration_token_to              }
        ,   { "port-range",     configuration_token_portrange       }
        ,   { "device",         configuration_token_device          }
        ,   { "port",           configuration_token_port            }
        ,   { "from",           configuration_token_from            }
        ,   { "ttl",            configuration_token_ttl             }
        ,   { "fwmark",         configuration_token_fwmark          }
        ,   { "tos",            configuration_token_tos             }
        ,   { "mtu",            configuration_token_mtu             }
        ,   { "security",       configuration_token_security        }
        ,   { "log",            configuration_token_log             }
        ,   { "directory",      configuration_token_directory       }
        ,   { "echo",           configuration_token_echo            }
        ,   { "noop",           configuration_token_noop            }
        ,   { NULL,             NULL                                }
    };

    char* _value = _configuration_token_value(token[1], opts);

    if NULL_IS(_value) {
        LOG(error, "unknown variable [%s] specified", token[1]);
        return rconfiguration_failed;
    }

    LOG(debug, "option: %s %s", token[0], _value);

    if (0 == strcasecmp("include", token[0]))
        return configuration_file(_value, cfg, opts);

    if (0 == strcasecmp("let", token[0]))
        return configuration_token_let(_value, opts);

    for (const struct _token* _token = _tokens; (NULL != _token->name) && (NULL != _token->fnc); ++_token)
        if (0 == strcasecmp(_token->name, token[0]))
            return _token->fnc(_value, cfg);

    LOG(error, "unknown configuration token %s", token[0]);
    return rconfiguration_failed;
}

static rconfiguration
configuration_prepaire_spacing (
    BTH char*                   data,
        size_t                  shift,
    BTH sconfiguration*         cfg,
    BTH sconfiguration_opts**   opts,
    BTH sconfiguration_parser*  parser
) {
    if (NULL != parser->tokens[parser->current]) {
        data[shift] = '\0';

        if (2 <= (++(parser->current))) {
            rconfiguration _return = configuration_line(parser->tokens, cfg, opts);
            if (rconfiguration_ok != _return)
                return _return;

            configuration_parser_cleanup(parser);
        }
    }

    return rconfiguration_ok;
}

static rconfiguration
configuration_prepaire (
        const char*             filename,
    BTH char*                   data,
        size_t                  length,
    BTH sconfiguration*         cfg,
    BTH sconfiguration_opts**   opts
) {
    size_t                  _line   = 1;

    rconfiguration          _return = rconfiguration_failed;
    size_t                  _i      = 0;
    sconfiguration_parser   _p;

    configuration_parser_initialize(&_p);

    while (1) {
        if (_i >= length) {
            if ((0 == _p.current)) break;

            if ((1 == _p.current) && (NULL == _p.tokens[_p.current])) {
                LOG(error, "unexcepted end of configuration file");
                goto _failure;
            }

            _return = configuration_line(_p.tokens, cfg, opts);
            if (rconfiguration_ok != _return)
                goto _failure;
 
            break;
        }

        switch (data[_i]) {
            case '"' : {
                if (NULL != _p.tokens[_p.current]) {
                    LOG(error, "string block must be start of token");
                    goto _failure;
                }

                _return = configuration_prepaire_unescape(data, length, &_i, opts, &_p);
                if (rconfiguration_ok != _return)
                    goto _failure;

                _return = configuration_prepaire_spacing(data, _i, cfg, opts, &_p);
                if (rconfiguration_ok != _return)
                    goto _failure;

                break;
            }

            case '\n':
            case '\r':
                if (0 < _i) {
                    if ((data[_i - 1] == data[_i]) || (data[_i - 1] != '\n' && data[_i - 1] != '\r'))
                        ++_line;

                } else {
                    ++_line;
                }

                if ((0 < _p.current) && (NULL == _p.tokens[_p.current])) {
                    LOG(error, "unexcepted line carriage after option but before value");
                    goto _failure;
                }

                _return = configuration_prepaire_spacing(data, _i, cfg, opts, &_p);
                if (rconfiguration_ok != _return)
                    goto _failure;

                break;

            case ' ' :
            case '\t':
                _return = configuration_prepaire_spacing(data, _i, cfg, opts, &_p);
                if (rconfiguration_ok != _return)
                    goto _failure;

                break;

            case '#' :
                while (_i < length && data[_i] != '\n' && data[_i] != '\r')
                    ++_i;

                break;

            default:
                if NULL_IS(_p.tokens[_p.current])
                    _p.tokens[_p.current] = &data[_i];

                break;
        }

        ++_i;
    }

    configuration_parser_cleanup(&_p);
    return rconfiguration_ok;

    _failure:
        LOG(error, "^ line %lu in [%s]", (unsigned long)_line, filename);
        configuration_parser_cleanup(&_p);
        return _return;
}

static rconfiguration
configuration_file (
        const char*             filename,
    BTH sconfiguration*         cfg,
    BTH sconfiguration_opts**   opts
) {
    sconfiguration_opts*    _opts_detach = (*opts);

    LOG(debug, "configuration file [%s]", filename);

    FILE* _file = fopen(filename, "rb");
    if NULL_IS(_file) {
        LOG(error, "can't open configuration file [%s]", filename);
        return rconfiguration_failed;
    }

    fseek(_file, 0, SEEK_END);

    size_t _length = ftell(_file);
    if (1 > _length) {
        LOG(error, "empty configuration file [%s]", filename);
        goto _error;
    }

    fseek(_file, 0, SEEK_SET);

    char* _data = (char*)malloc(_length + 1);
    if NULL_IS(_data) {
        LOG(critical, "out of memory: file loading [%lu]", (unsigned long)(_length + 1));
        goto _error;
    }

    if (_length != fread(_data, 1, _length, _file)) {
        LOG(error, "can't read configuration file [%s]", filename);
        goto _error;
    }

    _data[_length] = '\0';

    fclose(_file);

    rconfiguration _r = configuration_prepaire(filename, _data, _length, cfg, opts);

    //cleanup opts due to saved _opts_detach
    while ( (NULL != (*opts)) && (_opts_detach != (*opts)) ) {
        sconfiguration_opts* _c = (*opts);
        (*opts) = _c->next;

        free(_c);
    }

    free(_data);
    return _r;

    _error:
        fclose(_file);
        return rconfiguration_failed;
}

static rconfiguration
configuration_check (
    BTH sconfiguration*         cfg
) {
    if (1 > cfg->buffer_size) {
        LOG(error, "buffer value too small!");
        return rconfiguration_failed;
    }

    if NULL_IS(cfg->sources) {
        LOG(error, "configuration file doesn't containe any sources");
        return rconfiguration_failed;
    }

    size_t _sources = 0;

    for (ssource* _source = cfg->sources; NULL != _source; _source = _source->next) {
        /* check for sources without sinks - it's garbage */
        if NULL_IS(_source->sinks) {
            LOG(error, "source doesn't containe any sinks");
            LOG(error, " ^ can't relay packets to nowhere");

            return rconfiguration_failed;
        }

        /*  check for sources with sinks:
            if allow doesn't specified and only one sink - it's garbage
        */

        if NULL_IS(_source->allow)
            if ( NULL_IS(_source->sinks->next) && ('\0' == _source->ss.configuration.device[0]) && (_source->mgroups == NULL) ) {
                LOG(error, "source containe only one sink without:");
                LOG(error, "... allowed networks and device binding or m-group");
                LOG(error, " ^ can't relay packets to self");

                return rconfiguration_failed;
            }

        if (esource_type_raw == _source->type)
            if NULL_IS(_source->portrange) {
                LOG(error, "with raw source you MUST specify portrange");

                return rconfiguration_failed;
            }

        ++_sources;
    }

    if (0 == cfg->events) {//if events automatic - calculate it from sources count
        cfg->events  = 1; //rtlink
        cfg->events += _sources;

        if (0 < cfg->reload)
            cfg->events += 1;

        if (0 < cfg->restore)
            cfg->events += 1;
    }

    LOG(verbose, "sources count            %10u", (unsigned int)_sources);
    LOG(verbose, "events count             %10u events", (unsigned int)cfg->events);
    LOG(verbose, "buffer size              %10u bytes", (unsigned int)cfg->buffer_size);
    LOG(verbose, "rtlink reload inverval   %10u seconds", (unsigned int)cfg->reload);
    LOG(verbose, "sources restore inverval %10u seconds", (unsigned int)cfg->restore);

    return rconfiguration_ok;
}

#define _CFG_OPT_SILENT         (1)
#define _CFG_OPT_VERBOSE        (2)
#define _CFG_OPT_DEBUG          (3)
#define _CFG_OPT_LOG_NO_DATE    (4)

rconfiguration
configuration (
        int                     argc,
    IN  char**                  argv,
    OUT sconfiguration*         cfg
) {
    static const char* const _opts = "vhuc:l:D:d:";
    static const struct option const _opts_long[] = {
            { "help",           no_argument,        NULL,   'h'                     }
        ,   { "version",        no_argument,        NULL,   'v'                     }
        ,   { "usage",          no_argument,        NULL,   'u'                     }
        ,   { "configuration",  required_argument,  NULL,   'c'                     }
        ,   { "log",            required_argument,  NULL,   'l'                     }
        ,   { "directory",      required_argument,  NULL,   'd'                     }
        ,   { "silent",         no_argument,        NULL,   _CFG_OPT_SILENT         }
        ,   { "verbose",        no_argument,        NULL,   _CFG_OPT_VERBOSE        }
        ,   { "debug",          no_argument,        NULL,   _CFG_OPT_DEBUG          }
        ,   { "log-no-date",    no_argument,        NULL,   _CFG_OPT_LOG_NO_DATE    }
        ,   { "define",         required_argument,  NULL,   'D'                     }
        ,   { NULL,             no_argument,        NULL,    0                      }
    };

    char*                _cfg_file = NULL;
    sconfiguration_opts* _cfg_opts = NULL;

    int _a      =  0;
    int _option = -1;

    while (0 < (_option = getopt_long(argc, argv, _opts, _opts_long, &_a)))
        switch (_option) {
            case 'c':
                if (NULL != _cfg_file) {
                    LOG(error, "configuration file already specified");
                    goto _failure;
                }

                if NULL_IS(_cfg_file = strdup(optarg)) {
                    LOG(critical, "out of memory");
                    goto _failure;
                }

                break;

            case 'l':
                if (NULL != cfg->log) {
                    LOG(error, "log file already specified");
                    goto _failure;
                }

                if NULL_IS(cfg->log = strdup(optarg)) {
                    LOG(critical, "out of memory");
                    goto _failure;
                }

                break;

            case 'd':
                if (NULL != cfg->directory) {
                    LOG(error, "directory already specified");
                    goto _failure;
                }

                if NULL_IS(cfg->directory = strdup(optarg)) {
                    LOG(critical, "out of memory");
                    goto _failure;
                }

                break;

            case 'D': {
                char* _option = strdup(optarg);
                char* _value = _configuration_token_let_parse(_option);

                if NULL_IS(_value) {
                    LOG(critical, "can't parse --define|-D value");
                    free(_option);
                    goto _failure;
                }

                _configuration_token_let_push(&_cfg_opts, _option, _value);
                break;
            }

            case 'v':
            case 'u':
            case 'h':
                configuration_help(argv[0]);
                goto _failure;

            case _CFG_OPT_VERBOSE:
                log_unsuppress(LOGGING_VERBOSE);
                break;

            case _CFG_OPT_DEBUG:
                log_unsuppress(LOGGING_DEBUG);
                break;

            case _CFG_OPT_SILENT:
                log_suppress(LOGGING_SILENT_SUPPRESS);
                break;

            case _CFG_OPT_LOG_NO_DATE:
                log_suppress(LOG_LEVEL_MASK(LOG_DATE));
                break;

            default:
                LOG(error, "can't parse command line, try to read --help");
                goto _failure;
        }


    if NULL_IS(_cfg_file) {
        LOG(error, "you must specify configuration file, try to read --help");
        goto _failure;
    }

    rconfiguration _r = configuration_file(_cfg_file, cfg, &_cfg_opts);

    while (NULL != _cfg_opts) {
        sconfiguration_opts* _c = _cfg_opts;
        _cfg_opts = _cfg_opts->next;

        free(_c->name);
        free(_c);
    }

    free(_cfg_file);

    if (rconfiguration_ok != _r)
        return rconfiguration_failed;

    return configuration_check(cfg);

    _failure:
        while (NULL != _cfg_opts) {
            sconfiguration_opts* _c = _cfg_opts;
            _cfg_opts = _cfg_opts->next;

            free(_c->name);
            free(_c);
        }

        return rconfiguration_failed;
}

static void
_configuration_cleanup_portrange (
    BTH sipv4_portrange*        range
) {
    for (sipv4_portrange* _range = range; NULL != _range; ) {
        sipv4_portrange* _c_range = _range;
        _range = _range->next;
        free(_c_range);
    }
}

static void
configuration_cleanup_allow (
    BTH sipv4_allow*            allow
) {
    for (sipv4_allow* _allow = allow; NULL != _allow; ) {
        for (sipv4_allow_to* _to = _allow->allow_to; NULL != _to; ) {
            sipv4_allow_to* _c_to = _to;
            _to = _to->next;

            _configuration_cleanup_portrange(_c_to->portrange);
            free(_c_to);
        }

        sipv4_allow* _c_allow = _allow;
        _allow = _allow->next;
        free(_c_allow);
    }
}

void
configuration_cleanup (
    BTH sconfiguration*         cfg
) {
    if (NULL != cfg->log)
        free(cfg->log);

    if (NULL != cfg->directory)
        free(cfg->directory);

    for (ssource* _source = cfg->sources; NULL != _source; ) {
        for (ssink* _sink = _source->sinks; NULL != _sink; ) {
            configuration_cleanup_allow(_sink->allow);

            ssink* _c_sink = _sink;
            _sink = _sink->next;

            _configuration_cleanup_portrange(_c_sink->portrange);
            free(_c_sink);
        }

        for (smgroup* _mgroup = _source->mgroups; NULL != _mgroup; ) {
            smgroup* _c_mgroup = _mgroup;
            _mgroup = _mgroup->next;

            free(_c_mgroup);
        }

        configuration_cleanup_allow(_source->allow);

        ssource* _c_source = _source;
        _source = _source->next;

        if (NULL != _c_source->ratelimit)
            free(_c_source->ratelimit);

        _configuration_cleanup_portrange(_c_source->portrange);
        free(_c_source);
    }
}
