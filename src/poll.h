/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#if !defined(BPROXY_POLL)
#define BPROXY_POLL

#include "bproxy.h"
#include "socket.h"

#include <time.h>

typedef
struct _pollable        spollable;

typedef
struct _poll            spoll;

typedef
struct _poll_thread     spoll_thread;

typedef
struct _poll_passthrou  spoll_passthrou;

#define FPOLLABLE_IN            (1)
#define FPOLLABLE_OUT           (2)
#define FPOLLABLE_ERR           (4) 
#define FPOLLABLE_HUP           (8) 
#define FPOLLABLE_BTH           (FPOLLABLE_IN | FPOLLABLE_OUT)

typedef
enum {
        rpoll_handler_ok        = 0
    ,   rpoll_handler_failed
} rpoll_handler;

typedef
rpoll_handler (*fpollable_handler) (
        spollable*          pollable,
        uint32_t            flags,
        spoll_passthrou*    passthrou
);

struct _pollable {
    socket_t                socket;
    fpollable_handler       handler;
    uint32_t                flags;  
    spoll*                  poll;
};

struct _poll {
    socket_t                epoll;
};

struct _poll_thread {
    spoll*                  poll;

    ubyte_t*                buffer;
    size_t                  buffer_size;

    //epoll specific
    struct epoll_event*     events;
    size_t                  events_size;
};

struct _poll_passthrou {
    ubyte_t*                buffer; //threads shared buffer
    size_t                  length; 

    struct timespec         time;
};

typedef
enum {
        rpoll_ok                = 0
    ,   rpoll_timeout
    ,   rpoll_interrupted
    ,   rpoll_failed
} rpoll;

static inline void
pollable_initialize (
    OUT spollable*          pollable,
        spoll*              poll,
        fpollable_handler   handler,
        socket_t            socket,
        uint32_t            flags
) {
    pollable->poll    = poll;
    pollable->handler = handler;
    pollable->socket  = socket;
    pollable->flags   = flags;
}

static inline void
pollable_clear (
    OUT spollable*          pollable
) {
    pollable->handler = NULL;
    pollable->socket  = SOCKET_INVALID;
    pollable->poll    = NULL;
    pollable->flags   = 0;
}

static inline spoll*
pollable_poll (
    IN  spollable*          pollable
) { return pollable->poll; }

static inline void
pollable_poll_set (
    OUT spollable*          pollable,
        spoll*              poll
) { pollable->poll = poll; }

static inline socket_t
pollable_socket (
    IN  spollable*          pollable
) { return pollable->socket; }

static inline void
pollable_socket_set (
    OUT spollable*          pollable,
        socket_t            socket
) { pollable->socket = socket; }

rpoll
poll_create (
    OUT spoll*              poll
);

rpoll
poll_destroy (
    BTH spoll*              poll
);

rpoll
poll_thread_attach (
    OUT spoll_thread*       thread,
    BTH spoll*              poll,
        size_t              buffer_size,
        size_t              events_size
);

rpoll
poll_thread_detach (
    OUT spoll_thread*       thread,
    BTH spoll*              poll
);

rpoll
poll_attach (
    BTH spollable*          pollable
);

rpoll
poll_detach (
    BTH spollable*          pollable
);

rpoll
poll_wait (
    BTH spoll*              poll,
    BTH spoll_thread*       thread,
        uint64_t            timeout
);

#endif
