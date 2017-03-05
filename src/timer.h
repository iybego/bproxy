/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#if !defined(BRPOXY_TIMER)
#define BPROXY_TIMER

#include "bproxy.h"
#include "poll.h"

typedef
struct _timer       stimer;

typedef
enum {
        rtimer_ok           = 0
    ,   rtimer_failed
} rtimer;

typedef
rtimer (*ftimer_callback) (
        stimer*             timer
);

struct _timer {
    spollable           pollable;
    ftimer_callback     callback;
};


rtimer
timer_startup (
    OUT stimer*             timer,
    BTH spoll*              poll,
        ftimer_callback     callback
);

#define TIMER_SHIFT_SEC     (1000 * 1000 * 100)
#define TIMER_SHIFT_MSEC    (1000 * 100)
#define TIMER_SHIFT_USEC    (100)

rtimer
timer_arm (
    BTH stimer*             timer,
        uint64_t            shift   //100 nsecs
);

rtimer
timer_disarm (
    BTH stimer*             timer
);

rtimer
timer_attach (
    BTH stimer*             timer
);

rtimer
timer_detach (
    BTH stimer*             timer
);

rtimer
timer_cleanup (
    BTH stimer*             timer
);

//simple

typedef
struct _timer_simple stimer_simple;

typedef
rtimer (*ftimer_simple_callback) (
        stimer_simple*          timer,
        void*                   passthrou
);

struct _timer_simple {
    stimer                  timer;
    ftimer_simple_callback  callback;
    void*                   passthrou;
};

rtimer
timer_simple_startup (
    OUT stimer_simple*          timer,
    BTH spoll*                  poll,
        ftimer_simple_callback  callback,
        void*                   passthrou
);

rtimer
timer_simple_cleanup (
    BTH stimer_simple*          timer
);

static inline rtimer
timer_simple_arm (
    BTH stimer_simple*          timer,
        uint64_t                shift   //100 nsecs
) { return timer_arm(&(timer->timer), shift); }

static inline rtimer
timer_simple_disarm (
    BTH stimer_simple*          timer
) { return timer_disarm(&(timer->timer)); }

#endif

