/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#if !defined(BPROXY_RATELIMIT)
#define BPROXY_RATELIMIT

#include "bproxy.h"

#include <time.h>

typedef
enum {
        rratelimit_allowed
    ,   rratelimit_discarded
} rratelimit;

typedef
struct _ratelimit {
    uint32_t            rate;
    uint32_t            window;

    uint64_t            time;
    uint32_t            value;
} sratelimit;

static inline void
ratelimit_initialize (
    OUT sratelimit*     ratelimit,
        uint32_t        rate,
        uint32_t        window
) {
    ratelimit->rate     = rate;
    ratelimit->window   = window;
    ratelimit->time     = 0;
    ratelimit->value    = 0;
}

static inline rratelimit
ratelimit (
    BTH sratelimit*         ratelimit,
        uint32_t            value,
        struct timespec*    current
) {
    uint64_t _time       = (current->tv_sec * 1000) + (current->tv_nsec / (1000 * 1000));
    uint64_t _time_shift = (_time - ratelimit->time);

    uint32_t _value = ratelimit->rate;

    if (_time_shift < ratelimit->window)
        _value = ((_time_shift * ratelimit->rate) / ratelimit->window);

    if (0 < _value) {
        if (ratelimit->rate < (ratelimit->value += _value))
            ratelimit->value = ratelimit->rate;

        ratelimit->time = _time;
    }

    if (ratelimit->value < value)
        return rratelimit_discarded;

    ratelimit->value -= value;
    return rratelimit_allowed;
}

#endif
