/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#include "timer.h"
#include "log.h"

#include <errno.h>
#include <string.h>

#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/timerfd.h>

LOG_MODULE("timer");

#if !defined(CLOCK_MONOTONIC)
    #define CLOCK_MONOTONIC     (1)
#endif

static inline socket_t
_timer_socket (
    IN  stimer*             timer
) { return pollable_socket(&(timer->pollable)); }

rpoll_handler
_timer_poll_handler (
        spollable*          pollable,
        uint32_t            flags,
        spoll_passthrou*    passthrou
) {
    stimer* _timer = CONTAINEROF(pollable, stimer, pollable);

    LOG(debug, "timer occured %p", _timer);

    if (0 != (flags & (FPOLLABLE_ERR | FPOLLABLE_HUP))) {
        //TODO(iybego#9): restart timer
        LOG(error, "timer failed %p", _timer);
        return rpoll_handler_ok;
    }

    FOREVER {
        int _r = read(_timer_socket(_timer), passthrou->buffer, passthrou->length);  

        if (0  > _r) {
            if EINTR_IS      (errno) continue;
            if EAGAIN_IS     (errno) return rpoll_handler_ok;
            if EWOULDBLOCK_IS(errno) return rpoll_handler_ok;

            LOG(error, "timer error occured %d [%s]", errno, strerror(errno));
            return rpoll_handler_failed;
        }

        if (0 == _r) return rpoll_handler_ok;

        if (rtimer_ok != _timer->callback(_timer))
            return rpoll_handler_failed;
    }

    return rpoll_handler_ok;
}

rtimer
timer_startup (
    OUT stimer*             timer,
    BTH spoll*              poll,
        ftimer_callback     callback
) {
    socket_t _socket = timerfd_create(CLOCK_MONOTONIC, 0);
    if SOCKET_INVALID_IS(_socket) {
        LOG(error, "can't create timer fd, cuz' %d [%s]", errno, strerror(errno));
        return rtimer_failed;
    }

    int _flags = fcntl(_socket, F_GETFL, 0);
    if (0 > _flags) {
        LOG(error, "can't get timer fd flags, cuz' %d [%s]", errno, strerror(errno));
        goto _error;
    }

    if (0 > fcntl(_socket, F_SETFL, _flags | O_NONBLOCK)) {
        LOG(error, "can't set timer fd flags, cuz' %d [%s]", errno, strerror(errno));
        goto _error;
    }

    pollable_initialize(&(timer->pollable), poll, _timer_poll_handler, _socket, FPOLLABLE_IN);
    timer->callback = callback;

    return rtimer_ok;

    _error:
        close(_socket);
        return rtimer_failed;
}

rtimer
timer_arm (
    BTH stimer*             timer,
        uint64_t            shift
) {
    struct itimerspec _time;
    memset(&_time.it_interval, 0, sizeof(_time.it_interval)); 

    if (0 > clock_gettime(CLOCK_MONOTONIC, &(_time.it_value))) {
        LOG(error, "can't get current time, cuz' %d [%s]", errno, strerror(errno));
        return rtimer_failed;
    }

    _time.it_value.tv_sec += (shift / TIMER_SHIFT_SEC);

    if (999999999 <= (_time.it_value.tv_nsec += ((shift % TIMER_SHIFT_SEC) * 100))) {
        _time.it_value.tv_sec  += (_time.it_value.tv_nsec / 1000000000);
        _time.it_value.tv_nsec  = (_time.it_value.tv_nsec % 1000000000);
    }

    if (0 > timerfd_settime(_timer_socket(timer), TFD_TIMER_ABSTIME, &_time, NULL)) {
        LOG(error, "arm failed, cuz %d [%s]", errno, strerror(errno));
        return rtimer_failed;
    }

    return rtimer_ok;
}

rtimer
timer_disarm (
    BTH stimer*             timer
) {
    struct itimerspec _time;
    memset(&_time, 0, sizeof(_time));

    if (0 > timerfd_settime(_timer_socket(timer), 0, &_time, NULL)) {
        LOG(error, "disarm failed, cuz' %d [%s]", errno, strerror(errno));
        return rtimer_failed;
    }

    return rtimer_ok;
}

rtimer
timer_attach (
    BTH stimer*             timer
) {
    if (rpoll_ok != poll_attach(&(timer->pollable)))
        return rtimer_failed;

    return rtimer_ok;
}

rtimer
timer_detach (
    BTH stimer*             timer
) {
    if (rpoll_ok != poll_detach(&(timer->pollable)))
        return rtimer_failed;

    return rtimer_ok;
}

rtimer
timer_cleanup (
    BTH stimer*             timer
) {
    close(pollable_socket(&(timer->pollable)));
    return rtimer_ok;
}

static rtimer
_timer_simple_callback (
    stimer*             timer
) {
    stimer_simple* _simple = CONTAINEROF(timer, stimer_simple, timer);
    return _simple->callback(_simple, _simple->passthrou);
}

rtimer
timer_simple_startup (
    OUT stimer_simple*          timer,
    BTH spoll*                  poll,
        ftimer_simple_callback  callback,
        void*                   passthrou
) {
    if (rtimer_ok != timer_startup(&(timer->timer), poll, _timer_simple_callback))
        return rtimer_failed;

    if (rtimer_ok != timer_attach(&(timer->timer))) {
        timer_cleanup(&(timer->timer));
        return rtimer_failed;
    }

    timer->passthrou = passthrou;
    timer->callback  = callback;
    return rtimer_ok;
}

rtimer
timer_simple_cleanup (
    BTH stimer_simple*          timer
) {
    timer_detach(&(timer->timer));
    timer_cleanup(&(timer->timer));
    return rtimer_ok;
}

