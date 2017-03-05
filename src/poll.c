/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#include "poll.h"
#include "log.h"

#include <sys/epoll.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

LOG_MODULE("poll");

rpoll
poll_create (
    OUT spoll*              poll
) {
    if SOCKET_INVALID_IS(poll->epoll = epoll_create1(0)) {
        LOG(error, "can't create epoll cuz' %d [%s]", errno, strerror(errno));
        return rpoll_failed;
    }

    return rpoll_ok;
}

rpoll
poll_destroy (
    BTH spoll*              poll
) {
    close(poll->epoll);
    return rpoll_ok;
}

rpoll
poll_thread_attach (
    OUT spoll_thread*       thread,
    BTH spoll*              poll,
        size_t              buffer_size,
        size_t              events_size
) {
    (void)poll;

    thread->buffer      = NULL;
    thread->buffer_size = buffer_size;

    thread->events      = NULL;
    thread->events_size = events_size;

    if NULL_IS(thread->buffer = malloc(buffer_size)) {
        LOG(error, "out of memory: buffer [%lu]", (unsigned long)buffer_size);
        goto _failed_buffer;
    }

    if NULL_IS(thread->events = malloc(sizeof(struct epoll_event) * events_size)) {
        LOG(error, "out of memory: events [%lu]", (unsigned long)(sizeof(struct epoll_event) * events_size));
        goto _failed_events;
    }

    return rpoll_ok;

    _failed_events:
        free(thread->buffer);
        thread->buffer = NULL;

    _failed_buffer:
        return rpoll_failed;
}

rpoll
poll_thread_detach (
    OUT spoll_thread*       thread,
    BTH spoll*              poll
) {
    (void)poll;

    free(thread->buffer);
    free(thread->events);

    thread->buffer = NULL;
    thread->events = NULL;

    return rpoll_ok;
}

rpoll
poll_attach (
    BTH spollable*          pollable
) {
    struct epoll_event _event;
    _event.events   = EPOLLERR | EPOLLHUP;
    _event.data.ptr = (void*)pollable;

    if (FPOLLABLE_IN  & pollable->flags)
        _event.events |= EPOLLIN;

    if (FPOLLABLE_OUT & pollable->flags)
        _event.events |= EPOLLOUT;

    if (0 > epoll_ctl(pollable->poll->epoll, EPOLL_CTL_ADD, pollable->socket, &_event)) {
        LOG(error, "can't add socket into epoll cuz' %d [%s]", errno, strerror(errno));
        return rpoll_failed;
    }

    return rpoll_ok;
}

rpoll
poll_detach (
    BTH spollable*          pollable
) {
    struct epoll_event _event;
    memset(&_event, 0, sizeof(_event)); //see BUGS section in man 2 epoll_ctl

    if (0 > epoll_ctl(pollable->poll->epoll, EPOLL_CTL_DEL, pollable->socket, &_event)) {
        LOG(error, "can't remove socket from epoll cuz' %d [%s]", errno, strerror(errno));
        return rpoll_failed;
    }

    return rpoll_ok;
}

rpoll
poll_wait (
    BTH spoll*              poll,
    BTH spoll_thread*       thread,
        uint64_t            timeout
) {
    int _r_epoll = epoll_wait(poll->epoll, thread->events, thread->events_size, timeout);

    if (0 > _r_epoll) {
        if EINTR_IS(errno)
            return rpoll_interrupted;

        LOG(error, "error occured: %d [%s]", errno, strerror(errno));
        return rpoll_failed;
    }

    if (0 == _r_epoll)
        return rpoll_timeout;

    spoll_passthrou _passthrou = {
            thread->buffer
        ,   thread->buffer_size
        ,   { 0, 0 }
    };

    if (0 > clock_gettime(CLOCK_MONOTONIC, &(_passthrou.time))) {
        LOG(error, "can't get current time, cuz' %d [%s]", errno, strerror(errno));
        return rpoll_failed;
    }

    for (size_t _i = 0; _i < (unsigned)_r_epoll; ++_i) {
        spollable* _pollable = (spollable*)thread->events[_i].data.ptr;
        uint32_t   _flags    = 0;

        if (thread->events[_i].events & EPOLLIN )
            _flags |= FPOLLABLE_IN;

        if (thread->events[_i].events & EPOLLOUT)
            _flags |= FPOLLABLE_OUT;

        if (thread->events[_i].events & EPOLLHUP)
            _flags |= FPOLLABLE_HUP;

        if (thread->events[_i].events & EPOLLERR)
            _flags |= FPOLLABLE_ERR;

        rpoll_handler _r_handler  = _pollable->handler(_pollable, _flags, &_passthrou);

        switch (_r_handler) {
            case rpoll_handler_ok:
                continue;

            case rpoll_handler_failed:
                LOG(error, "handler raise error");
                return rpoll_failed;
        }
    }

    return rpoll_ok;
}
