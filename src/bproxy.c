/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

/** TODO(ideas, but i too lazy for it):
        track statistics

        reload (SIGHUP)
            change @gcfg to pointer
            reload request, try:
                - load configuration to new sconfiguration structure (memory usage at this step?)
                - replace current @gcfg with new
                - cleanup old @gcfg

        allow to set limits to sources recvmsg loop (max packets per tick):
            some "fair play" for sources, cuz' we can "block" in recv loop
            ... if some source receive packets faster that relay

            - DONE PARTIALY: hardcoded value

        allow to answer with icmp time exceed & fragmentation

        allow to use routing table as sink addresses table
            reason for it is strongswan, wich doesn't add any addresses to ipsec0
            but add it to routing table 220 [192.168.2.2 dev ipsec0 proto static]
            so we can add something like filters for routing-table, like
                > sink "table:220" # get device from sinks \"device\" option
**/

#include "bproxy.h"

#include "configuration.h"
#include "log.h"
#include "socket.h"

#include "poll.h"
#include "rtlink.h"
#include "timer.h"

#include <string.h>

#include <netinet/in.h>
#include <signal.h>
#include <unistd.h>

#include <errno.h>

#include <stdio.h>

LOG_MODULE("bproxy");

#define FWORKING                (1)
#define FRELOAD_CONFIGURATION   (2)

static int              gworking = FWORKING;
static sconfiguration   gcfg;

static void
main_sighandler (
        int                 signal
) {
    switch (signal) {
        default:
            if (0 == (FWORKING & gworking)) {
                LOG(error, "signaled twice, halting!");
                exit(4);
            }

            gworking &= ~(FWORKING | FRELOAD_CONFIGURATION);
            break;

        case SIGHUP:
            if (0 == (FRELOAD_CONFIGURATION & gworking))
                gworking |= FRELOAD_CONFIGURATION;

            break;

        case SIGUSR1:
            if (rlog_ok != log_reopen(gcfg.log))
                LOG(critical, "can't reopen log file");

            break;

        case SIGUSR2:
            sources_restart(gcfg.sources);
            break;
    }
}

static rtimer
main_timer_reload (
        stimer_simple*      timer,
        void*               passthrou
) {
    if (rnetlink_ok != rtlink_reload((srtlink*)passthrou))
        LOG(warning, "netlink reload failed");

    return timer_simple_arm(timer, gcfg.reload * TIMER_SHIFT_SEC);
}

static rtimer
main_timer_restore (
        stimer*             timer
) {
    sources_start(gcfg.sources);
    return timer_arm(timer, gcfg.restore * TIMER_SHIFT_SEC);
}

static rsysctl
main_sysctl_warmup(
) {
    rsysctl _return = rsysctl_ok;

    if (rsysctl_ok != ipv4_default_ttl(NULL)) {
        LOG(error, "can't warmup default ttl value");
        _return = rsysctl_failed;
    }

    if (rsysctl_ok != ipv4_minimum_pmtu(NULL)) {
        LOG(error, "can't warmup minimum_pmtu value");
        _return = rsysctl_failed;
    }

    return _return;
}

int
main (
        int                 argc,
        char**              argv
) {
    if (rlog_ok != log_startup(LOGGING_DEFAULT_SUPPRESS)) {
        fprintf(stderr, "critical: can't startup logging\n");
        return EXIT_FAILURE;
    }

    spoll           _poll;
    spoll_thread    _poll_thread;

    srtlink _rtlink;

    stimer_simple   _timer_rtlink_reload;
    stimer          _timer_sources;

    signal(SIGINT,  main_sighandler);
    signal(SIGTERM, main_sighandler);
    signal(SIGKILL, main_sighandler);

    signal(SIGHUP,  main_sighandler);
    signal(SIGUSR1, main_sighandler);
    signal(SIGUSR2, main_sighandler);

    int _exit_code = EXIT_FAILURE;

    configuration_initialize(&gcfg);
    if (rconfiguration_ok != configuration(argc, argv, &gcfg))
        goto _failure_configure;

    if (NULL != gcfg.directory) {
        if (0 > chdir(gcfg.directory)) {
            LOG(critical, "can't change directory, cuz' %d [%s]", errno, strerror(errno));
            goto _failure_directory;
        }

        free(gcfg.directory);
        gcfg.directory = NULL;
    }

    if (NULL != gcfg.log)
        if (rlog_ok != log_reopen(gcfg.log)) {
            LOG(critical, "can't reopen log\n");
            goto _failure_log_reopen;
        }

    if (rsysctl_ok != main_sysctl_warmup()) {
        LOG(critical, "can't warmup sysctl cache");    
        goto _failure_warmup_sysctl_cache;
    }

    if (rpoll_ok != poll_create(&_poll)) {
        LOG(critical, "can't work without poll");
        goto _failure_poll;
    }

    if (rpoll_ok != poll_thread_attach(&_poll_thread, &_poll, gcfg.buffer_size, gcfg.events)) {
        LOG(critical, "can't attach thread to poll");
        goto _failure_poll_thread;
    }

    if (rnetlink_ok != rtlink_create(&_rtlink, &_poll, gcfg.rtlink_hash)) {
        LOG(critical, "can't work without netlink:rtlink");
        goto _failure_rtlink;
    }

    if (rnetlink_ok != rtlink_attach(&_rtlink)) {
        LOG(critical, "can't attach netlink:rtlink to poll");
        goto _failure_rtlink_poll;
    }

    if (rsource_ok != sources_bootup(gcfg.sources, &_rtlink, &_poll)) {
        LOG(critical, "bootup failed");
        goto _failure_sources_bootup;
    }

    if (rtimer_ok != timer_simple_startup(&_timer_rtlink_reload, &_poll, main_timer_reload, &_rtlink)) {
        LOG(critical, "can't startup reload timer");
        goto _failure_timer_reload;
    }

    if (rtimer_ok != timer_startup(&_timer_sources, &_poll, main_timer_restore)) {
        LOG(critical, "can't startup restore timer");
        goto _failure_timer_sources;
    }

    if (rtimer_ok != timer_attach(&_timer_sources)) {
        LOG(critical, "can't attach restore timer");
        goto _failure_timer_sources_attach;
    }

    if (rnetlink_ok != rtlink_reload(&_rtlink)) {
        LOG(critical, "can't reload rtlink");
        goto _failure_rtlink_reload;
    }

    if (rsource_ok != sources_start(gcfg.sources)) {
        LOG(critical, "sources starting failed");
        goto _sources_startup;
    }

    if (0 != gcfg.reload)
        if (rtimer_ok != timer_simple_arm(&_timer_rtlink_reload, gcfg.reload * TIMER_SHIFT_SEC)) {
            LOG(critical, "can't arm reload timer");
            goto _failure_timer_arm;
        }

    if (0 != gcfg.restore)
        if (rtimer_ok != timer_arm(&_timer_sources, gcfg.restore * TIMER_SHIFT_SEC)) {
            LOG(critical, "can't arm restore timer");
            goto _failure_timer_arm;
        }

    LOG(information, "ready...");

    _exit_code = EXIT_SUCCESS;

    while (0 != (gworking & FWORKING)) switch (poll_wait(&_poll, &_poll_thread, -1)) {
        case rpoll_ok:
            break;

        case rpoll_timeout:
            break;

        case rpoll_interrupted:
            if (0 != (gworking & FRELOAD_CONFIGURATION)) {
                gworking &= ~(FRELOAD_CONFIGURATION);

                LOG(verbose, "reload requested");

                if (rsysctl_ok != main_sysctl_warmup())
                    LOG(warning, "sysctl warmup failed");

                //TODO(iybego#9): reload configuration
            }

            break;

        case rpoll_failed:
            LOG(error, "poll wait failed");
            goto _failure_loop;
    }

    LOG(information, "stoping...");

    _failure_loop:

    _failure_timer_arm:

    _sources_startup:

    _failure_rtlink_reload:

        timer_detach(&_timer_sources);
    _failure_timer_sources_attach:

        timer_cleanup(&_timer_sources);
    _failure_timer_sources:

        timer_simple_cleanup(&_timer_rtlink_reload);
    _failure_timer_reload:

        sources_cleanup(gcfg.sources, NULL);
    _failure_sources_bootup:

        rtlink_detach(&_rtlink);
    _failure_rtlink_poll:

        rtlink_destroy(&_rtlink);
    _failure_rtlink:

        poll_thread_detach(&_poll_thread, &_poll);
    _failure_poll_thread:

        poll_destroy(&_poll);
    _failure_poll:

    _failure_warmup_sysctl_cache:
    _failure_log_reopen:
    _failure_directory:
    _failure_configure:
        configuration_cleanup(&gcfg);

        LOG(information, "see ya later, stoped with %d", _exit_code);

        log_cleanup();
        return _exit_code;
}

