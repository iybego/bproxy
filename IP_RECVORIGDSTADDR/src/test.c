/**
    IP_RECVORIGDSTADDR autotest, part of [bproxy]
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016

    ritual:
      Bind to ANY [0.0.0.0] with automatic port selected
      Resolve binding @port

      Fork
        child   -> send uint16_t with @port to LOOPBACK [127.0.0.1]:@port
                   exit

        parent  -> wait child
                   try to receive packet
                   check received data
                   iterate over CMSG and check is IP_RECVORIGDSTADDR supplied
**/

#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>

#if     !defined(IP_TRANSPARENT)
    #warning hardcoded value used [IP_TRANSPARENT]
    #define IP_TRANSPARENT      (19)
#endif

#if     !defined(IP_ORIGDSTADDR)
    #warning hardcoded value used [IP_ORIGDSTADDR]
    #define IP_ORIGDSTADDR      (20)
#endif

#if     !defined(IP_RECVORIGDSTADDR)
    #warning hardcoded value used [IP_RECVORIGDSTADDR]
    #define IP_RECVORIGDSTADDR  (IP_ORIGDSTADDR)
#endif

#define __SOCKOPT(x, y, z, s, n, o)                                                                 \
    do { if (0 > setsockopt(_socket, x, y, z, s)) {                                                 \
        printf("can't set socket option [" n ", " o "], cuz' %d [%s]\n", errno, strerror(errno));   \
        goto _failure_close;                                                                        \
    } } while (0)

#define SOCKOPT(x, y, z)                                                                            \
    __SOCKOPT(x, y, &z, sizeof(z), #x, #y)

#define CONTROL_LENGTH (CMSG_SPACE(sizeof(struct sockaddr_in)))

int
child_do (
    uint16_t    port
) {
    struct sockaddr_in _target;

    memset(&_target, 0, sizeof(_target));

    _target.sin_family      = AF_INET;
    _target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    _target.sin_port        = port;

    int _socket = socket(AF_INET, SOCK_DGRAM, 0);

    if (0 > _socket) {
        printf("child: socket call failed, cuz' %d [%s]\n", errno, strerror(errno));
        return EXIT_FAILURE;
    }

    do {
        int _r = sendto(_socket, &port, sizeof(port), 0, (struct sockaddr*)&_target, sizeof(_target));

        if (0 > _r) {
            if (EINTR == errno) continue;

            printf("child: sendto failed, cuz' %d [%s]\n", errno, strerror(errno));

            close(_socket);
            return EXIT_FAILURE;
        }

        close(_socket);
        return EXIT_SUCCESS;

    } while (1);

    //unrechable
    return EXIT_FAILURE;
}

int
main (
    int         argc,
    char**      argv
) {
    (void)argc; (void)argv;

    int _enable = 1;
    int _return = EXIT_FAILURE;

    printf("\n==== testing [IP_RECVORIGDSTADDR]\n");

    int _socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (0 > _socket) {
        printf("socket call failed, cuz' %d [%s]\n", errno, strerror(errno));
        goto _failure_socket;
    }

    /*SOCKOPT(SOL_IP,     IP_TRANSPARENT,     _enable); */
    SOCKOPT(SOL_IP,     IP_RECVORIGDSTADDR, _enable);

    struct sockaddr_in _binding;
    socklen_t _binding_length = sizeof(_binding);

    memset(&_binding, 0, sizeof(_binding));

    _binding.sin_family         = AF_INET;
    _binding.sin_addr.s_addr    = htonl(INADDR_ANY);
    _binding.sin_port           = 0;

    if (0 > bind(_socket, (struct sockaddr*)&_binding, sizeof(_binding))) {
        printf("socket binding failed, cuz' %d [%s]\n", errno, strerror(errno));
        goto _failure_close;
    }

    if (0 > getsockname(_socket, (struct sockaddr*)&_binding, &_binding_length)) {
        printf("getsockname failed, cuz' %d [%s]\n", errno, strerror(errno));
        goto _failure_close;
    }

    if (sizeof(struct sockaddr_in) != _binding_length) {
        printf("binding length, wrong size %u, must be %u\n", (unsigned int)_binding_length, (unsigned int)sizeof(struct sockaddr_in));
        goto _failure_close;
    }

    printf("binded to port %d\n", (int)ntohs(_binding.sin_port));

    fflush(stdout);

    pid_t _child = fork();

    if (0 == _child)
        return child_do(_binding.sin_port);

    int _wstatus = 0;

    if (_child != wait(&_wstatus)) {
        printf("wrong child pid! its confusing!\n");

        kill(_child, SIGKILL);

        goto _failure_close;
    }

    if (0 == WIFEXITED(_wstatus)) {
        printf("child failed\n");
        goto _failure_close;
    }

    if (EXIT_SUCCESS != WEXITSTATUS(_wstatus)) {
        printf("child return wrong exit code\n");
        goto _failure_close;
    }

    do {
        char                _buffer[sizeof(uint16_t)];
        char                _control[CONTROL_LENGTH];
        struct iovec        _iov = {_buffer, sizeof(_buffer)};
        struct msghdr       _msg = { NULL, 0, &_iov, 1, _control, sizeof(_control), 0};

        int _length = recvmsg(_socket, &_msg, (MSG_TRUNC | MSG_CTRUNC | MSG_DONTWAIT));

        if (0 > _length) {
            if (EINTR       == errno) continue;

            #if defined(EWOULDBLOCK)
            if (EWOULDBLOCK == errno) {
                printf("no messages avalible, but child already stoped - this is strange");
                goto _failure_socket;
            }
            #endif

            #if defined(EAGAIN)
            if (EAGAIN      == errno) {
                printf("no messages avalible, but child already stoped - this is strange");
                goto _failure_socket;
            }
            #endif

            printf("recvmsg failed, cuz' %d [%s]\n", errno, strerror(errno));
            goto _failure_socket;
        }

        if (0 != (_msg.msg_flags & MSG_CTRUNC)) {
            printf("truncated cmsg!\n");
            goto _failure_socket;
        }

        if ((_length != sizeof(uint16_t)) || (0 != (_msg.msg_flags & MSG_TRUNC))) {
            printf("wrong received message length, ignored\n");
            continue;
        }

        if (0 != memcmp(_buffer, &(_binding.sin_port), sizeof(uint16_t))) {
            printf("wrong message received, ignored\n");
            continue;
        }

        for (struct cmsghdr* _cmsg = CMSG_FIRSTHDR(&_msg); NULL != _cmsg; _cmsg = CMSG_NXTHDR(&_msg, _cmsg)) {
            printf("cmsg received [level: %d, type: %d]\n", _cmsg->cmsg_level, _cmsg->cmsg_type);

            if ( (SOL_IP == _cmsg->cmsg_level) && (IP_ORIGDSTADDR == _cmsg->cmsg_type) ) {
                printf("IP_ORIGDSTADDR received\n");

                struct sockaddr_in* _destination = (struct sockaddr_in*)CMSG_DATA(_cmsg);

                if (0 != memcmp(&(_destination->sin_port), &(_binding.sin_port), sizeof(uint16_t))) {
                    uint16_t _port;
                    memcpy(&_port, &(_destination->sin_port), sizeof(uint16_t));

                    printf(" ^ wrong destination port %d!\n", (int)ntohs(_port));
                    goto _failure_socket;
                }

                uint32_t _address = htonl(INADDR_LOOPBACK);

                if (0 != memcmp(&(_destination->sin_addr.s_addr), &_address, sizeof(_address))) {
                    uint32_t _d_address;
                    memcpy(&_d_address, &(_destination->sin_addr.s_addr), sizeof(uint32_t));

                    printf(" ^ wrong destination address [%lx], must be [%lx]\n", (unsigned long int)_d_address, (unsigned long int)_address);
                    goto _failure_socket;
                }

                printf(" ^ looks like all ok! grats!\n");
                _return = EXIT_SUCCESS;
                goto _failure_close;
            }
        }

        printf("failure: [SOL_IP, IP_ORIGDSTADDR] doesn't exists in CMSG!\n");
        goto _failure_socket;

    } while (1);

    _failure_close:
        close(_socket);

    _failure_socket:

        if (EXIT_SUCCESS == _return) {
            printf("==== testing [OK]\n\n");
        } else {
            printf("==== testing [FAILED]\n\n");
        }

        return _return;
}
