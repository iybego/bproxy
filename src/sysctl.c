/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#define SYSCTL_BUFFER_SIZE_READ     (128)
#define SYSCTL_PATH_BUFFER_SIZE     (256)

#define SYSCTL_PATH                 "/proc/sys/"
#define SYSCTL_PATH_SIZE            (sizeof(SYSCTL_PATH) - 1)

#include "sysctl.h"

#include <stdio.h>

#include "errno.h"
#include "log.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

LOG_MODULE("sysctl");

rsysctl
sysctl_path (
    OUT char*                   buffer,
        size_t                  length,
        const char*             path
) {
    if (SYSCTL_PATH_SIZE >= length)
        return rsysctl_failed;

    memcpy(buffer, SYSCTL_PATH, SYSCTL_PATH_SIZE);
    
    size_t _iterator = 0;
    size_t _write    = SYSCTL_PATH_SIZE;
    
    FOREVER {
        if (_write >= length)
            return rsysctl_failed;
            
        switch (path[_iterator]) {
            case '/':
                buffer[_write++] = '.';
                break;
            
            case '.':
                buffer[_write++] = '/';
                break;
                
            default :
                buffer[_write++] = path[_iterator];
                break;                
            
            case '\0':
                buffer[_write] = '\0';
                return rsysctl_ok;
        }
        
        ++_iterator;
    }
    
    LOG(error, "unexcepted code flow!");
    return rsysctl_failed;
}

rsysctl
sysctl_read_raw (
    OUT void*                   buffer,
        size_t                  length,
        const char*             path
) {
    char _path[SYSCTL_PATH_BUFFER_SIZE];
        
    if (rsysctl_ok != sysctl_path(_path, sizeof(_path), path)) {
        LOG(error, "can't fixup path %s", path);
        return rsysctl_failed;
    }
    
    LOG(debug, "path [%s] fixed as [%s]", path, _path);
    
    int _file = open(_path, O_RDONLY);
    
    if (0 > _file) {
        LOG ( error
            , "can't open %s" PRIerrno
            , _path, DPRIerrno
        );

        return rsysctl_failed;
    }

    FOREVER {
        ssize_t _read = read(_file, buffer, length);

        if (0 > _read) {
            if EINTR_IS(errno) continue;

            close(_file);

            LOG ( error
                , "error occured while reading %s" PRIerrno
                , path, DPRIerrno
            );

            return rsysctl_failed;
        }

        close(_file);

        if ((0 == _read) || (length <= (unsigned)_read)) {
            LOG(error, "looks like %s broken", path);
            return rsysctl_failed;
        }
        
        return rsysctl_ok;
    }
    
    LOG(error, "unreachable code flow");
    return rsysctl_failed;
}

rsysctl
sysctl_read (
    OUT void*                   buffer,
        const char*             format,
        const char*             path
) {
    char _buffer[SYSCTL_BUFFER_SIZE_READ];
    
    if (rsysctl_ok != sysctl_read_raw(&_buffer, sizeof(_buffer), path))
        return rsysctl_failed;
    
    _buffer[sizeof(_buffer) - 1] = '\0'; //paranoic
    
    if (1 > sscanf(_buffer, format, buffer)) {
        LOG(debug, "wrong value for %s [%s] in %s", format, _buffer, path);
        return rsysctl_failed;
    }
    
    return rsysctl_ok;
}

