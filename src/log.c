/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#include "bproxy.h"
#include "log.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

static const char* const MODULE = "log";
static const char* const glog_level_printable[]  = {
        "d"
    ,   "v"
    ,   "i"
    ,   "w"
    ,   "e"
    ,   "c"
};

static uint32_t     glog_suppression = 0;
static FILE*        glog_file        = NULL;
static char*        glog_buffer      = NULL;

rlog
log_startup (
    uint32_t            mask
) {
    glog_buffer = (char*)malloc(LOG_BUFFER_SIZE);
    if NULL_IS(glog_buffer)
        return rlog_failed;

    glog_file        = stdout;
    glog_suppression = mask;

    fclose(stdin);
    fclose(stderr);

    return rlog_ok;
}

rlog
log_cleanup (
) { 
    log_write(elog_debug, MODULE, "cleanup");

    fflush(glog_file);
    free(glog_buffer); 
    return rlog_ok;
}

uint32_t
log_suppress (
        uint32_t        mask
) {
    uint32_t _old = glog_suppression;
    glog_suppression |= mask;
    return _old;
}

uint32_t
log_unsuppress (
        uint32_t        mask
) {
    uint32_t _old = glog_suppression;
    glog_suppression &= (~mask);
    return _old;
}

int
_log_write_va (
        elog            level,
        const char*     block,
        const char*     format,
        va_list         va
) {
    vsnprintf(glog_buffer, LOG_BUFFER_SIZE, format, va);
    glog_buffer[LOG_BUFFER_SIZE - 1] = 0;

    int _return = 0;

    if (glog_suppression & (1 << elog_LOG_DATE)) {
        _return = fprintf(glog_file, "[%s:%-14s] %s\n", glog_level_printable[level], block, glog_buffer);        

    } else {
        char        _buffer_time[32];
        struct tm   _tm;
        time_t      _time;

        time(&_time);
        localtime_r(&_time, &_tm);
        strftime(_buffer_time, sizeof(_buffer_time), "%Y/%m/%d %H%M.%S", &_tm);

        _return = fprintf(glog_file, "%s [%s:%-14s] %s\n", _buffer_time, glog_level_printable[level], block, glog_buffer);         
    }

    fflush(glog_file);

    return _return;
}

int
log_write (
        elog            level,
        const char*     block,
        const char*     format,
        ...
) {
    if (glog_suppression & (1 << level))
        return 0;

    va_list _va;
    va_start(_va, format);

    int _return = _log_write_va(level, block, format, _va);

    va_end(_va);

    return _return;
}

static inline char
_log_hex (
        char           byte
) { return (byte < 0x0A)?(byte + '0'):(byte + 'A' - 0x0A); }

int
log_binary (
        elog            level,
        const char*     block,
        const void*     buffer,
        size_t          length,
        const char*     format,
        ...
) {
    if (glog_suppression & (1 << level))
        return 0;

    static const char _delimiter_a[73] = "========================================================================\0";
    static const char _empty[73]       = "                                <EMPTY>                                 \0";
    static const char _delimiter_b[73] = "------------------------------------------------------------------------\0";

    char _buffer[73];
    int  _return        = 0;

    _buffer[72] = 0;

    _return += log_write(level, block, "%s", _delimiter_a);

    if STRING_NOT_NULL_IS(format) {
        va_list _a;
        va_start(_a, format);
        _return += _log_write_va(level, block, format, _a);
        va_end(_a);

        _return += log_write(level, block, "%s", _delimiter_b);
    }

    if (NULL_IS(buffer) || (length < 1)) {
        _return += log_write(level, block, "%s", _empty);
        _return += log_write(level, block, "%s", _delimiter_a);
        return _return;
    }

    #define __LOG_ADDR "ADDR  "
    memcpy(_buffer, __LOG_ADDR, sizeof(__LOG_ADDR) - 1);
    #undef __LOG_ADDR

    for (size_t _i = 0; _i < 16; _i++) {
        _buffer[_i*3 + 6] = '+';
        _buffer[_i*3 + 7] = _log_hex(_i & 0x0F);
        _buffer[_i*3 + 8] = ' ';

        _buffer[_i + 56]  = _log_hex(_i & 0x0F);
    }

    _buffer[54]  = '|';
    _buffer[55]  = ' ';
    
    _return += log_write(level, block, "%s", _buffer);
    _return += log_write(level, block, "%s", _delimiter_b);

    for (size_t _i = 0; _i < length; ) {
        memset(_buffer, ' ', sizeof(_buffer) - 1);

        _buffer[54] = '|';

        _buffer[0]  = _log_hex((_i & 0xF000) >> 12);
        _buffer[1]  = _log_hex((_i & 0x0F00) >>  8);
        _buffer[2]  = _log_hex((_i & 0x00F0) >>  4);
        _buffer[3]  = _log_hex((_i & 0x000F) >>  0);
        _buffer[4] = ':';

        for (size_t _ii = 0; (_ii < 16) && (_i < length); _i++, _ii++ ) {
            _buffer[_ii * 3 + 6] = _log_hex((((const char*)buffer)[_i] & 0xF0) >> 4);
            _buffer[_ii * 3 + 7] = _log_hex((((const char*)buffer)[_i] & 0x0F) >> 0);

            if (((const char*)buffer)[_i] >= 0x21 && ((const char*)buffer)[_i] <= 0x7E)
                _buffer[_ii + 56] = ((const char*)buffer)[_i];
        }

        _return += log_write(level, block, "%s", _buffer);
    }

    _return += log_write(level, block, "%s", _delimiter_a);

    return _return;
}

rlog
log_reopen (
        const char*     filename
) {
    if NULL_IS(filename)
        return rlog_failed;

    FILE* _file = fopen(filename, "a");
    FILE* _old  = glog_file;

    if NULL_IS(_file) {
        log_write(elog_error, MODULE, "can't open file [%s] for writing", filename);
        return rlog_failed;
    }

    glog_file = _file;

    fclose(_old);

    log_write(elog_debug, MODULE, "file changed to %s", filename);
    return rlog_ok;
}
