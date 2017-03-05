/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#if !defined(BPROXY_UTILS)
#define BPROXY_UTILS

#include <time.h>

static inline char*
strcpy_l (
        char*                   destination,
        const char*             source,
        size_t                  length
) {
    size_t _i = 0;

    while (_i < length) {
        destination[_i] = source[_i];

        if ('\0' == source[_i])
            break;

        ++_i;
    }

    return &destination[_i];
}

static inline size_t
strlen_l (
        const char*             source,
        size_t                  length
) {
    size_t _i = 0;

    while ((_i < length) && ('\0' != source[_i]))
        ++_i;

    return _i;
}

static inline uint32_t
delta_u32 (
        uint32_t                first,
        uint32_t                second
) { return (first >= second)?(first - second):(second - first); }

static inline uint32_t
delta_u32_window (
        uint32_t                left,
        uint32_t                right,
        uint32_t                window
) {
    if (right >= left) return (right - left);
    return (window - left) + right;
}

static inline uint64_t
delta_u64 (
        uint64_t                first,
        uint64_t                second
) { return (first >= second)?(first - second):(second - first); }

#endif
