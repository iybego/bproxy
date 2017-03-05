/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#if !defined(BPROXY_INTTYPES)
#define BPROXY_INTTYPES

#include <inttypes.h>

#define _INTTYPE_u8_TYPE            uint8_t
#define _INTTYPE_u8_FORMAT_scan     "%"SCNu8
#define _INTTYPE_u8_FORMAT_print    "%"PRIu8

#define _INTTYPE_u16_TYPE           uint16_t
#define _INTTYPE_u16_FORMAT_scan    "%"SCNu16
#define _INTTYPE_u16_FORMAT_print   "%"PRIu16

#define _INTTYPE_u32_TYPE           uint32_t
#define _INTTYPE_u32_FORMAT_scan    "%"SCNu32
#define _INTTYPE_u32_FORMAT_print   "%"PRIu32

#define _INTTYPE_u64_TYPE           uint64_t
#define _INTTYPE_u64_FORMAT_scan    "%"SCNu64
#define _INTTYPE_u64_FORMAT_print   "%"PRIu64

#define INTTYPE_FORMAT(x, mode)     _INTTYPE_##x##_FORMAT_##mode
#define INTTYPE_TYPE(x)             _INTTYPE_##x##_TYPE

#endif