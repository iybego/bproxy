/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#if !defined(BPROXY_SWAP)
#define BPROXY_SWAP

#include <string.h>
#include <netinet/in.h>

static inline uint16_t
unaligned_u16 (
    IN  const uint16_t*         value
) {
    uint16_t _temp;
    memcpy(&_temp, value, sizeof(uint16_t));
    return _temp;
}

static inline uint32_t
unaligned_u32 (
    IN  const uint32_t*         value
) {
    uint32_t _temp;
    memcpy(&_temp, value, sizeof(uint32_t));
    return _temp;
}

static inline uint16_t
unaligned_htons (
    IN  const uint16_t*         value
) { return ntohs(unaligned_u16(value)); }

static inline uint32_t
unaligned_htonl (
    IN  const uint32_t*         value
) { return ntohl(unaligned_u32(value)); }

static inline void
u16_unaligned (
    OUT void*                   output,
        uint16_t                value
) { memcpy(output, &value, sizeof(value)); }

static inline void
u32_unaligned (
    OUT void*                   output,
        uint32_t                value
) { memcpy(output, &value, sizeof(value)); }

static inline void
htons_unaligned (
    OUT void*                   output,
        uint16_t                value 
) { u16_unaligned(output, htons(value)); }

static inline void
htonl_unaligned (
    OUT void*                   output,
        uint16_t                value 
) { u32_unaligned(output, htonl(value)); }

#endif
