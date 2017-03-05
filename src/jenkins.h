/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#if !defined(BPROXY_JENKINS)
#define BPROXY_JENKINS

#include "bproxy.h"

typedef
struct _hash32_jenkins {
    uint32_t                            hash;
} shash32_jenkins;

static inline void
hash32_jenkins_begin (
    OUT shash32_jenkins*                hash
) { hash->hash = 0; }

static inline void
hash32_jenkins_append (
    BTH shash32_jenkins*                hash,
    IN  const void*                     data,
        size_t                          length
) {
    for (size_t _i = 0; _i < length; ++_i) {
        hash->hash += (((const unsigned char*)data)[_i]);
        hash->hash += (hash->hash << 10);
        hash->hash ^= (hash->hash >>  6);
    }
}

static inline uint32_t
hash32_jenkins_end (
    BTH shash32_jenkins*                hash
) {
    hash->hash += (hash->hash <<  3);
    hash->hash ^= (hash->hash >> 11);
    hash->hash += (hash->hash << 15);

    return hash->hash;
}

static inline uint32_t
hash32_jenkins (
        const void*                     data,
        size_t                          length
) {
    shash32_jenkins _hash;

    hash32_jenkins_begin(&_hash);
    hash32_jenkins_append(&_hash, data, length);
    return hash32_jenkins_end(&_hash);
}

#endif
