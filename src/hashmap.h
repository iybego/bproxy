/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#if !defined(BPROXY_HASHMAP)
#define BPROXY_HASHMAP

#include "bproxy.h"

typedef
enum {
        rhashmap_ok             = 0
    ,   rhashmap_not_found
    ,   rhashmap_exists
    ,   rhashmap_failed
} rhashmap;

typedef
struct _hashmap_entry       shashmap_entry;

typedef
struct _hashmap             shashmap;

typedef
uint32_t (*fhashmap_hash) (
    IN  const void*         buffer,
        size_t              length
);

typedef
int (*fhashmap_compare) (
    IN  shashmap_entry*     target,
    IN  const void*         buffer,
        size_t              length
);

typedef
struct _hashmap_interface {
    fhashmap_hash               hash;
    fhashmap_compare            compare;
} shashmap_interface;

struct _hashmap_entry {
    uint32_t                    hash;

    shashmap_entry**            owner;
    shashmap_entry*             next;
};

struct _hashmap {
    const shashmap_interface*   interface;

    size_t                      length;
    shashmap_entry*             entries[];
};

typedef
struct _hashmap_cursor {
    uint32_t                    hash;
    shashmap_entry**            cursor;
} shashmap_cursor;

shashmap*
hashmap_allocate (
        size_t                      factor,
        const shashmap_interface*   interface
);

void
hashmap_free (
    BTH shashmap*                   hashmap
);

rhashmap
hashmap_lookup (
    OUT shashmap_cursor*            cursor,
    BTH shashmap*                   hashmap,
        const void*                 key,
        size_t                      length
);

rhashmap
hashmap_insert (
    BTH shashmap_cursor*            cursor,
        shashmap_entry*             entry
);

static inline void*
hashmap_cursor (
    IN  shashmap_cursor*            cursor
) { return *(cursor->cursor); }

rhashmap
hashmap_remove (
    BTH shashmap_entry*             entry
);

rhashmap
hashmap_cursor_remove (
    BTH shashmap_cursor*            cursor
);

#endif
