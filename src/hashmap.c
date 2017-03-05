/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#include "hashmap.h"
#include "log.h"

#include <string.h>

LOG_MODULE("hashmap");

#define hashmap_entry(hashmap, hash)        \
    (hashmap->entries[hash & ((hashmap)->length - 1)])

shashmap*
hashmap_allocate (
        size_t                      factor,
        const shashmap_interface*   interface
) {
    size_t _length = (((size_t)1) << factor);

    LOG(debug, "map size %lu", (unsigned long)_length);

    shashmap* _map = (shashmap*)malloc(sizeof(shashmap) + (sizeof(shashmap_entry*) * _length));

    if NULL_IS(_map) {
        LOG(error, "out of memory [%lu]", (unsigned long)(sizeof(shashmap) + (sizeof(shashmap_entry*) * _length)));
        return NULL;
    }

    _map->length    = _length;
    _map->interface = interface;

    memset(_map->entries, 0, sizeof(shashmap_entry*) * _length);

    return _map;
}

void
hashmap_free (
    BTH shashmap*                   hashmap
) { free(hashmap); }

rhashmap
hashmap_lookup (
    OUT shashmap_cursor*            cursor,
    BTH shashmap*                   hashmap,
        const void*                 key,
        size_t                      length
) {
    cursor->hash    = hashmap->interface->hash(key, length);
    cursor->cursor  = &(hashmap_entry(hashmap, cursor->hash));

    while (*(cursor->cursor)) {
        if (cursor->hash == (*cursor->cursor)->hash)
            if (0 == hashmap->interface->compare(*(cursor->cursor), key, length))
                return rhashmap_ok;

        cursor->cursor = &((*cursor->cursor)->next);
    }

    return rhashmap_not_found;
}

rhashmap
hashmap_remove (
    BTH shashmap_entry*             entry
) {
    if (NULL != entry->next)
        entry->next->owner = entry->owner;

    (*entry->owner) = entry->next;
    return rhashmap_ok;
}

rhashmap
hashmap_cursor_remove (
    BTH shashmap_cursor*            cursor
) { return hashmap_remove(*(cursor->cursor)); }

rhashmap
hashmap_insert (
    BTH shashmap_cursor*            cursor,
        shashmap_entry*             entry
) {
    entry->hash = cursor->hash;

    entry->next  = (*cursor->cursor);
    if (NULL != (*cursor->cursor))
        (*(cursor->cursor))->owner = &entry->next;

    entry->owner = cursor->cursor;
    (*cursor->cursor) = entry;

    return rhashmap_ok;
}
