/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#if !defined(BPROXY_LIST)
#define BPROXY_LIST

#include "bproxy.h"

typedef
struct _list slist;

typedef
struct _list_entry slist_entry;

#define LIST_INITIALIZE { 0, NULL, NULL }

struct _list {
    size_t              size;

    slist_entry*        first;
    slist_entry*        last;
};

struct _list_entry {
    slist*              head;

    slist_entry*        next;
    slist_entry*        previous;
};

typedef
enum {
        rlist_entry_attached    = 0
    ,   rlist_entry_detached
} rlist_entry;

static inline void
list_entry_initialize (
    OUT slist_entry*            entry
) {
    entry->head     = NULL;
    entry->next     = NULL;
    entry->previous = NULL;
}

static inline rlist_entry
list_entry_attached (
    IN  const slist_entry*      entry
) { return NULL_IS(entry->head)?rlist_entry_detached:rlist_entry_attached; }

static inline slist*
list_entry_head (
    IN  slist_entry*            entry
) { return entry->head; }

#define LIST_ENTRY_ATTACHED(x)      \
    (rlist_entry_attached == list_entry_attached(x))

#define LIST_ENTRY_NOT_ATTACHED(x)  \
    (rlist_entry_attached != list_entry_attached(x))

#define LIST_EMPTY(x)               \
    (0 == list_size(x))

#define LIST_NOT_EMPTY(x)           \
    (0 != list_size(x))

#define LIST_FIRST(list, type, member)              \
    ( (type*)( ( NULL != (list)    )?( (NULL != (list)->first)?( CONTAINEROF(((list)->first), type, member) ):NULL ):NULL ) )

#define LIST_LAST(list, type, member)              \
    ( (type*)( ( NULL != (list)    )?( (NULL != (list)->last )?( CONTAINEROF(((list)->last ), type, member) ):NULL ):NULL ) )

#define LIST_NEXT(pointer, type, member)            \
    ( (type*)( ( NULL != (pointer) )?( (NULL != (pointer)->member.next    )?( CONTAINEROF(((pointer)->member.next    ), type, member) ):NULL ): NULL ) )

#define LIST_PREVIOUS(pointer, type, member)        \
    ( (type*)( ( NULL != (pointer) )?( (NULL != (pointer)->member.previous)?( CONTAINEROF(((pointer)->member.previous), type, member) ):NULL ): NULL ) )

#define LIST_FOREACH(iterator, type, member, list)  \
    for (type* iterator = LIST_FIRST(list, type, member); NULL != iterator; iterator = LIST_NEXT(iterator, type, member))

#define LIST_FOREACH_SAFE(iterator, type, member, list)                                                             \
    for (type* iterator = LIST_FIRST(list, type, member), *__##iterator##_safe = LIST_NEXT(iterator, type, member); \
        NULL != iterator;                                                                                           \
        iterator = __##iterator##_safe, __##iterator##_safe = LIST_NEXT(iterator, type, member))

#define LIST_ENTRY_HEAD(entry, type, member)        \
    CONTAINEROF_SAFE(list_entry_head(entry), type, member)

static inline void
list_initialize (
    OUT slist*                  list
) {
    list->size  = 0;

    list->first = NULL;
    list->last  = NULL;
}

static inline size_t
list_size (
    IN  const slist*            list
) { return list->size; }

static inline slist_entry*
list_first (
    IN  slist*                  list
) { return list->first; }

static inline slist_entry*
list_last (
    IN  slist*                  list
) { return list->last; }

static inline slist_entry*
list_entry_next (
    IN  slist_entry*            entry
) { return entry->next; }

static inline slist_entry*
list_entry_previous (
    IN  slist_entry*            entry
) { return entry->previous; }

static inline void
list_insert (
    BTH slist*                  list,
    BTH slist_entry*            entry
) {
    entry->head = list;

    entry->next     = list->first;
    entry->previous = NULL;

    if (NULL != list->first)
        list->first->previous = list->first;

    list->first = entry;

    if NULL_IS(list->last)
        list->last = entry;

    ++(entry->head->size);
}

static inline void
list_append (
    BTH slist*                  list,
    BTH slist_entry*            entry
) {
    entry->head = list;

    entry->next     = NULL;
    entry->previous = list->last;

    if (NULL != list->last)
        list->last->next = entry;

    list->last = entry;

    if NULL_IS(list->first)
        list->first = entry;

    ++(entry->head->size);
}

static inline void
list_detach (
    BTH slist_entry*            entry
) {
    --(entry->head->size);

    if NULL_IS(entry->next) {
        entry->head->last = entry->previous;
    } else {
        entry->next->previous = entry->previous;
    }

    if NULL_IS(entry->previous) {
        entry->head->first = entry->next;
    } else {
        entry->previous->next = entry->next;
    }

    entry->head     = NULL;
    entry->next     = NULL;
    entry->previous = NULL;
}

#endif
