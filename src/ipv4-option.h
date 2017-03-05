/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#if !defined(BPROXY_IPV4_OPTION)
#define BPROXY_IPV4_OPTION

#include "bproxy.h"
#include "ipv4.h"

#define IPV4_OPTION_ID_EOOL             (0x00) //[E]nd [O]f [O]ptions [L]ist
#define IPV4_OPTION_ID_NOP              (0x01) //  1
#define IPV4_OPTION_ID_SECURITY         (0x82) //130

#define FIPV4_OPTION_COPY               (0x80) //Copy to fragments

typedef
struct _ipv4_option_cursor {
    ubyte_t*                    buffer;
    size_t                      length;

    ubyte_t*                    option;
    ubyte_t*                    position;
} sipv4_option_cursor;

typedef
struct _ipv4_option_iterator {
    ubyte_t*                    buffer;
    size_t                      length;

    ubyte_t*                    current;
} sipv4_option_iterator;

// --- known options interfaces

ripv4
ipv4_security_option (
    BTH sipv4_option_cursor*            cursor,
        uint8_t                         level,
        uint64_t                        category
);

// --- options
ripv4
ipv4_option_padding ( //write options padding to buffer, from position
    OUT ubyte_t*                        buffer,
        size_t                          length,
        ubyte_t**                       position
);

// --- iterator, reading

void
ipv4_option_iterator (
    OUT sipv4_option_iterator*          iterator,
        void*                           buffer,
        size_t                          length
);

ripv4
ipv4_option_next (          //set iterator to next option
    BTH sipv4_option_iterator*          iterator
);

ripv4
ipv4_option_type (          //get current options's data type
    OUT uint8_t*                        type,
        const sipv4_option_iterator*    iterator
);

ripv4
ipv4_option_size (          //get current options's data size
    OUT uint8_t*                        size,
        const sipv4_option_iterator*    iterator
);

ripv4
ipv4_option_data (          //get current option's data pointer
    OUT void**                          data,
        const sipv4_option_iterator*    iterator
);

ripv4
ipv4_option_copy (          //copy current interator's option into cursor
    BTH sipv4_option_cursor*            destination,
    IN  const sipv4_option_iterator*    iterator
);

// --- cursor, writing

void
ipv4_option_cursor (        //begin options writing into buffer
    OUT sipv4_option_cursor*            cursor,
        void*                           buffer,
        size_t                          length
);

static inline size_t
ipv4_option_cursor_used (   //current cursor position
    IN  const sipv4_option_cursor*      cursor
) { return (cursor->position - cursor->buffer); }

static inline ripv4
ipv4_option_cursor_avalible (
    IN  const sipv4_option_cursor*      cursor,
        size_t                          length
) {
    if (cursor->length < (ipv4_option_cursor_used(cursor) + length))
        return ripv4_failed;

    return ripv4_ok;
}

static inline ubyte_t*
ipv4_option_cursor_position (
    IN  const sipv4_option_cursor*      cursor
) { return cursor->position; }

ripv4
ipv4_option_cursor_close (  //write padding and cleanup cursor
    BTH sipv4_option_cursor*            cursor
);

ripv4
ipv4_option_begin (         //begin option writing
    BTH sipv4_option_cursor*            cursor,
        uint8_t                         type
);

ripv4
ipv4_option_write (         //write buffer into option data
    BTH sipv4_option_cursor*            cursor,
        const void*                     source,
        size_t                          length
);

static inline ripv4
ipv4_option_write_u8 (      //write byte into option data
    BTH sipv4_option_cursor*            cursor,
        uint8_t                         value
) { return ipv4_option_write(cursor, &value, sizeof(value)); }

ripv4
ipv4_option_undo (          //rollback current option writing
    BTH sipv4_option_cursor*            cursor
);

ripv4
ipv4_option_close (         //end option writing
    BTH sipv4_option_cursor*            cursor
);


#endif

