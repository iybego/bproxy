/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#include "ipv4-option.h"
#include "log.h"

#include <string.h>

LOG_MODULE("ipv4-option");

ripv4
ipv4_security_option (
    BTH sipv4_option_cursor*            cursor,
        uint8_t                         level,
        uint64_t                        category
) {
    LOG(debug, "writing security option with %"PRIu8":%"PRIu64, level, category);

    if (ripv4_ok != ipv4_option_begin   (cursor, IPV4_OPTION_ID_SECURITY))
        return ripv4_failed;

    if (ripv4_ok != ipv4_option_write_u8(cursor, 0xAB)) //unclassified
        goto _undo;

    #define _IPV4_SECURITY_TICK(byte)                               \
        do {                                                        \
            _write  = ((byte & ( _mask)) << (_shift)) | _bits;      \
            _bits   =  (byte & (~_mask)) >> (7 - _shift);           \
                                                                    \
            if (0 != category) _write |= 0x01;                      \
                                                                    \
            if (ripv4_ok != ipv4_option_write_u8(cursor, _write))   \
                goto _undo;                                         \
                                                                    \
            _mask >>= 1;                                            \
                                                                    \
            if (8 == (++_shift)) {                                  \
                _shift = 1;                                         \
                _mask  = 0x7F;                                      \
            }                                                       \
                                                                    \
        } while (0)

    uint8_t _mask   = 0x7F;
    uint8_t _write  = 0;
    uint8_t _bits   = 0;
    uint8_t _shift  = 1;

    _IPV4_SECURITY_TICK(level);

    for ENDIAN_ITERATOR_LITTLE(_index, sizeof(category)) {
        if (0 == category)
            break;

        uint8_t _byte = ((ubyte_t*)&category)[_index];
        ((ubyte_t*)&category)[_index] = 0;

        _IPV4_SECURITY_TICK(_byte);
    }

    if (0 != _bits)
        _IPV4_SECURITY_TICK(0x00);

    return ipv4_option_close(cursor);

    _undo:
        ipv4_option_undo(cursor);
        return ripv4_failed;
}

ripv4
ipv4_option_padding (
    OUT ubyte_t*                        buffer,
        size_t                          length,
        ubyte_t**                       position
) {
    size_t _used    = ((*position) - buffer);
    size_t _padding = 4 - (_used & 0x03);

    if (4 == _padding) 
        return ripv4_ok;

    LOG(debug, "used %d bytes, padding is %d bytes", (int)_used, (int)_padding);

    if (length <= (_used + _padding))
        return ripv4_failed;

    memset((*position), 0, _padding);

    (*position) += _padding;

    return ripv4_ok;
}

// --- iterator, reading

size_t
_ipv4_option_head_size (
        uint8_t                         type
) {
    switch (type) {
        case IPV4_OPTION_ID_NOP:
        case IPV4_OPTION_ID_EOOL:
            return 1;
    }

    return 2;
}

void
ipv4_option_iterator (
    OUT sipv4_option_iterator*          iterator,
        void*                           buffer,
        size_t                          length
) {
    iterator->buffer    = buffer;
    iterator->length    = length;
    iterator->current   = NULL;
}

ripv4
ipv4_option_next (          //set iterator to next option
    BTH sipv4_option_iterator*          iterator
) {
    if NULL_IS(iterator->current) {
        iterator->current = iterator->buffer;
        return ripv4_ok;
    }

    uint8_t _size;
    uint8_t _type;

    if (ripv4_ok != ipv4_option_type(&_type, iterator)) {
        LOG(debug, "can't get option type");
        return ripv4_failed;
    }

    if (ripv4_ok != ipv4_option_size(&_size, iterator)) {
        LOG(debug, "can't get size");
        return ripv4_failed;
    }

    _size += _ipv4_option_head_size(_type);

    LOG(debug, "iterator shift %d bytes", (int)(iterator->current - iterator->buffer));

    if ((iterator->current - iterator->buffer + (size_t)_size) >= iterator->length) {
        LOG(debug, "options ended");
        return ripv4_failed;
    }

    iterator->current += _size;
    return ripv4_ok;
}

ripv4
ipv4_option_type (          //get current options's data type
    OUT uint8_t*                        type,
        const sipv4_option_iterator*    iterator
) {
    if NULL_IS(iterator->current)
        return ripv4_failed;

    (*type) = (*iterator->current);
    return ripv4_ok; 
}

ripv4
ipv4_option_size (          //get current options's data size
    OUT uint8_t*                        size,
        const sipv4_option_iterator*    iterator
) {
    uint8_t _type;

    if (ripv4_ok != ipv4_option_type(&_type, iterator))
        return ripv4_failed;

    size_t _head_size = _ipv4_option_head_size(_type);

    if (2 > _head_size) {
        (*size) = 0; //cuz' header doesn't fit size, size always 0
        return ripv4_ok;
    }

    size_t _data_size = *(iterator->current + 1);

    if (_head_size > _data_size) {
        LOG(debug, "option %d size should be atleast %d", (int)_type, (int)_head_size);
        return ripv4_failed;
    }

    if ((iterator->current - iterator->buffer + _data_size) > iterator->length) {
        LOG(debug, "option data doesn't fit buffer %d > %d", (int)(iterator->current - iterator->buffer + _data_size), (int)iterator->length);
        return ripv4_failed;
    }

    (*size) = (_data_size - _head_size);
    return ripv4_ok;
}

ripv4
ipv4_option_data (          //get current option's data pointer
    OUT void**                          data,
        const sipv4_option_iterator*    iterator
) {
    uint8_t _type;

    if (ripv4_ok != ipv4_option_type(&_type, iterator))
        return ripv4_failed;

    size_t _head_size = _ipv4_option_head_size(_type);

    if (2 > _head_size) {
        (*data) = NULL;
        return ripv4_ok;
    }

    (*data) = iterator->current + _head_size;
    return ripv4_ok;
}

ripv4
ipv4_option_copy (          //copy current interator's option into cursor
    BTH sipv4_option_cursor*            destination,
    IN  const sipv4_option_iterator*    iterator
) {
    uint8_t _type;
    void*   _data;
    uint8_t _size;

    if (ripv4_ok != ipv4_option_type(&_type, iterator))
        return ripv4_failed;

    if (ripv4_ok != ipv4_option_data(&_data, iterator))
        return ripv4_failed;

    if (ripv4_ok != ipv4_option_size(&_size, iterator))
        return ripv4_failed;

    if (ripv4_ok != ipv4_option_begin(destination, _type))
        return ripv4_failed;

    if ((0 < _size) && NOT_NULL_IS(_data))
        if (ripv4_ok != ipv4_option_write(destination, _data, _size)) {
            ipv4_option_undo(destination);
            return ripv4_failed;
        }

    return ipv4_option_close(destination);        
}

// --- cursor, writing

void
ipv4_option_cursor (
    OUT sipv4_option_cursor*            cursor,
        void*                           buffer,
        size_t                          length
) {
    cursor->position = (ubyte_t*)buffer;
    cursor->option   = NULL;

    cursor->buffer   = (ubyte_t*)buffer;
    cursor->length   = length;
}

ripv4
ipv4_option_cursor_close (
    BTH sipv4_option_cursor*            cursor 
) {
    if NOT_NULL_IS(cursor->option)
        return ripv4_failed;

    return ipv4_option_padding(cursor->buffer, cursor->length, &(cursor->position));
}

ripv4
ipv4_option_begin (
    BTH sipv4_option_cursor*            cursor,
        uint8_t                         type
) {
    if NOT_NULL_IS(cursor->option)
        return ripv4_failed;

    size_t _head_length = _ipv4_option_head_size(type);

    if (ripv4_ok != ipv4_option_cursor_avalible(cursor, _head_length))
        return ripv4_failed;

    LOG(debug, "starting option %d, head length %d", (int)type, (int)_head_length);

    cursor->option    = cursor->position;
    cursor->position += _head_length; 

    (*cursor->option) = type;
    return ripv4_ok;
}

ripv4
ipv4_option_write (
    BTH sipv4_option_cursor*            cursor,
        const void*                     source,
        size_t                          length
) {
    if NULL_IS(cursor->option)
        return ripv4_failed;

    if (1 == _ipv4_option_head_size(cursor->option[0]))
        return ripv4_failed;

    LOG(debug, "writing option data: %d bytes", (int)length);

    if (ripv4_ok != ipv4_option_cursor_avalible(cursor, length)) {
        LOG(debug, " ^ insufficient space");
        return ripv4_failed;
    }

    memcpy(cursor->position, source, length);

    cursor->position += length;
    return ripv4_ok;
}

ripv4
ipv4_option_undo (
    BTH sipv4_option_cursor*            cursor
) { 
    if NULL_IS(cursor->option)
        return ripv4_failed;

    cursor->position = cursor->option;
    cursor->option   = NULL;

    return ripv4_ok;
}

ripv4
ipv4_option_close (
    BTH sipv4_option_cursor*            cursor
) {
    if NULL_IS(cursor->option)
        return ripv4_failed;

    uint8_t _size = cursor->position - cursor->option;

    LOG(debug, "closing option %d, with %d bytes size", (int)(cursor->option[0]), (int)_size);

    if (1 == _ipv4_option_head_size(cursor->option[0])) {
        if (1 != _size) {
            LOG(debug, "wrong size for option");
            return ripv4_failed;
        }

        cursor->option = NULL;
        return ripv4_ok;
    }

    cursor->option[1] = _size;
    cursor->option    = NULL;

    return ripv4_ok;
}


