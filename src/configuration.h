/**
    Broadcast Proxy
    Alexander Belyaev <iybego@ocihs.spb.ru>, 2016
**/

#if !defined(BPROXY_CONFIGURATION)
#define BPROXY_CONFIGURATION

#include "bproxy.h"
#include "source.h"

typedef
struct _configuration {
    char*               log;
    char*               directory;

    size_t              events;
    size_t              buffer_size;

    size_t              rtlink_hash;

    unsigned long       reload;
    unsigned long       restore;
    unsigned long       statistics;

    ssource*            sources;
} sconfiguration;

static inline void
configuration_initialize (
    OUT sconfiguration*     cfg
) {
    cfg->log            = NULL;
    cfg->directory      = NULL;

    cfg->events         = 0; //calculate automatically
    cfg->buffer_size    = DEFAULT_BUFFER_SIZE;

    cfg->statistics     = 0; //disabled

    cfg->rtlink_hash    = 5;

    cfg->reload         = 120;
    cfg->restore        =   5;

    cfg->sources        = NULL;
}

typedef
enum {
        rconfiguration_ok               = 0
    ,   rconfiguration_failed
    ,   rconfiguration_out_of_memory
} rconfiguration;

rconfiguration
configuration (
        int                     argc,
    IN  char**                  argv,
    OUT sconfiguration*         cfg
);

void
configuration_cleanup (
    BTH sconfiguration*         cfg
);

#endif

