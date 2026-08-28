/*
 * Observer registry + dispatch for the host stub.
 *
 * Fixed capacity, no allocation, single-threaded. This is the reference
 * shape of the nx86_host callbacks, not a production event pipeline.
 */
#ifndef NX86_HOST_EVENT_BUS_H
#define NX86_HOST_EVENT_BUS_H

#include "nativex86/plugin.h"

#define NX86_HOST_MAX_OBSERVERS  16
#define NX86_HOST_MAX_EVENT_SIZE 256

typedef struct nx86_observer_slot {
    uint32_t         token;   /* 0 means the slot is free */
    uint32_t         mask;
    nx86_observer_fn fn;
    void            *user_data;
} nx86_observer_slot;

typedef struct nx86_event_bus {
    nx86_observer_slot slots[NX86_HOST_MAX_OBSERVERS];
    uint32_t           next_token;
    uint64_t           next_seq;
    uint64_t           published;
    uint64_t           delivered;
} nx86_event_bus;

/* Storage with the alignment an event record needs, used to re-stamp
 * plugin-authored events without mutating the caller's copy. */
typedef union nx86_event_buffer {
    nx86_event_header header;
    uint64_t          align;
    unsigned char     bytes[NX86_HOST_MAX_EVENT_SIZE];
} nx86_event_buffer;

void nx86_bus_init(nx86_event_bus *bus);

nx86_status nx86_bus_register(nx86_event_bus *bus,
                              uint32_t event_mask,
                              nx86_observer_fn fn,
                              void *user_data,
                              uint32_t *out_token);

nx86_status nx86_bus_unregister(nx86_event_bus *bus, uint32_t token);

/* Fill the header of an event the host itself authored. */
void nx86_bus_stamp(nx86_event_bus *bus,
                    nx86_event_header *header,
                    uint32_t struct_size,
                    nx86_event_kind kind);

/* Deliver a stamped event to every observer subscribed to its kind. */
nx86_status nx86_bus_publish(nx86_event_bus *bus,
                             const nx86_event_header *event);

/* Copy, re-stamp (seq / timestamp / pid) and publish an event authored
 * by a plugin. */
nx86_status nx86_bus_republish(nx86_event_bus *bus,
                               const nx86_event_header *event);

#endif /* NX86_HOST_EVENT_BUS_H */
