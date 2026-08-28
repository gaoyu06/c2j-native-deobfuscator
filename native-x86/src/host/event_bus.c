#include "event_bus.h"

#include "platform.h"

#include <string.h>

void nx86_bus_init(nx86_event_bus *bus)
{
    memset(bus, 0, sizeof(*bus));
    bus->next_token = 1u;
    bus->next_seq = 1u;
    bus->accepting = 0u;
}

void nx86_bus_set_accepting(nx86_event_bus *bus, int accepting)
{
    if (bus == NULL) {
        return;
    }
    bus->accepting = accepting ? 1u : 0u;
}

nx86_status nx86_bus_register(nx86_event_bus *bus,
                              uint32_t event_mask,
                              nx86_observer_fn fn,
                              void *user_data,
                              uint32_t *out_token)
{
    int i;

    if (bus == NULL || fn == NULL || out_token == NULL || event_mask == 0u) {
        return NX86_ERR_INVALID_ARG;
    }

    for (i = 0; i < NX86_HOST_MAX_OBSERVERS; ++i) {
        if (bus->slots[i].token != 0u) {
            continue;
        }
        bus->slots[i].token = bus->next_token++;
        bus->slots[i].mask = event_mask;
        bus->slots[i].fn = fn;
        bus->slots[i].user_data = user_data;
        *out_token = bus->slots[i].token;
        return NX86_OK;
    }
    return NX86_ERR_NO_MEMORY;
}

nx86_status nx86_bus_unregister(nx86_event_bus *bus, uint32_t token)
{
    int i;

    if (bus == NULL || token == 0u) {
        return NX86_ERR_INVALID_ARG;
    }
    for (i = 0; i < NX86_HOST_MAX_OBSERVERS; ++i) {
        if (bus->slots[i].token == token) {
            memset(&bus->slots[i], 0, sizeof(bus->slots[i]));
            return NX86_OK;
        }
    }
    return NX86_ERR_NOT_FOUND;
}

void nx86_bus_stamp(nx86_event_bus *bus,
                    nx86_event_header *header,
                    uint32_t struct_size,
                    nx86_event_kind kind)
{
    header->struct_size = struct_size;
    header->kind = kind;
    header->seq = bus->next_seq++;
    header->timestamp_ns = nx86_plat_now_ns();
    /* process_id names the observed process. The stub observes no target,
     * so there is no observed process to name: leave it zero rather than
     * mislabel the record with the host's own pid. */
    header->process_id = 0u;
    header->thread_id = 0u; /* the stub observes nothing, so no thread id */
}

nx86_status nx86_bus_publish(nx86_event_bus *bus,
                             const nx86_event_header *event)
{
    int i;

    if (bus == NULL || event == NULL) {
        return NX86_ERR_INVALID_ARG;
    }
    if (event->struct_size < (uint32_t)sizeof(nx86_event_header)) {
        return NX86_ERR_INVALID_ARG;
    }
    if (event->kind >= 32u) {
        /* Subscription masks are 32 bits wide in ABI 0.1. */
        return NX86_ERR_UNSUPPORTED;
    }
    if (bus->accepting == 0u) {
        /* Outside the start..stop window nothing is delivered. */
        return NX86_ERR_LIFECYCLE;
    }

    bus->published++;
    for (i = 0; i < NX86_HOST_MAX_OBSERVERS; ++i) {
        const nx86_observer_slot *slot = &bus->slots[i];
        if (slot->token == 0u) {
            continue;
        }
        if ((slot->mask & NX86_EVENT_MASK(event->kind)) == 0u) {
            continue;
        }
        slot->fn(slot->user_data, event);
        bus->delivered++;
    }
    return NX86_OK;
}

nx86_status nx86_bus_republish(nx86_event_bus *bus,
                               const nx86_event_header *event)
{
    nx86_event_buffer buffer;

    if (bus == NULL || event == NULL) {
        return NX86_ERR_INVALID_ARG;
    }
    if (event->struct_size < (uint32_t)sizeof(nx86_event_header) ||
        event->struct_size > (uint32_t)NX86_HOST_MAX_EVENT_SIZE) {
        return NX86_ERR_INVALID_ARG;
    }
    if (bus->accepting == 0u) {
        /* Reject before copying so shutdown-time emits reach no observer. */
        return NX86_ERR_LIFECYCLE;
    }

    memcpy(buffer.bytes, event, event->struct_size);
    buffer.header.seq = bus->next_seq++;
    buffer.header.timestamp_ns = nx86_plat_now_ns();
    /* process_id is the producer's: it names the observed process, which
     * the host does not own. Leave whatever the plugin set. */

    return nx86_bus_publish(bus, &buffer.header);
}
