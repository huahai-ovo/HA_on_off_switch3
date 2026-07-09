#include "packet_loss.h"
#include <string.h>   // for memset
#define MAX_RX_STATS 20

static rx_stats_t rx_stats[MAX_RX_STATS];  // array limited to this file

rx_stats_t* find_or_create_stats(uint16_t addr)
{
    for (int i = 0; i < MAX_RX_STATS; i++) {
        if (rx_stats[i].short_addr == addr) {
            return &rx_stats[i];
        }
    }
    for (int i = 0; i < MAX_RX_STATS; i++) {
        if (rx_stats[i].short_addr == 0) {
            rx_stats[i].short_addr = addr;
            rx_stats[i].first_rx   = true;
            rx_stats[i].rx_count   = 0;
            rx_stats[i].drop_count = 0;
            rx_stats[i].rx_bytes   = 0;
            return &rx_stats[i];
        }
    }
    return NULL;
}