#ifndef PACKET_LOSS_H
#define PACKET_LOSS_H

#include <stdint.h>
#include <stdbool.h>

/* 结构体定义放在头文件里，供所有引用者使用 */
typedef struct {
    uint16_t short_addr;
    uint16_t last_seq;
    uint32_t rx_count;
    uint32_t drop_count;
    bool     first_rx;
    uint32_t rx_bytes;
    uint32_t first_rx_ms;
    uint32_t last_rx_ms;
} rx_stats_t;

/* 函数声明不带 static */
extern rx_stats_t* find_or_create_stats(uint16_t addr);

#endif /* PACKET_LOSS_H */