#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_err.h"
#include "esp_check.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "ha/esp_zigbee_ha_standard.h"
#include "esp_zb_switch.h"
#include "esp_zigbee_core.h"
#include "esp_timer.h"
#include <math.h> 
#include "packet_loss.h"

/* 本代码为 Zigbee 协调器，维护应用层活跃子设备白名单 */
#if defined ZB_ED_ROLE
#error Define ZB_COORDINATOR_ROLE in idf.py menuconfig to compile coordinator source code.
#endif

static const char *TAG = "ZB_COORDINATOR";

/* ------------------ 应用层活跃子设备白名单 ------------------ */

#define MAX_ACTIVE_CHILDREN 16
#define HEARTBEAT_TIMEOUT_MS  15000
#define MAX_MISSED_PINGS      3
#define MAX_RX_STATS 20
typedef struct {
    uint16_t short_addr;
    uint8_t  lqi;
    int8_t   rssi;
    uint32_t last_seen_ms;
    uint8_t  missed_pings;//连续未响应时延检测包的次数，超过阈值则认为设备离线并从白名单移除
    bool     online;
    uint8_t logical_type; /* 可选：设备类型标识 1-路由，2-终端，0xff-未知*/
    uint32_t ping_sent_ms;//时延检测发送时间戳
    uint32_t RTT;
} active_child_t;

static active_child_t active_children[MAX_ACTIVE_CHILDREN];
static int active_child_count = 0;
static rx_stats_t throughput_stats[MAX_RX_STATS];

static rx_stats_t *find_or_create_throughput_stats(uint16_t addr)
{
    for (int i = 0; i < MAX_RX_STATS; i++) {
        if (throughput_stats[i].short_addr == addr) {
            return &throughput_stats[i];
        }
    }
    for (int i = 0; i < MAX_RX_STATS; i++) {
        if (throughput_stats[i].short_addr == 0) {
            throughput_stats[i].short_addr = addr;
            throughput_stats[i].first_rx = true;
            throughput_stats[i].last_seq = 0;
            throughput_stats[i].rx_count = 0;
            throughput_stats[i].drop_count = 0;
            throughput_stats[i].rx_bytes = 0;
            throughput_stats[i].first_rx_ms = 0;
            throughput_stats[i].last_rx_ms = 0;
            return &throughput_stats[i];
        }
    }
    return NULL;
}

/* Support legacy packet_loss naming */
#define rx_stats throughput_stats
#define find_or_create_stats find_or_create_throughput_stats

/* 获取当前毫秒时间戳 */
static uint32_t get_now_ms(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000);
}

/* 添加或更新子设备到白名单 */
static void add_or_update_child(uint16_t short_addr)
{
    for (int i = 0; i < active_child_count; i++) {
        if (active_children[i].short_addr == short_addr) {
            active_children[i].last_seen_ms = get_now_ms();
            active_children[i].missed_pings = 0;
            active_children[i].online = true;
            ESP_LOGI(TAG, "Updated child 0x%04hx in whitelist", short_addr);
            return;
        }
    }

    if (active_child_count < MAX_ACTIVE_CHILDREN) {
        active_children[active_child_count].short_addr = short_addr;
        active_children[active_child_count].lqi = 0;
        active_children[active_child_count].rssi = -128;
        active_children[active_child_count].last_seen_ms = get_now_ms();
        active_children[active_child_count].missed_pings = 0;
        active_children[active_child_count].online = true;
        active_children[active_child_count].logical_type = 0xff; /* 默认为未知设备 */
        active_children[active_child_count].ping_sent_ms = 0;
        active_child_count++;
        ESP_LOGI(TAG, "Added new child 0x%04hx to whitelist (total: %d)", short_addr, active_child_count);
    } else {
        ESP_LOGW(TAG, "Whitelist full, cannot add 0x%04hx", short_addr);
    }
}

/* 查找子设备索引，找不到返回 -1 */
static int find_child_index(uint16_t short_addr)
{
    for (int i = 0; i < active_child_count; i++) {
        if (active_children[i].short_addr == short_addr) {
            return i;
        }
    }
    return -1;
}

/* 从白名单中移除 */
static void remove_child(int index)
{
    if (index < 0 || index >= active_child_count) return;

    uint16_t addr = active_children[index].short_addr;
    ESP_LOGW(TAG, "Removing child 0x%04hx from whitelist, sending network leave", addr);

    for (int i = index; i < active_child_count - 1; i++) {
        active_children[i] = active_children[i + 1];
    }
    active_child_count--;
}

/* ------------------ Zigbee 信号处理 ------------------ */

void esp_zb_app_signal_handler(esp_zb_app_signal_t *signal_struct)
{
    uint32_t *p_sg_p = signal_struct->p_app_signal;
    esp_err_t err_status = signal_struct->esp_err_status;
    esp_zb_app_signal_type_t sig_type = *p_sg_p;
    esp_zb_zdo_signal_device_annce_params_t *dev_annce_params = NULL;

    switch (sig_type) {
    case ESP_ZB_ZDO_SIGNAL_SKIP_STARTUP:
        ESP_LOGI(TAG, "Initialize Zigbee stack");
        esp_zb_bdb_start_top_level_commissioning(ESP_ZB_BDB_MODE_INITIALIZATION);
        break;

    case ESP_ZB_BDB_SIGNAL_DEVICE_FIRST_START:
    case ESP_ZB_BDB_SIGNAL_DEVICE_REBOOT:
        if (err_status == ESP_OK) {
            ESP_LOGI(TAG, "Device started up in %s factory-reset mode",
                     esp_zb_bdb_is_factory_new() ? "" : "non");

            if (esp_zb_bdb_is_factory_new()) {
                ESP_LOGI(TAG, "Start network formation");
                esp_zb_bdb_start_top_level_commissioning(ESP_ZB_BDB_MODE_NETWORK_FORMATION);
            } else {
                esp_zb_bdb_open_network(150);
                ESP_LOGI(TAG, "Device rebooted, network open for 150s");
            }
        } else {
            ESP_LOGE(TAG, "Failed to initialize Zigbee stack (status: %s)", esp_err_to_name(err_status));
        }
        break;

    case ESP_ZB_BDB_SIGNAL_FORMATION:
        if (err_status == ESP_OK) {
            esp_zb_ieee_addr_t extended_pan_id;
            esp_zb_get_extended_pan_id(extended_pan_id);
            ESP_LOGI(TAG, "Formed network successfully (Ext PAN ID: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x, PAN ID: 0x%04hx, Channel:%d, Short Addr: 0x%04hx)",
                     extended_pan_id[7], extended_pan_id[6], extended_pan_id[5], extended_pan_id[4],
                     extended_pan_id[3], extended_pan_id[2], extended_pan_id[1], extended_pan_id[0],
                     esp_zb_get_pan_id(), esp_zb_get_current_channel(), esp_zb_get_short_address());
            esp_zb_bdb_start_top_level_commissioning(ESP_ZB_BDB_MODE_NETWORK_STEERING);
        } else {
            ESP_LOGE(TAG, "Network formation failed: %s", esp_err_to_name(err_status));
        }
        break;

    case ESP_ZB_BDB_SIGNAL_STEERING:
        if (err_status == ESP_OK) {
            ESP_LOGI(TAG, "Network steering success");
        } else {
            ESP_LOGW(TAG, "Network steering failed: %s", esp_err_to_name(err_status));
        }
        break;

    case ESP_ZB_ZDO_SIGNAL_DEVICE_ANNCE://这竟然是设备入网时的唯一入口，而路由器入网时不会产生这个信号，所以此时的代码只能让终端加入白名单
        dev_annce_params = (esp_zb_zdo_signal_device_annce_params_t *)esp_zb_app_signal_get_params(p_sg_p);
        ESP_LOGI(TAG, "New device commissioned or rejoined (short: 0x%04hx)", dev_annce_params->device_short_addr);
        add_or_update_child(dev_annce_params->device_short_addr);
        break;

    case ESP_ZB_NWK_SIGNAL_PERMIT_JOIN_STATUS:
        if (err_status == ESP_OK) {
            uint8_t duration = *(uint8_t *)esp_zb_app_signal_get_params(p_sg_p);
            if (duration) {
                ESP_LOGI(TAG, "Network(0x%04hx) is open for %d seconds", esp_zb_get_pan_id(), duration);
            } else {
                ESP_LOGW(TAG, "Network(0x%04hx) closed, devices joining not allowed.", esp_zb_get_pan_id());
            }
        }
        break;

    default:
        ESP_LOGD(TAG, "ZDO signal: %s (0x%x), status: %s",
                 esp_zb_zdo_signal_to_string(sig_type), sig_type,
                 esp_err_to_name(err_status));
        break;
    }
}

/*------------时延检测响应回调-------------*/
static void ping_response_callback(esp_zb_zdp_status_t zdo_status, uint8_t ep_count, uint8_t *ep_id_list, void *user_ctx)
{
    uint16_t addr = (uint16_t)(uintptr_t)user_ctx;
    int idx = find_child_index(addr);

    if (idx >= 0) {
        if (zdo_status == ESP_ZB_ZDP_STATUS_SUCCESS) {
            uint32_t now = get_now_ms();
            uint32_t rtt = now - active_children[idx].ping_sent_ms;
    //        ESP_LOGI(TAG, "Latency RTT to 0x%04hx: %lu ms", addr, rtt);
            active_children[idx].RTT = rtt;
            active_children[idx].missed_pings = 0;
            active_children[idx].last_seen_ms = now;
            active_children[idx].online = true;
        } else {
            ESP_LOGW(TAG, "Latency ping to 0x%04hx failed or timeout (status=%d)", addr, zdo_status);
            active_children[idx].missed_pings++;
            if (active_children[idx].missed_pings >= MAX_MISSED_PINGS) {
                remove_child(idx);
            }
        }
    }
}

/*-------------------发送时延检测包----------------------*/
//使用ZDO命令发送时延检测包，目标设备收到后会回复一个ZDO响应，我们在响应回调里计算RTT并更新设备状态
static void send_latency_ping(uint16_t short_addr)
{
    int idx = find_child_index(short_addr);
    if (idx < 0) return;

    active_children[idx].ping_sent_ms = get_now_ms();

    esp_zb_zdo_active_ep_req_param_t req = {
        .addr_of_interest = short_addr,
    };
    esp_zb_zdo_active_ep_req(&req, ping_response_callback, (void *)(uintptr_t)short_addr);
    ESP_LOGI(TAG, "Latency ping sent to 0x%04hx", short_addr);
}


/* ------------------ LQI 请求回调 ------------------ */

static void lqi_response_callback(const esp_zb_zdo_mgmt_lqi_rsp_t *rsp, void *user_ctx)
{
    uint16_t dst_addr = (uint16_t)(uintptr_t)user_ctx;
    int idx = find_child_index(dst_addr);

    if (rsp && rsp->status == ESP_ZB_ZDP_STATUS_SUCCESS) {
        ESP_LOGI(TAG, "LQI rsp from 0x%04hx: entries=%u, count=%u",
                 dst_addr, rsp->neighbor_table_entries, rsp->neighbor_table_list_count);

    if(idx<0)//设备被踢了，但突然又响应了，说明它又重新加入了，可能是它自己重启了，或者是它被其他路由器拉入了网络，这时我们也把它重新加回白名单
    {
        ESP_LOGI(TAG, "Adding child 0x%04hx (LQI success)", dst_addr);
        add_or_update_child(dst_addr);
        idx = find_child_index(dst_addr);
    }
     if (idx >= 0) {
            active_children[idx].missed_pings = 0;
            active_children[idx].last_seen_ms = get_now_ms();
            active_children[idx].online = true;

            /* 从协调器本地邻居表读取该设备的实时 LQI/RSSI 以及设备身份*/
            esp_zb_nwk_info_iterator_t it = ESP_ZB_NWK_INFO_ITERATOR_INIT;
            esp_zb_nwk_neighbor_info_t nbr;
            esp_zb_lock_acquire(portMAX_DELAY);
            while (esp_zb_nwk_get_next_neighbor(&it, &nbr) == ESP_OK) {
                if (nbr.short_addr == dst_addr) {
                    active_children[idx].lqi = nbr.lqi;
                    active_children[idx].rssi = nbr.rssi;
                    
                        if(nbr.device_type == 0x01)//如果是路由器
                        {
                            active_children[idx].logical_type = 1; /* 路由 */
                        }
                        if (nbr.device_type == 0x02)//如果是终端
                        {
                            active_children[idx].logical_type = 2; /* 终端 */
                        }
                        
                    break;
                }
            }
            esp_zb_lock_release();
        }
    } else {
        ESP_LOGW(TAG, "LQI rsp from 0x%04hx failed or timeout", dst_addr);
        if (idx >= 0) {
            active_children[idx].missed_pings++;
            if (active_children[idx].missed_pings >= MAX_MISSED_PINGS) {
                ESP_LOGW(TAG, "Child 0x%04hx missed %d pings, removing", dst_addr, MAX_MISSED_PINGS);
                remove_child(idx);
            }
        }
    }
}

static void log_router_neighbors(void)
{
    esp_zb_nwk_info_iterator_t it = ESP_ZB_NWK_INFO_ITERATOR_INIT;
    esp_zb_nwk_neighbor_info_t nbr;

    esp_zb_lock_acquire(portMAX_DELAY);
    ESP_LOGI(TAG, "====== Neighbor Table Routers ======");
    while (esp_zb_nwk_get_next_neighbor(&it, &nbr) == ESP_OK) {
        if (nbr.short_addr == esp_zb_get_short_address() ||
            nbr.short_addr == 0x0000 ||
            nbr.short_addr == 0xFFFF) {
            continue;
        }
        if (nbr.device_type != ESP_ZB_DEVICE_TYPE_ROUTER) {
            continue;
        }
        ESP_LOGI(TAG, "Router 0x%04hx depth=%u lqi=%u rssi=%d age=%u out_cost=%u rel=%u rx_on_idle=%u",
                 nbr.short_addr,
                 nbr.depth,
                 nbr.lqi,
                 nbr.rssi,
                 nbr.age,
                 nbr.outgoing_cost,
                 nbr.relationship,
                 nbr.rx_on_when_idle);
    }
    ESP_LOGI(TAG, "===================================");
    esp_zb_lock_release();
}

/* ------------------ 遍历协调器邻居表发送心跳/LQI ------------------ */

// [改] 原来：遍历白名单(active_children)发LQI
// [改] 现在：遍历协调器邻居表，遇到新设备先拉进白名单，同时发LQI
static void send_heartbeat_for_neighbor_update(void)
{
    esp_zb_nwk_info_iterator_t it = ESP_ZB_NWK_INFO_ITERATOR_INIT;  // [改] 原来用白名单索引，现在用邻居表迭代器
    esp_zb_nwk_neighbor_info_t nbr;                                 // [改]
    int req_count = 0;                                              // [改] 原来叫 has_target，现在计数

    esp_zb_lock_acquire(portMAX_DELAY);
    while (esp_zb_nwk_get_next_neighbor(&it, &nbr) == ESP_OK) {     // [改] 原来遍历 active_children，现在遍历邻居表
        //  跳过自己和协调器
        if (nbr.short_addr == esp_zb_get_short_address() || 
            nbr.short_addr == 0x0000 || 
            nbr.short_addr == 0xFFFF) {
            continue;
        }
        // [改] ========== 向这个邻居发 LQI 请求（不管它在不在白名单） ==========
        esp_zb_zdo_mgmt_lqi_req_param_t lqi_req = {
            .start_index = 0,
            .dst_addr = nbr.short_addr,
        };
        esp_zb_zdo_mgmt_lqi_req(&lqi_req, lqi_response_callback, (void *)(uintptr_t)nbr.short_addr);
        req_count++;
    }
    esp_zb_lock_release();

    if (req_count == 0) {                                           // [改]
        ESP_LOGD(TAG, "No neighbors to ping");
    }
}
/* ------------------ 定时监测任务 ------------------ */

static void comm_quality_monitor_task(void *pvParameters)
{
    ESP_LOGI(TAG, "CommQuality monitor task started");
    vTaskDelay(pdMS_TO_TICKS(3000));

    while (1) {
        uint32_t now_ms = get_now_ms();

        /* 绝对时间超时检查 */
        for (int i = active_child_count - 1; i >= 0; i--) {
            if ((now_ms - active_children[i].last_seen_ms) > HEARTBEAT_TIMEOUT_MS) {
                ESP_LOGW(TAG, "Child 0x%04hx heartbeat timeout (%lu ms), removing",
                         active_children[i].short_addr, now_ms - active_children[i].last_seen_ms);
                remove_child(i);
            }
        }

        send_heartbeat_for_neighbor_update();
        log_router_neighbors();
        vTaskDelay(pdMS_TO_TICKS(1000));

      //向白名单中的每个子设备发送时延检测包（支持多跳）
        for (int i = 0; i < active_child_count; i++) {
            send_latency_ping(active_children[i].short_addr);
            vTaskDelay(pdMS_TO_TICKS(100)); // 错开 100ms，避免瞬时拥塞
        }


        ESP_LOGI(TAG, "========== Active Child Whitelist ==========");
        ESP_LOGI(TAG, "PAN ID: 0x%04hx, Channel: %d, Short Addr: 0x%04hx",
                 esp_zb_get_pan_id(), esp_zb_get_current_channel(), esp_zb_get_short_address());

        if (active_child_count == 0) {
            ESP_LOGI(TAG, "No active children.");
        } else {
        now_ms = get_now_ms();
                    //串口打印当前活跃子设备列表及其状态
            for (int i = 0; i < active_child_count; i++) {
                uint32_t age_ms = (now_ms >= active_children[i].last_seen_ms) ?
                                (now_ms - active_children[i].last_seen_ms) : 0;
                 const char *type_str = (active_children[i].logical_type == 1) ? "路由" :
                               (active_children[i].logical_type == 2) ? "终端" : "Unknown";
                ESP_LOGI(TAG, "[%d] Addr=0x%04hx,类型=%s, 链路质量=%u, RSSI=%d, missed=%u, age=%lu ms, RTT=%lu ms",
                        i+1, active_children[i].short_addr, type_str,
                        active_children[i].lqi, active_children[i].rssi,
                        active_children[i].missed_pings, age_ms, active_children[i].RTT);
            }
        }
        ESP_LOGI(TAG, "Total active children: %d", active_child_count);
        ESP_LOGI(TAG, "===========================================");
        //打印吞吐测试统计数据
        ESP_LOGI(TAG, "========== Throughput Test Statistics ==========");
        bool has_tp_data = false;
        for (int i = 0; i < MAX_RX_STATS; i++) {
            if (rx_stats[i].short_addr != 0 && rx_stats[i].rx_count > 0) {
                has_tp_data = true;
                uint32_t elapsed_ms = rx_stats[i].last_rx_ms - rx_stats[i].first_rx_ms;
                uint32_t total = rx_stats[i].rx_count + rx_stats[i].drop_count;
                float pdr = (total > 0) ? (100.0f * rx_stats[i].rx_count / total) : 0.0f;
                float throughput = 0.0f;
                
                if (elapsed_ms > 0) {
                    throughput = (float)(rx_stats[i].rx_bytes * 8) 
                            / (elapsed_ms / 1000.0f) / 1000.0f;
                }

                ESP_LOGI(TAG, "[0x%04x] 发送:%lu  收到:%lu  丢包:%lu  PDR:%.2f%%  吞吐:%.2f kbps  时长:%lu ms",
                        rx_stats[i].short_addr,
                        total,
                        rx_stats[i].rx_count,
                        rx_stats[i].drop_count,
                        pdr,
                        throughput,
                        elapsed_ms);
            }
        }
        if (!has_tp_data) {
            ESP_LOGI(TAG, "No throughput test data received");
        }
        ESP_LOGI(TAG, "================================================");
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}

//添加数据吞吐重置函数
static void reset_all_stats(void)
{
    for (int i = 0; i < MAX_RX_STATS; i++) {
        if (rx_stats[i].short_addr != 0) {
            ESP_LOGI(TAG, "[0x%04x] 统计周期结束: 收包=%lu, 丢包=%lu, PDR=%.2f%%",
                    rx_stats[i].short_addr,
                    rx_stats[i].rx_count,
                    rx_stats[i].drop_count,
                    (rx_stats[i].rx_count + rx_stats[i].drop_count) > 0 ?
                    100.0f * rx_stats[i].rx_count / (rx_stats[i].rx_count + rx_stats[i].drop_count) : 0.0f);
        }
        memset(&rx_stats[i], 0, sizeof(rx_stats_t));
    }
}

static uint32_t last_stats_reset_ms = 0;
static esp_err_t zb_custom_cluster_handler(const esp_zb_zcl_custom_cluster_command_message_t *msg)
{
    //  ESP_LOGI(TAG, "========== 收到自定义Cluster消息 ==========");
    // 检查消息指针有效性
    if (!msg) {
        return ESP_FAIL;
    }

    // 验证 Cluster ID 是否为 0xFC00（终端约定的自定义 Cluster ID）
    if (msg->info.cluster!= 0xFC00) {
        return ESP_FAIL;
    }

    // 验证命令 ID 是否为 0x01（终端约定的姿态数据命令 ID）
    if (msg->info.command.id!= 0x01) {
        return ESP_FAIL;
    }

    // 验证数据负载长度：2字节短地址 + 3个float (每个4字节) = 15字节
    // if (msg->data.size == 15) {
    //     ESP_LOGW(TAG, "Unexpected data length for MPU6050: %d (expected 15)", msg->data.size);
    //     return ESP_FAIL;
    // }
    uint8_t *p = msg->data.value;
    uint16_t src_addr;
    float pitch, roll, yaw;
    uint32_t now_ms = (uint32_t)(esp_timer_get_time() / 1000);
    if(msg->data.size == 15)
    {
        // 从负载中拷贝数据：偏移0处2字节为短地址（小端模式）
        memcpy(&src_addr, p+1, 2);
        // 偏移2处4字节为 pitch 角
        memcpy(&pitch, p + 3, 4);
        // 偏移6处4字节为 roll 角
        
        memcpy(&roll, p + 7, 4);
        // 偏移10处4字节为 yaw 角
        memcpy(&yaw, p + 11, 4);
        // 打印姿态数据到串口
        ESP_LOGI(TAG, "[姿态数据] 源地址=0x%04x, Pitch=%.2f°, Roll=%.2f°, Yaw=%.2f°",
                src_addr, pitch, roll, yaw);
        return ESP_OK;
    }
            if(msg->data.size == 50){
            uint16_t seq;
            memcpy(&seq,p+1,2);//偏移0处2字节为序列号（小端模式）
            memcpy(&src_addr,  p + 3,  2);

            /* [关键] 丢包率统计 */
            rx_stats_t *st = find_or_create_stats(src_addr);
            if (st) {
                  if (!st->first_rx) {
                    uint16_t diff = seq - st->last_seq;
                    if (diff == 0) {
                        // MAC层重传导致的重复包，不计入统计
                        return ESP_OK;
                    }
                    if (diff > 1 && diff < 1000) {
                        st->drop_count += (diff - 1);
                    }
                }else {
                    st->first_rx = false;
                }
                st->last_seq = seq;
                st->rx_count++;
                st->rx_bytes += msg->data.size;

                uint32_t now_ms = (uint32_t)(esp_timer_get_time() / 1000);
                if (st->rx_count == 1) st->first_rx_ms = now_ms;
                st->last_rx_ms = now_ms;
            }
            return ESP_OK;
            // ESP_LOGI(TAG, "[吞吐测试] 源地址=0x%04x, Seq=%u, 累计RX=%lu, DROP=%lu",
            //         src_addr, seq, st ? st->rx_count : 0, st ? st->drop_count : 0);
        } else {
            ESP_LOGW(TAG, "Unknown payload size: %d (expected 15 or 50)", msg->data.size);
            return ESP_FAIL;
        }
}

static esp_err_t zb_action_handler(esp_zb_core_action_callback_id_t callback_id, const void *message)
{
    // ESP_LOGI(TAG, ">>> zb_action_handler triggered, callback_id = 0x%x", callback_id);
    // 根据回调 ID 进行分发处理
    switch (callback_id) {
    case ESP_ZB_CORE_CMD_CUSTOM_CLUSTER_REQ_CB_ID:
        // 自定义 cluster 命令请求：将 message 转换为正确的结构体类型并调用处理函数
        //esp_zb_zcl_custom_cluster_command_message_t 是 ZCL 层传递过来的结构体，包含了命令的基本信息和数据负载，我们需要解析它来获取姿态数据
        return zb_custom_cluster_handler((const esp_zb_zcl_custom_cluster_command_message_t*)message);

    default:
        // 其它未处理的回调 ID，仅打印警告（可选）
        ESP_LOGW(TAG, "Unhandled Zigbee action callback ID: 0x%x", callback_id);
        return ESP_OK;  // 不阻断其他处理
    }
}
/* ------------------ Zigbee 主任务 ------------------ */

static void esp_zb_task(void *pvParameters)
{
    esp_zb_cfg_t zb_nwk_cfg = ESP_ZB_ZC_CONFIG();
    esp_zb_init(&zb_nwk_cfg);
     /* ========== 手动构建端点 ========== */
    esp_zb_cluster_list_t *cluster_list = esp_zb_zcl_cluster_list_create();
    //基础 Cluster，提供了设备基本信息和一些通用功能，ZCL 标准定义了它的 Cluster ID 是 0x0000，且必须由服务器端实现
    esp_zb_cluster_list_add_basic_cluster(cluster_list, esp_zb_basic_cluster_create(NULL), ESP_ZB_ZCL_CLUSTER_SERVER_ROLE);
 /* ========== 手动构建端点，插入 0xFC00 自定义 Cluster ========== */
    esp_zb_attribute_list_t *custom_attrs = esp_zb_zcl_attr_list_create(0xFC00);
    esp_zb_cluster_list_add_custom_cluster(cluster_list, custom_attrs, ESP_ZB_ZCL_CLUSTER_SERVER_ROLE);

    /* 4. 端点配置结构体（新版） */
    esp_zb_endpoint_config_t endpoint_config = {
        .endpoint = 1,
        .app_profile_id = ESP_ZB_AF_HA_PROFILE_ID,
        .app_device_id = 0xFFFF,// 0xFFFF 表示自定义设备 ID，协调器通常不需要特定设备 ID
        .app_device_version = 0,
    };

    esp_zb_ep_list_t *ep_list = esp_zb_ep_list_create();
    esp_zb_ep_list_add_ep(ep_list, cluster_list, endpoint_config); // 将集群列表添加到端点上
    zcl_basic_manufacturer_info_t info = {
        .manufacturer_name = ESP_MANUFACTURER_NAME,
        .model_identifier = ESP_MODEL_IDENTIFIER,
    };
    esp_zcl_utility_add_ep_basic_manufacturer_info(ep_list, 1, &info);

    esp_zb_device_register(ep_list);
    esp_zb_core_action_handler_register(zb_action_handler);
    esp_zb_set_primary_network_channel_set(ESP_ZB_PRIMARY_CHANNEL_MASK);
    ESP_ERROR_CHECK(esp_zb_start(false));
    esp_zb_stack_main_loop();
}

/* ------------------ 入口 ------------------ */
void app_main(void)
{
    esp_zb_platform_config_t config = {
        .radio_config = ESP_ZB_DEFAULT_RADIO_CONFIG(),
        .host_config = ESP_ZB_DEFAULT_HOST_CONFIG(),
    };

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
    }

    ESP_ERROR_CHECK(esp_zb_platform_config(&config));
    esp_log_level_set(TAG, ESP_LOG_INFO);

    esp_log_level_set("esp_zb_zcl", ESP_LOG_DEBUG);   // ZCL 层调试
    esp_log_level_set("esp_zb_aps", ESP_LOG_DEBUG);   // APS 层调试
    xTaskCreate(comm_quality_monitor_task, "CommMonitor", 4096, NULL, 4, NULL);
    xTaskCreate(esp_zb_task, "ZigbeeMain", 4096, NULL, 5, NULL);
}
