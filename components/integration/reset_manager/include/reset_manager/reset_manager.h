#ifndef _RESET_MANAGER_H_
#define _RESET_MANAGER_H_

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"
#include "ring_share/ring_share.h"

#define UUID_LENGTH 13
#define RM_DIRECTIONAL_ANTENNA_COUNT 4
#define RM_DEFAULT_TX_POWER_QDBM 80
#define RM_DEFAULT_RSSI_THRESHOLD_DBM (-128)
#define RM_STARTUP_PACKET_VERSION 2

typedef struct __attribute__((packed)) {
    uint8_t opcode;
    uint8_t version;
    char uuid[UUID_LENGTH];
    uint8_t is_root;
    uint8_t orientation_mode;
    uint8_t configuration_mode;
    uint8_t tx_power_qdbm[RM_DIRECTIONAL_ANTENNA_COUNT];
    int8_t rssi_threshold_dbm[RM_DIRECTIONAL_ANTENNA_COUNT];
} rm_startup_packet_t;

_Static_assert(sizeof(rm_startup_packet_t) <= RS_MAX_BROADCAST_LEN,
               "Startup packet exceeds ring_share capacity");

typedef struct reset_manager {
    ring_share_t *rs;
    bool is_up;
    bool is_root;
    char uuid[UUID_LENGTH];
    char mac[UUID_LENGTH];
    int64_t last_reset_time;
} reset_manager_t;

void rm_init(ring_share_t *rs);

bool rm_broadcast_reset(void);
bool rm_broadcast_startup_info(
    bool is_root, bool orientation_mode, bool configuration_mode,
    const uint8_t tx_power_qdbm[RM_DIRECTIONAL_ANTENNA_COUNT],
    const int8_t rssi_threshold_dbm[RM_DIRECTIONAL_ANTENNA_COUNT]);

/** Return this directional module's configured power, in 0.25 dBm units. */
uint8_t rm_get_local_antenna_power(void);

/** Return the minimum RSSI accepted by this directional module, in dBm. */
int8_t rm_get_local_rssi_threshold(void);
bool rm_is_device_up(void);
bool rm_is_root(void);
bool rm_should_device_reset(void);
const char *rm_get_uuid(void);
const char *rm_get_mac(void);
int64_t rm_get_last_reset_time(void);

#endif  // _RESET_MANAGER_H_
