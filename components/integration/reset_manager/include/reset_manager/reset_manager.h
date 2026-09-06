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

typedef struct {
    uint8_t opcode;
    char uuid[UUID_LENGTH];
    uint8_t is_root;
} rm_startup_packet_t;

typedef struct reset_manager {
    ring_share_t *rs;
    bool is_up;
    bool is_root;
    char uuid[UUID_LENGTH];
    char mac[UUID_LENGTH];
    int64_t last_reset_time;
} reset_manager_t;

void rm_init(ring_share_t *rs);

/** Load this directional module's persisted power after NVS is initialized. */
esp_err_t rm_power_storage_init(void);

bool rm_broadcast_reset(void);
bool rm_broadcast_startup_info(bool is_root);

/**
 * Asynchronously distribute four directional powers from the central module.
 * A coordinated reset is emitted only after all four modules acknowledge
 * successful NVS persistence.
 */
esp_err_t rm_schedule_antenna_power_update(
    const uint8_t *power_qdbm, size_t count);

bool rm_is_antenna_power_update_pending(void);

/** Return this directional module's configured power, in 0.25 dBm units. */
uint8_t rm_get_local_antenna_power(void);
bool rm_is_device_up(void);
bool rm_is_root(void);
bool rm_should_device_reset(void);
const char *rm_get_uuid(void);
const char *rm_get_mac(void);
int64_t rm_get_last_reset_time(void);

#endif  // _RESET_MANAGER_H_
