#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_system.h"
#include <string.h>
#include "config.h"
#include "reset_manager/reset_manager.h"

void node_set_orientation_mode_requested(bool enabled);
void node_set_configuration_mode_requested(bool enabled);

#define ROOT_UUID "000000000000"

static const char *TAG = "reset_manager";

static reset_manager_t reset_manager = {0};
static reset_manager_t *rm = &reset_manager;

#define RESET_TIMEOUT_US 30000000 // 30 Seconds
#define RESET_BROADCAST_WAIT_MS 2000 // 2 Seconds

#define RM_OPCODE_RESET    0xA5
#define RM_OPCODE_STARTUP  0xB6

static uint8_t local_tx_power_qdbm = RM_DEFAULT_TX_POWER_QDBM;
static int8_t local_rssi_threshold_dbm = RM_DEFAULT_RSSI_THRESHOLD_DBM;

static bool rm_is_valid_power(uint8_t power_qdbm) {
    static const uint8_t supported_levels[] = {
        8, 20, 28, 34, 44, 52, 56, 60, 66, 72, 80,
    };

    for (size_t index = 0;
         index < sizeof(supported_levels) / sizeof(supported_levels[0]);
         index++) {
        if (power_qdbm == supported_levels[index]) {
            return true;
        }
    }

    return false;
}

static bool rm_radio_settings_are_valid(
    const uint8_t power_qdbm[RM_DIRECTIONAL_ANTENNA_COUNT],
    const int8_t rssi_threshold_dbm[RM_DIRECTIONAL_ANTENNA_COUNT]) {
    if (power_qdbm == NULL || rssi_threshold_dbm == NULL) {
        return false;
    }

    for (size_t index = 0; index < RM_DIRECTIONAL_ANTENNA_COUNT; index++) {
        if (!rm_is_valid_power(power_qdbm[index]) ||
            rssi_threshold_dbm[index] > -1) {
            return false;
        }
    }
    return true;
}

static void rm_generate_uuid_from_mac(char *uuid_out, size_t len) {
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);
    snprintf(uuid_out, len, "%02X%02X%02X%02X%02X%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void rm_on_sibling_message(void *ctx, const uint8_t *msg, uint16_t len) {
    if (len < 1) {
        return;
    }

    switch (msg[0]) {
        case RM_OPCODE_RESET:
            if (!rm->is_up) {
                rm->last_reset_time = esp_timer_get_time();
                ESP_LOGI(TAG, "Reset signal received: still on setup, not resetting");
                return;
            } else {
                ESP_LOGW(TAG, "Reset signal received: resetting device");
                vTaskDelay(pdMS_TO_TICKS(RESET_BROADCAST_WAIT_MS)); // Wait for the broadcast to be fully passed on to the ring
                esp_restart();
            }

            break;

        case RM_OPCODE_STARTUP:
            if (len != sizeof(rm_startup_packet_t)) {
                ESP_LOGW(TAG, "Invalid startup message length: %d", len);
                return;
            } else {
                rm_startup_packet_t startup;
                memcpy(&startup, msg, sizeof(startup));
                if (startup.version != RM_STARTUP_PACKET_VERSION ||
                    !rm_radio_settings_are_valid(
                        startup.tx_power_qdbm,
                        startup.rssi_threshold_dbm)) {
                    ESP_LOGW(TAG,
                             "Invalid startup packet version or radio settings");
                    return;
                }

                strncpy(rm->uuid, startup.uuid, UUID_LENGTH);
                rm->uuid[UUID_LENGTH - 1] = '\0';
                rm->is_root = startup.is_root;
                node_set_orientation_mode_requested(
                    startup.orientation_mode != 0);
                node_set_configuration_mode_requested(
                    startup.configuration_mode != 0);

                config_id_t orientation = config_get_id();
                if (orientation <= CONFIG_ID_WEST) {
                    local_tx_power_qdbm =
                        startup.tx_power_qdbm[orientation];
                    local_rssi_threshold_dbm =
                        startup.rssi_threshold_dbm[orientation];
                }
                ESP_LOGI(TAG,
                         "Startup received: UUID=%s root=%d orientation_mode=%d configuration_mode=%d tx=%u qdBm min_rssi=%d dBm",
                         rm->uuid, rm->is_root,
                         startup.orientation_mode,
                         startup.configuration_mode,
                         (unsigned int)local_tx_power_qdbm,
                         (int)local_rssi_threshold_dbm);

                rm->is_up = true;
            }
            break;

        default:
            ESP_LOGW(TAG, "Unknown message opcode: 0x%02X", msg[0]);
            break;
    }
}

// Initialize reset manager
void rm_init(ring_share_t *rs) {
    rm->rs = rs;
    rm->is_up = false;
    rm->is_root = false;
    rm->last_reset_time = esp_timer_get_time();
    local_tx_power_qdbm = RM_DEFAULT_TX_POWER_QDBM;
    local_rssi_threshold_dbm = RM_DEFAULT_RSSI_THRESHOLD_DBM;
    rm_generate_uuid_from_mac(rm->mac, sizeof(rm->mac));
    memset(rm->uuid, 0, sizeof(rm->uuid));

    rs_register_component(
        rm->rs,
        RS_RESET_MANAGER,
        (ring_callback_t){
            .callback = rm_on_sibling_message,
            .context = rm
        }
    );

    ESP_LOGI(TAG, "Reset manager initialized");
}

bool rm_broadcast_reset(void) {
    if (!rm->rs) {
        ESP_LOGW(TAG, "RESET broadcast skipped: manager not initialized");
        return false;
    }

    rm->last_reset_time = esp_timer_get_time();
    uint8_t opcode = RM_OPCODE_RESET;

    bool result = rs_broadcast(rm->rs, RS_RESET_MANAGER, &opcode, 1);

    if(result) {
        ESP_LOGI(TAG, "Reset broadcast successfully sent to all devices");
    }

    return result;
}

uint8_t rm_get_local_antenna_power(void) {
    return local_tx_power_qdbm;
}

int8_t rm_get_local_rssi_threshold(void) {
    return local_rssi_threshold_dbm;
}

bool rm_broadcast_startup_info(
    bool is_root, bool orientation_mode, bool configuration_mode,
    const uint8_t tx_power_qdbm[RM_DIRECTIONAL_ANTENNA_COUNT],
    const int8_t rssi_threshold_dbm[RM_DIRECTIONAL_ANTENNA_COUNT]) {
    if (!rm->rs) {
        ESP_LOGW(TAG, "STARTUP broadcast skipped: manager not initialized");
        return false;
    }
    if (!rm_radio_settings_are_valid(tx_power_qdbm,
                                     rssi_threshold_dbm)) {
        ESP_LOGE(TAG, "STARTUP broadcast rejected: invalid radio settings");
        return false;
    }

    rm_startup_packet_t packet = {0};
    packet.opcode = RM_OPCODE_STARTUP;
    packet.version = RM_STARTUP_PACKET_VERSION;
    
    if(is_root){
        strncpy(rm->uuid, ROOT_UUID, sizeof(rm->uuid));
    } else {
        strncpy(rm->uuid, rm->mac, sizeof(rm->uuid));
    }
    
    strncpy(packet.uuid, rm->uuid, sizeof(packet.uuid));
    packet.uuid[sizeof(packet.uuid) - 1] = '\0';
    packet.is_root = is_root ? 1 : 0;
    packet.orientation_mode = orientation_mode ? 1 : 0;
    packet.configuration_mode = configuration_mode ? 1 : 0;
    memcpy(packet.tx_power_qdbm, tx_power_qdbm,
           sizeof(packet.tx_power_qdbm));
    memcpy(packet.rssi_threshold_dbm, rssi_threshold_dbm,
           sizeof(packet.rssi_threshold_dbm));
    rm->is_root = is_root;

    bool broadcast = rs_broadcast(rm->rs, RS_RESET_MANAGER, (uint8_t *)&packet, sizeof(packet));

    if(broadcast) {
        ESP_LOGI(TAG,
                 "Startup broadcasted: UUID=%s root=%d orientation_mode=%d configuration_mode=%d",
                 rm->uuid, rm->is_root, packet.orientation_mode,
                 packet.configuration_mode);
        rm->is_up = true;
    }

    return broadcast;
}

bool rm_should_device_reset(void){
    int64_t current_time = esp_timer_get_time();
    return ((current_time - rm->last_reset_time) > RESET_TIMEOUT_US);
}

bool rm_is_device_up(void) {
    return rm->is_up;
}

bool rm_is_root(void){
    return rm->is_root;
}

const char *rm_get_uuid(void) {
    return rm->uuid;
}

const char *rm_get_mac(void){
    return rm->mac;
}

int64_t rm_get_last_reset_time(void) {
    return rm->last_reset_time;
}
