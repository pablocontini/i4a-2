#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_system.h"
#include "nvs.h"
#include <string.h>
#include "config.h"
#include "traffic.h"
#include "reset_manager/reset_manager.h"

void node_set_orientation_mode_requested(bool enabled);

#define ROOT_UUID "000000000000"

static const char *TAG = "reset_manager";

static reset_manager_t reset_manager = {0};
static reset_manager_t *rm = &reset_manager;

#define RESET_TIMEOUT_US 30000000 // 30 Seconds
#define RESET_BROADCAST_WAIT_MS 2000 // 2 Seconds
#define POWER_ACK_TIMEOUT_MS 20000 // 20 Seconds
#define POWER_APPLY_POLL_MS 50
#define POWER_APPLY_TASK_STACK 4096
#define POWER_APPLY_TASK_PRIORITY 5

#define POWER_NVS_NAMESPACE "antenna_node"
#define POWER_NVS_KEY "powers"
#define POWER_PACKET_VERSION 1
#define POWER_ACK_SUCCESS_MASK 0x0F

#define RM_OPCODE_RESET    0xA5
#define RM_OPCODE_STARTUP  0xB6
#define RM_OPCODE_POWER_CONFIG 0xC7
#define RM_OPCODE_POWER_ACK 0xD8

#define RM_POWER_ACK_OK 0
#define RM_POWER_ACK_INVALID_CONFIG 1
#define RM_POWER_ACK_NVS_ERROR 2

typedef struct __attribute__((packed)) {
    uint8_t opcode;
    uint8_t version;
    uint16_t transaction_id;
    uint8_t power_qdbm[RM_DIRECTIONAL_ANTENNA_COUNT];
} rm_power_config_packet_t;

typedef struct __attribute__((packed)) {
    uint8_t opcode;
    uint8_t version;
    uint16_t transaction_id;
    uint8_t orientation;
    uint8_t status;
} rm_power_ack_packet_t;

static uint8_t local_power_config[RM_DIRECTIONAL_ANTENNA_COUNT] = {
    RM_DEFAULT_TX_POWER_QDBM,
    RM_DEFAULT_TX_POWER_QDBM,
    RM_DEFAULT_TX_POWER_QDBM,
    RM_DEFAULT_TX_POWER_QDBM,
};
static bool power_storage_initialized = false;
static bool power_update_pending = false;
static uint8_t pending_power_config[RM_DIRECTIONAL_ANTENNA_COUNT];
static uint16_t power_transaction_counter = 0;
static uint16_t expected_power_transaction = 0;
static uint8_t power_ack_success_mask = 0;
static uint8_t power_ack_failure_mask = 0;
static portMUX_TYPE power_ack_lock = portMUX_INITIALIZER_UNLOCKED;

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

static bool rm_power_config_is_valid(
    const uint8_t power_qdbm[RM_DIRECTIONAL_ANTENNA_COUNT]) {
    for (size_t index = 0; index < RM_DIRECTIONAL_ANTENNA_COUNT; index++) {
        if (!rm_is_valid_power(power_qdbm[index])) {
            return false;
        }
    }
    return true;
}

static void rm_set_default_power_config(void) {
    for (size_t index = 0; index < RM_DIRECTIONAL_ANTENNA_COUNT; index++) {
        local_power_config[index] = RM_DEFAULT_TX_POWER_QDBM;
    }
}

static esp_err_t rm_persist_power_config(
    const uint8_t power_qdbm[RM_DIRECTIONAL_ANTENNA_COUNT]) {
    if (!power_storage_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!rm_power_config_is_valid(power_qdbm)) {
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open(POWER_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        return err;
    }

    err = nvs_set_blob(handle, POWER_NVS_KEY, power_qdbm,
                       RM_DIRECTIONAL_ANTENNA_COUNT);
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    nvs_close(handle);

    if (err == ESP_OK) {
        memcpy(local_power_config, power_qdbm, sizeof(local_power_config));
    }
    return err;
}

static void rm_send_power_ack(uint16_t transaction_id,
                              config_id_t orientation, uint8_t status) {
    rm_power_ack_packet_t ack = {
        .opcode = RM_OPCODE_POWER_ACK,
        .version = POWER_PACKET_VERSION,
        .transaction_id = transaction_id,
        .orientation = (uint8_t)orientation,
        .status = status,
    };

    if (!rs_broadcast(rm->rs, RS_RESET_MANAGER, &ack, sizeof(ack))) {
        ESP_LOGW(TAG, "Unable to broadcast power ACK: orientation=%u transaction=%u",
                 (unsigned int)orientation, (unsigned int)transaction_id);
    }
}

static void rm_handle_power_config(const uint8_t *msg, uint16_t len) {
    if (len != sizeof(rm_power_config_packet_t)) {
        ESP_LOGW(TAG, "Invalid power configuration length: %u",
                 (unsigned int)len);
        return;
    }

    rm_power_config_packet_t packet;
    memcpy(&packet, msg, sizeof(packet));
    config_id_t orientation = config_get_id();
    if (orientation > CONFIG_ID_WEST) {
        return;
    }

    uint8_t status = RM_POWER_ACK_OK;
    esp_err_t err = ESP_OK;
    if (packet.version != POWER_PACKET_VERSION ||
        !rm_power_config_is_valid(packet.power_qdbm)) {
        status = RM_POWER_ACK_INVALID_CONFIG;
        err = ESP_ERR_INVALID_ARG;
    } else {
        err = rm_persist_power_config(packet.power_qdbm);
        if (err != ESP_OK) {
            status = RM_POWER_ACK_NVS_ERROR;
        }
    }

    if (err == ESP_OK) {
        ESP_LOGI(TAG,
                 "Power configuration stored: orientation=%u power=%u qdBm transaction=%u",
                 (unsigned int)orientation,
                 (unsigned int)packet.power_qdbm[orientation],
                 (unsigned int)packet.transaction_id);
    } else {
        ESP_LOGE(TAG,
                 "Power configuration rejected: orientation=%u transaction=%u error=%s",
                 (unsigned int)orientation,
                 (unsigned int)packet.transaction_id,
                 esp_err_to_name(err));
    }

    rm_send_power_ack(packet.transaction_id, orientation, status);
}

static void rm_handle_power_ack(const uint8_t *msg, uint16_t len) {
    if (len != sizeof(rm_power_ack_packet_t) ||
        config_get_id() != CONFIG_ID_CENTER) {
        return;
    }

    rm_power_ack_packet_t ack;
    memcpy(&ack, msg, sizeof(ack));
    if (ack.version != POWER_PACKET_VERSION ||
        ack.orientation > CONFIG_ID_WEST) {
        return;
    }

    uint8_t orientation_bit = (uint8_t)(1U << ack.orientation);
    taskENTER_CRITICAL(&power_ack_lock);
    if (power_update_pending &&
        ack.transaction_id == expected_power_transaction) {
        if (ack.status == RM_POWER_ACK_OK) {
            power_ack_success_mask |= orientation_bit;
        } else {
            power_ack_failure_mask |= orientation_bit;
        }
    }
    taskEXIT_CRITICAL(&power_ack_lock);
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
                const rm_startup_packet_t *startup = (const rm_startup_packet_t *)msg;

                strncpy(rm->uuid, startup->uuid, UUID_LENGTH);
                rm->uuid[UUID_LENGTH - 1] = '\0';
                rm->is_root = startup->is_root;
                node_set_orientation_mode_requested(
                    startup->orientation_mode != 0);
                ESP_LOGI(TAG,
                         "Startup message received: UUID=%s, is_root=%d, orientation_mode=%d",
                         rm->uuid, rm->is_root,
                         startup->orientation_mode);

                rm->is_up = true;
            }
            break;

        case RM_OPCODE_POWER_CONFIG:
            rm_handle_power_config(msg, len);
            break;

        case RM_OPCODE_POWER_ACK:
            rm_handle_power_ack(msg, len);
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
    power_update_pending = false;
    expected_power_transaction = 0;
    power_ack_success_mask = 0;
    power_ack_failure_mask = 0;
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

esp_err_t rm_power_storage_init(void) {
    if (power_storage_initialized) {
        return ESP_OK;
    }

    rm_set_default_power_config();
    config_id_t orientation = config_get_id();
    if (orientation > CONFIG_ID_WEST) {
        power_storage_initialized = true;
        return ESP_OK;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open(POWER_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to open local antenna power store: %s",
                 esp_err_to_name(err));
        return err;
    }

    uint8_t stored[RM_DIRECTIONAL_ANTENNA_COUNT] = {0};
    size_t stored_length = sizeof(stored);
    err = nvs_get_blob(handle, POWER_NVS_KEY, stored, &stored_length);
    bool stored_valid = err == ESP_OK && stored_length == sizeof(stored) &&
        rm_power_config_is_valid(stored);

    if (stored_valid) {
        memcpy(local_power_config, stored, sizeof(local_power_config));
    } else {
        if (err != ESP_ERR_NVS_NOT_FOUND && err != ESP_OK) {
            ESP_LOGW(TAG, "Invalid local antenna power store: %s",
                     esp_err_to_name(err));
        }

        esp_err_t erase_err = nvs_erase_key(handle, POWER_NVS_KEY);
        if (erase_err != ESP_OK && erase_err != ESP_ERR_NVS_NOT_FOUND) {
            err = erase_err;
        } else {
            err = nvs_set_blob(handle, POWER_NVS_KEY, local_power_config,
                               sizeof(local_power_config));
        }
        if (err == ESP_OK) {
            err = nvs_commit(handle);
        }
    }

    nvs_close(handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to initialize local antenna powers: %s",
                 esp_err_to_name(err));
        return err;
    }

    power_storage_initialized = true;
    ESP_LOGI(TAG, "Local antenna power loaded: orientation=%u power=%u qdBm",
             (unsigned int)orientation,
             (unsigned int)local_power_config[orientation]);
    return ESP_OK;
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

static void rm_clear_power_update_state(void) {
    taskENTER_CRITICAL(&power_ack_lock);
    expected_power_transaction = 0;
    power_ack_success_mask = 0;
    power_ack_failure_mask = 0;
    power_update_pending = false;
    taskEXIT_CRITICAL(&power_ack_lock);
}

static void rm_antenna_power_update_task(void *argument) {
    (void)argument;

    rm_power_config_packet_t packet = {
        .opcode = RM_OPCODE_POWER_CONFIG,
        .version = POWER_PACKET_VERSION,
    };
    memcpy(packet.power_qdbm, pending_power_config,
           sizeof(packet.power_qdbm));

    taskENTER_CRITICAL(&power_ack_lock);
    power_transaction_counter++;
    if (power_transaction_counter == 0) {
        power_transaction_counter++;
    }
    packet.transaction_id = power_transaction_counter;
    expected_power_transaction = packet.transaction_id;
    power_ack_success_mask = 0;
    power_ack_failure_mask = 0;
    taskEXIT_CRITICAL(&power_ack_lock);

    ESP_LOGI(TAG, "Broadcasting antenna powers: transaction=%u",
             (unsigned int)packet.transaction_id);
    if (!rs_broadcast(rm->rs, RS_RESET_MANAGER, &packet, sizeof(packet))) {
        ESP_LOGW(TAG,
                 "Power configuration did not complete a clean ring traversal; waiting for ACKs");
    }

    int64_t deadline_us = esp_timer_get_time() +
        (int64_t)POWER_ACK_TIMEOUT_MS * 1000;
    while (esp_timer_get_time() < deadline_us) {
        uint8_t success_mask;
        uint8_t failure_mask;
        taskENTER_CRITICAL(&power_ack_lock);
        success_mask = power_ack_success_mask;
        failure_mask = power_ack_failure_mask;
        taskEXIT_CRITICAL(&power_ack_lock);

        if (failure_mask != 0) {
            ESP_LOGE(TAG,
                     "Antenna power update aborted by negative ACK mask 0x%02x",
                     failure_mask);
            rm_clear_power_update_state();
            vTaskDelete(NULL);
            return;
        }

        if (success_mask == POWER_ACK_SUCCESS_MASK) {
            ESP_LOGI(TAG,
                     "All directional modules persisted antenna powers; restarting node");
            if (!rm_broadcast_reset()) {
                ESP_LOGW(TAG,
                         "Reset broadcast did not complete; central restart will retry synchronization on boot");
            }

            vTaskDelay(pdMS_TO_TICKS(RESET_BROADCAST_WAIT_MS + 500));
            esp_restart();
        }

        vTaskDelay(pdMS_TO_TICKS(POWER_APPLY_POLL_MS));
    }

    uint8_t success_mask;
    taskENTER_CRITICAL(&power_ack_lock);
    success_mask = power_ack_success_mask;
    taskEXIT_CRITICAL(&power_ack_lock);
    ESP_LOGE(TAG,
             "Antenna power update timed out: ACK mask 0x%02x, expected 0x%02x",
             success_mask, POWER_ACK_SUCCESS_MASK);
    rm_clear_power_update_state();
    vTaskDelete(NULL);
}

esp_err_t rm_schedule_antenna_power_update(const uint8_t *power_qdbm,
                                           size_t count) {
    if (power_qdbm == NULL || count != RM_DIRECTIONAL_ANTENNA_COUNT ||
        !rm_power_config_is_valid(power_qdbm)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (rm->rs == NULL || !rm->is_up || !power_storage_initialized ||
        config_get_id() != CONFIG_ID_CENTER) {
        return ESP_ERR_INVALID_STATE;
    }

    taskENTER_CRITICAL(&power_ack_lock);
    if (power_update_pending) {
        taskEXIT_CRITICAL(&power_ack_lock);
        return ESP_ERR_INVALID_STATE;
    }
    memcpy(pending_power_config, power_qdbm,
           sizeof(pending_power_config));
    power_update_pending = true;
    taskEXIT_CRITICAL(&power_ack_lock);

    BaseType_t created = xTaskCreate(
        rm_antenna_power_update_task,
        "power_update",
        POWER_APPLY_TASK_STACK,
        NULL,
        POWER_APPLY_TASK_PRIORITY,
        NULL);
    if (created != pdPASS) {
        rm_clear_power_update_state();
        return ESP_ERR_NO_MEM;
    }

    return ESP_OK;
}

bool rm_is_antenna_power_update_pending(void) {
    taskENTER_CRITICAL(&power_ack_lock);
    bool pending = power_update_pending;
    taskEXIT_CRITICAL(&power_ack_lock);
    return pending;
}

uint8_t rm_get_local_antenna_power(void) {
    config_id_t orientation = config_get_id();
    if (!power_storage_initialized || orientation > CONFIG_ID_WEST) {
        return RM_DEFAULT_TX_POWER_QDBM;
    }
    return local_power_config[orientation];
}

bool rm_broadcast_startup_info(bool is_root, bool orientation_mode) {
    if (!rm->rs) {
        ESP_LOGW(TAG, "STARTUP broadcast skipped: manager not initialized");
        return false;
    }

    rm_startup_packet_t packet;
    packet.opcode = RM_OPCODE_STARTUP;
    
    if(is_root){
        strncpy(rm->uuid, ROOT_UUID, sizeof(rm->uuid));
    } else {
        strncpy(rm->uuid, rm->mac, sizeof(rm->uuid));
    }
    
    strncpy(packet.uuid, rm->uuid, sizeof(packet.uuid));
    packet.uuid[sizeof(packet.uuid) - 1] = '\0';
    packet.is_root = is_root ? 1 : 0;
    packet.orientation_mode = orientation_mode ? 1 : 0;
    rm->is_root = is_root;

    bool broadcast = rs_broadcast(rm->rs, RS_RESET_MANAGER, (uint8_t *)&packet, sizeof(packet));

    if(broadcast) {
        ESP_LOGI(TAG,
                 "Startup message broadcasted: UUID=%s, is_root=%d, orientation_mode=%d",
                 rm->uuid, rm->is_root, packet.orientation_mode);
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
