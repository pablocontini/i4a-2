#ifndef PORTAL_SETTINGS_H
#define PORTAL_SETTINGS_H

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PORTAL_SETTINGS_ADMIN_PASSWORD_MIN_LENGTH 8
#define PORTAL_SETTINGS_ADMIN_PASSWORD_MAX_LENGTH 63

#define PORTAL_SETTINGS_ANTENNA_COUNT 4
#define PORTAL_SETTINGS_DEFAULT_POWER_QDBM 80
#define PORTAL_SETTINGS_DEFAULT_RSSI_THRESHOLD_DBM (-128)

typedef enum {
    PORTAL_ANTENNA_NORTH = 0,
    PORTAL_ANTENNA_SOUTH,
    PORTAL_ANTENNA_EAST,
    PORTAL_ANTENNA_WEST,
} portal_antenna_t;

/**
 * Maximum transmit power for the four directional ESP32 radios. Values use
 * the ESP-IDF unit of 0.25 dBm so they can later be passed to the Wi-Fi
 * driver without losing precision. The central hotspot is intentionally not
 * represented here.
 */
typedef struct {
    uint8_t quarter_dbm[PORTAL_SETTINGS_ANTENNA_COUNT];
} portal_antenna_power_config_t;

/**
 * Minimum received signal level accepted by each directional station. An AP
 * whose RSSI is below the corresponding value is ignored. Values are dBm;
 * -128 disables the practical cutoff and preserves the original behaviour.
 */
typedef struct {
    int8_t dbm[PORTAL_SETTINGS_ANTENNA_COUNT];
} portal_antenna_rssi_config_t;

/** Load the administrator verifier and antenna settings from NVS. */
esp_err_t portal_settings_init(void);

/** Validate an administrator password before hashing or persisting it. */
bool portal_settings_is_valid_admin_password(const char *password);

/** Verify a password against the salted PBKDF2 verifier stored in NVS. */
bool portal_settings_verify_admin_password(const char *password);

/** Replace the administrator password verifier in NVS. */
esp_err_t portal_settings_set_admin_password(const char *password);

/** True until the initial administrator password has been replaced. */
bool portal_settings_is_using_initial_password(void);

/** Validate one of the transmit-power levels supported by ESP-IDF v5.1.2. */
bool portal_settings_is_valid_power_qdbm(uint8_t quarter_dbm);

/** Return a copy of the four persisted directional antenna powers. */
portal_antenna_power_config_t portal_settings_get_antenna_powers(void);

/** Atomically persist all four directional antenna powers in NVS. */
esp_err_t portal_settings_set_antenna_powers(
    const portal_antenna_power_config_t *config);

/** Validate an RSSI threshold expressed in dBm. */
bool portal_settings_is_valid_rssi_threshold(int rssi_dbm);

/** Return a copy of the four persisted RSSI thresholds. */
portal_antenna_rssi_config_t portal_settings_get_antenna_rssi_thresholds(void);

/** Atomically persist all four directional RSSI thresholds in NVS. */
esp_err_t portal_settings_set_antenna_rssi_thresholds(
    const portal_antenna_rssi_config_t *config);

#ifdef __cplusplus
}
#endif

#endif // PORTAL_SETTINGS_H
