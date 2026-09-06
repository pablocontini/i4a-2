#ifndef CONFIG_PORTAL_H
#define CONFIG_PORTAL_H

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef esp_err_t (*config_portal_apply_password_cb_t)(const char *password,
                                                       void *context);
typedef esp_err_t (*config_portal_apply_powers_cb_t)(
    const uint8_t *power_qdbm, size_t count, void *context);

/**
 * Configure the central module BOOT button and start its monitor task.
 * A debounced short press enables two HTTP areas for five minutes: the root
 * page lets the final user change only the ComNetAR Wi-Fi credentials, while
 * /admin requires administrator authentication and manages only the stored
 * directional antenna powers and administrator password. Holding BOOT for
 * six seconds restores only the ComNetAR Wi-Fi credentials; it does not reset
 * the administrator verifier or stored directional antenna powers.
 * One callback applies a saved credential to the running ComNetAR AP without
 * restarting the node. The other schedules distribution of the already saved
 * directional antenna powers and a coordinated node restart.
 */
esp_err_t config_portal_init(config_portal_apply_password_cb_t apply_password,
                             config_portal_apply_powers_cb_t apply_powers,
                             void *context);

#ifdef __cplusplus
}
#endif

#endif // CONFIG_PORTAL_H
