#ifndef CONFIG_PORTAL_H
#define CONFIG_PORTAL_H

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef esp_err_t (*config_portal_apply_password_cb_t)(const char *password,
                                                       void *context);

/**
 * Configure the central module BOOT button and start its monitor task.
 * A debounced short press enables the password portal. Holding it for six
 * seconds restores the ComNetAR credentials immediately; release is not
 * required to trigger the operation.
 * The callback applies a saved credential to the running ComNetAR AP without
 * restarting the node.
 */
esp_err_t config_portal_init(config_portal_apply_password_cb_t apply_password,
                             void *context);

#ifdef __cplusplus
}
#endif

#endif // CONFIG_PORTAL_H
