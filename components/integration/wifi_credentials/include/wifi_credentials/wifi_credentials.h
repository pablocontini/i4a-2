#ifndef WIFI_CREDENTIALS_H
#define WIFI_CREDENTIALS_H

#include <stdbool.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WIFI_CREDENTIALS_PASSWORD_MAX_LENGTH 63

/**
 * Initialize the ComNetAR credential store and load the saved password.
 * An empty password is used when the device has factory settings.
 */
esp_err_t wifi_credentials_init(void);

/**
 * Return the password loaded in RAM. The returned pointer remains owned by
 * this component and must not be modified or freed.
 */
const char *wifi_credentials_get_house_password(void);

/** Validate a WPA2 passphrase accepted by the configuration portal. */
bool wifi_credentials_is_valid_password(const char *password);

/** Persist a new ComNetAR password and update the in-memory copy. */
esp_err_t wifi_credentials_set_house_password(const char *password);

/** Restore the factory state (ComNetAR without a password). */
esp_err_t wifi_credentials_factory_reset(void);

#ifdef __cplusplus
}
#endif

#endif // WIFI_CREDENTIALS_H
