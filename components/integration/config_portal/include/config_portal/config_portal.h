#ifndef CONFIG_PORTAL_H
#define CONFIG_PORTAL_H

#include <stdbool.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CONFIG_PORTAL_BOOT_MODE_NORMAL = 0,
    CONFIG_PORTAL_BOOT_MODE_CONFIGURATION,
    CONFIG_PORTAL_BOOT_MODE_ORIENTATION,
} config_portal_boot_mode_t;

/**
 * Consume the one-shot mode request left in RTC memory before a coordinated
 * restart. This is called only by the central module during startup.
 */
config_portal_boot_mode_t config_portal_take_boot_mode_request(void);

/** Monitor BOOT during normal operation and restart into configuration mode. */
esp_err_t config_portal_start_button_monitor(void);

/** Start the dedicated configuration AP and web portal for five minutes. */
esp_err_t config_portal_run(void);

#ifdef __cplusplus
}
#endif

#endif // CONFIG_PORTAL_H
