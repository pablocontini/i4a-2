#include <stddef.h>
#include <string.h>

#include "esp_log.h"
#include "esp_random.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"
#include "nvs.h"

#include "portal_settings/portal_settings.h"

#define PORTAL_SETTINGS_NAMESPACE "portal_admin"
#define ADMIN_PASSWORD_SALT_KEY "pwd_salt"
#define ADMIN_PASSWORD_HASH_KEY "pwd_hash"
#define ADMIN_PASSWORD_CHANGED_KEY "pwd_custom"
#define ANTENNA_POWER_KEY "ant_power"
#define ANTENNA_RSSI_KEY "ant_rssi"

#define ADMIN_PASSWORD_INITIAL "i4a12345"
#define ADMIN_PASSWORD_SALT_LENGTH 16
#define ADMIN_PASSWORD_HASH_LENGTH 32
#define ADMIN_PASSWORD_PBKDF2_ITERATIONS 10000

static const char *TAG = "portal_settings";

static uint8_t admin_password_salt[ADMIN_PASSWORD_SALT_LENGTH];
static uint8_t admin_password_hash[ADMIN_PASSWORD_HASH_LENGTH];
static portal_antenna_power_config_t antenna_powers;
static portal_antenna_rssi_config_t antenna_rssi_thresholds;
static bool admin_password_changed = false;
static bool initialized = false;

static void secure_zero(void *buffer, size_t length)
{
    volatile uint8_t *cursor = (volatile uint8_t *)buffer;
    while (length-- > 0) {
        *cursor++ = 0;
    }
}

static bool is_printable_ascii(const char *value)
{
    for (const unsigned char *cursor = (const unsigned char *)value;
         *cursor != '\0'; cursor++) {
        if (*cursor < 0x20 || *cursor > 0x7e) {
            return false;
        }
    }

    return true;
}

bool portal_settings_is_valid_admin_password(const char *password)
{
    if (password == NULL) {
        return false;
    }

    size_t length = strnlen(
        password, PORTAL_SETTINGS_ADMIN_PASSWORD_MAX_LENGTH + 1);
    if (length < PORTAL_SETTINGS_ADMIN_PASSWORD_MIN_LENGTH ||
        length > PORTAL_SETTINGS_ADMIN_PASSWORD_MAX_LENGTH) {
        return false;
    }

    return is_printable_ascii(password);
}

static esp_err_t derive_password_hash(
    const char *password,
    const uint8_t salt[ADMIN_PASSWORD_SALT_LENGTH],
    uint8_t output[ADMIN_PASSWORD_HASH_LENGTH])
{
    int result = mbedtls_pkcs5_pbkdf2_hmac_ext(
        MBEDTLS_MD_SHA256,
        (const unsigned char *)password,
        strlen(password),
        salt,
        ADMIN_PASSWORD_SALT_LENGTH,
        ADMIN_PASSWORD_PBKDF2_ITERATIONS,
        ADMIN_PASSWORD_HASH_LENGTH,
        output);

    if (result != 0) {
        ESP_LOGE(TAG, "Unable to derive administrator verifier: -0x%04x",
                 (unsigned int)-result);
        return ESP_FAIL;
    }

    return ESP_OK;
}

static bool constant_time_equal(const uint8_t *left, const uint8_t *right,
                                size_t length)
{
    uint8_t difference = 0;
    for (size_t index = 0; index < length; index++) {
        difference |= left[index] ^ right[index];
    }
    return difference == 0;
}

static bool load_exact_blob(nvs_handle_t handle, const char *key, void *output,
                            size_t expected_length, bool *found)
{
    size_t stored_length = 0;
    esp_err_t err = nvs_get_blob(handle, key, NULL, &stored_length);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        *found = false;
        return true;
    }
    if (err != ESP_OK || stored_length != expected_length) {
        ESP_LOGE(TAG, "Invalid NVS value for %s", key);
        return false;
    }

    err = nvs_get_blob(handle, key, output, &stored_length);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to read NVS value %s: %s", key,
                 esp_err_to_name(err));
        return false;
    }

    *found = true;
    return true;
}

static esp_err_t initialize_admin_password(nvs_handle_t handle)
{
    uint8_t new_salt[ADMIN_PASSWORD_SALT_LENGTH];
    uint8_t new_hash[ADMIN_PASSWORD_HASH_LENGTH];
    esp_fill_random(new_salt, sizeof(new_salt));

    esp_err_t err = derive_password_hash(ADMIN_PASSWORD_INITIAL, new_salt,
                                         new_hash);
    if (err == ESP_OK) {
        err = nvs_set_blob(handle, ADMIN_PASSWORD_SALT_KEY, new_salt,
                           sizeof(new_salt));
    }
    if (err == ESP_OK) {
        err = nvs_set_blob(handle, ADMIN_PASSWORD_HASH_KEY, new_hash,
                           sizeof(new_hash));
    }
    if (err == ESP_OK) {
        err = nvs_set_u8(handle, ADMIN_PASSWORD_CHANGED_KEY, 0);
    }

    if (err == ESP_OK) {
        memcpy(admin_password_salt, new_salt, sizeof(new_salt));
        memcpy(admin_password_hash, new_hash, sizeof(new_hash));
        admin_password_changed = false;
    }

    secure_zero(new_salt, sizeof(new_salt));
    secure_zero(new_hash, sizeof(new_hash));
    return err;
}

bool portal_settings_is_valid_power_qdbm(uint8_t quarter_dbm)
{
    static const uint8_t supported_levels[] = {
        8, 20, 28, 34, 44, 52, 56, 60, 66, 72, 80,
    };

    for (size_t index = 0;
         index < sizeof(supported_levels) / sizeof(supported_levels[0]);
         index++) {
        if (quarter_dbm == supported_levels[index]) {
            return true;
        }
    }

    return false;
}

static bool antenna_powers_are_valid(
    const portal_antenna_power_config_t *config)
{
    if (config == NULL) {
        return false;
    }

    for (size_t index = 0; index < PORTAL_SETTINGS_ANTENNA_COUNT; index++) {
        if (!portal_settings_is_valid_power_qdbm(config->quarter_dbm[index])) {
            return false;
        }
    }

    return true;
}

static void set_default_antenna_powers(void)
{
    for (size_t index = 0; index < PORTAL_SETTINGS_ANTENNA_COUNT; index++) {
        antenna_powers.quarter_dbm[index] =
            PORTAL_SETTINGS_DEFAULT_POWER_QDBM;
    }
}

bool portal_settings_is_valid_rssi_threshold(int rssi_dbm)
{
    return rssi_dbm >= INT8_MIN && rssi_dbm <= -1;
}

static bool antenna_rssi_thresholds_are_valid(
    const portal_antenna_rssi_config_t *config)
{
    if (config == NULL) {
        return false;
    }

    for (size_t index = 0; index < PORTAL_SETTINGS_ANTENNA_COUNT; index++) {
        if (!portal_settings_is_valid_rssi_threshold(config->dbm[index])) {
            return false;
        }
    }

    return true;
}

static void set_default_antenna_rssi_thresholds(void)
{
    for (size_t index = 0; index < PORTAL_SETTINGS_ANTENNA_COUNT; index++) {
        antenna_rssi_thresholds.dbm[index] =
            PORTAL_SETTINGS_DEFAULT_RSSI_THRESHOLD_DBM;
    }
}

esp_err_t portal_settings_init(void)
{
    if (initialized) {
        return ESP_OK;
    }

    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open(PORTAL_SETTINGS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to open portal settings: %s",
                 esp_err_to_name(err));
        return err;
    }

    bool salt_found = false;
    bool hash_found = false;
    bool needs_commit = false;

    bool salt_valid = load_exact_blob(
        handle, ADMIN_PASSWORD_SALT_KEY, admin_password_salt,
        sizeof(admin_password_salt), &salt_found);
    bool hash_valid = load_exact_blob(
        handle, ADMIN_PASSWORD_HASH_KEY, admin_password_hash,
        sizeof(admin_password_hash), &hash_found);

    if (!salt_valid || !hash_valid || !salt_found || !hash_found) {
        ESP_LOGW(TAG, "Administrator password is not initialized; installing initial verifier");
        err = initialize_admin_password(handle);
        needs_commit = err == ESP_OK;
    } else {
        uint8_t changed = 0;
        err = nvs_get_u8(handle, ADMIN_PASSWORD_CHANGED_KEY, &changed);
        if (err == ESP_ERR_NVS_NOT_FOUND) {
            admin_password_changed = false;
            err = nvs_set_u8(handle, ADMIN_PASSWORD_CHANGED_KEY, 0);
            needs_commit = err == ESP_OK;
        } else if (err == ESP_OK) {
            admin_password_changed = changed != 0;
        }
    }

    if (err == ESP_OK) {
        bool powers_found = false;
        bool powers_valid = load_exact_blob(
            handle, ANTENNA_POWER_KEY, &antenna_powers,
            sizeof(antenna_powers), &powers_found);
        if (!powers_valid || !powers_found ||
            !antenna_powers_are_valid(&antenna_powers)) {
            ESP_LOGW(TAG, "Antenna powers are not initialized; using 20 dBm");
            set_default_antenna_powers();
            err = nvs_set_blob(handle, ANTENNA_POWER_KEY, &antenna_powers,
                               sizeof(antenna_powers));
            needs_commit = err == ESP_OK;
        }
    }

    if (err == ESP_OK) {
        bool thresholds_found = false;
        bool thresholds_valid = load_exact_blob(
            handle, ANTENNA_RSSI_KEY, &antenna_rssi_thresholds,
            sizeof(antenna_rssi_thresholds), &thresholds_found);
        if (!thresholds_valid || !thresholds_found ||
            !antenna_rssi_thresholds_are_valid(&antenna_rssi_thresholds)) {
            ESP_LOGW(TAG,
                     "Antenna RSSI thresholds are not initialized; accepting all signals");
            set_default_antenna_rssi_thresholds();
            err = nvs_set_blob(handle, ANTENNA_RSSI_KEY,
                               &antenna_rssi_thresholds,
                               sizeof(antenna_rssi_thresholds));
            needs_commit = err == ESP_OK;
        }
    }

    if (err == ESP_OK && needs_commit) {
        err = nvs_commit(handle);
    }
    nvs_close(handle);

    if (err != ESP_OK) {
        secure_zero(admin_password_salt, sizeof(admin_password_salt));
        secure_zero(admin_password_hash, sizeof(admin_password_hash));
        ESP_LOGE(TAG, "Unable to initialize portal settings: %s",
                 esp_err_to_name(err));
        return err;
    }

    initialized = true;
    ESP_LOGI(TAG, "Administrator verifier and antenna settings loaded");
    return ESP_OK;
}

bool portal_settings_verify_admin_password(const char *password)
{
    if (!initialized ||
        !portal_settings_is_valid_admin_password(password)) {
        return false;
    }

    uint8_t candidate_hash[ADMIN_PASSWORD_HASH_LENGTH];
    esp_err_t err = derive_password_hash(password, admin_password_salt,
                                         candidate_hash);
    bool matches = err == ESP_OK && constant_time_equal(
        candidate_hash, admin_password_hash, sizeof(candidate_hash));
    secure_zero(candidate_hash, sizeof(candidate_hash));
    return matches;
}

esp_err_t portal_settings_set_admin_password(const char *password)
{
    if (!initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!portal_settings_is_valid_admin_password(password)) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t new_salt[ADMIN_PASSWORD_SALT_LENGTH];
    uint8_t new_hash[ADMIN_PASSWORD_HASH_LENGTH];
    esp_fill_random(new_salt, sizeof(new_salt));

    esp_err_t err = derive_password_hash(password, new_salt, new_hash);
    if (err != ESP_OK) {
        secure_zero(new_salt, sizeof(new_salt));
        secure_zero(new_hash, sizeof(new_hash));
        return err;
    }

    nvs_handle_t handle = 0;
    err = nvs_open(PORTAL_SETTINGS_NAMESPACE, NVS_READWRITE, &handle);
    if (err == ESP_OK) {
        err = nvs_set_blob(handle, ADMIN_PASSWORD_SALT_KEY, new_salt,
                           sizeof(new_salt));
    }
    if (err == ESP_OK) {
        err = nvs_set_blob(handle, ADMIN_PASSWORD_HASH_KEY, new_hash,
                           sizeof(new_hash));
    }
    if (err == ESP_OK) {
        err = nvs_set_u8(handle, ADMIN_PASSWORD_CHANGED_KEY, 1);
    }
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    if (err == ESP_OK) {
        memcpy(admin_password_salt, new_salt, sizeof(new_salt));
        memcpy(admin_password_hash, new_hash, sizeof(new_hash));
        admin_password_changed = true;
        ESP_LOGI(TAG, "Administrator password verifier updated");
    } else {
        ESP_LOGE(TAG, "Unable to persist administrator password: %s",
                 esp_err_to_name(err));
    }

    if (handle != 0) {
        nvs_close(handle);
    }
    secure_zero(new_salt, sizeof(new_salt));
    secure_zero(new_hash, sizeof(new_hash));
    return err;
}

bool portal_settings_is_using_initial_password(void)
{
    return initialized && !admin_password_changed;
}

portal_antenna_power_config_t portal_settings_get_antenna_powers(void)
{
    return antenna_powers;
}

esp_err_t portal_settings_set_antenna_powers(
    const portal_antenna_power_config_t *config)
{
    if (!initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!antenna_powers_are_valid(config)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (memcmp(&antenna_powers, config, sizeof(*config)) == 0) {
        return ESP_OK;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open(PORTAL_SETTINGS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        return err;
    }

    err = nvs_set_blob(handle, ANTENNA_POWER_KEY, config, sizeof(*config));
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    nvs_close(handle);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to persist antenna powers: %s",
                 esp_err_to_name(err));
        return err;
    }

    memcpy(&antenna_powers, config, sizeof(antenna_powers));
    ESP_LOGI(TAG, "Directional antenna powers updated in NVS");
    return ESP_OK;
}

portal_antenna_rssi_config_t portal_settings_get_antenna_rssi_thresholds(void)
{
    return antenna_rssi_thresholds;
}

esp_err_t portal_settings_set_antenna_rssi_thresholds(
    const portal_antenna_rssi_config_t *config)
{
    if (!initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!antenna_rssi_thresholds_are_valid(config)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (memcmp(&antenna_rssi_thresholds, config, sizeof(*config)) == 0) {
        return ESP_OK;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open(PORTAL_SETTINGS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        return err;
    }

    err = nvs_set_blob(handle, ANTENNA_RSSI_KEY, config, sizeof(*config));
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    nvs_close(handle);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to persist antenna RSSI thresholds: %s",
                 esp_err_to_name(err));
        return err;
    }

    memcpy(&antenna_rssi_thresholds, config,
           sizeof(antenna_rssi_thresholds));
    ESP_LOGI(TAG, "Directional antenna RSSI thresholds updated in NVS");
    return ESP_OK;
}
