#include <string.h>

#include "esp_log.h"
#include "nvs.h"

#include "wifi_credentials/wifi_credentials.h"

#define WIFI_CREDENTIALS_NAMESPACE "comnetar"
#define WIFI_CREDENTIALS_PASSWORD_KEY "ap_pass"
#define WIFI_CREDENTIALS_PASSWORD_MIN_LENGTH 8

static const char *TAG = "wifi_credentials";

static char house_password[WIFI_CREDENTIALS_PASSWORD_MAX_LENGTH + 1] = {0};
static bool initialized = false;

static bool is_printable_ascii(const char *value)
{
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor; cursor++) {
        if (*cursor < 0x20 || *cursor > 0x7e) {
            return false;
        }
    }

    return true;
}

bool wifi_credentials_is_valid_password(const char *password)
{
    if (password == NULL) {
        return false;
    }

    size_t length = strnlen(password, WIFI_CREDENTIALS_PASSWORD_MAX_LENGTH + 1);
    if (length < WIFI_CREDENTIALS_PASSWORD_MIN_LENGTH ||
        length > WIFI_CREDENTIALS_PASSWORD_MAX_LENGTH) {
        return false;
    }

    return is_printable_ascii(password);
}

esp_err_t wifi_credentials_init(void)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(WIFI_CREDENTIALS_NAMESPACE, NVS_READONLY, &handle);

    if (err == ESP_ERR_NVS_NOT_FOUND) {
        house_password[0] = '\0';
        initialized = true;
        ESP_LOGI(TAG, "No saved ComNetAR password; using factory open-network state");
        return ESP_OK;
    }

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to open credential store: %s", esp_err_to_name(err));
        return err;
    }

    char stored_password[sizeof(house_password)] = {0};
    size_t stored_length = sizeof(stored_password);
    err = nvs_get_str(handle, WIFI_CREDENTIALS_PASSWORD_KEY,
                      stored_password, &stored_length);
    nvs_close(handle);

    if (err == ESP_ERR_NVS_NOT_FOUND) {
        house_password[0] = '\0';
        initialized = true;
        ESP_LOGI(TAG, "No saved ComNetAR password; using factory open-network state");
        return ESP_OK;
    }

    if (err != ESP_OK || !wifi_credentials_is_valid_password(stored_password)) {
        const char *reason = err == ESP_OK
            ? "validation failed"
            : esp_err_to_name(err);
        ESP_LOGE(TAG, "Stored ComNetAR password is invalid (%s); restoring factory state",
                 reason);
        house_password[0] = '\0';
        initialized = true;
        return wifi_credentials_factory_reset();
    }

    memcpy(house_password, stored_password, stored_length);
    initialized = true;
    ESP_LOGI(TAG, "Saved ComNetAR password loaded");
    return ESP_OK;
}

const char *wifi_credentials_get_house_password(void)
{
    return house_password;
}

esp_err_t wifi_credentials_set_house_password(const char *password)
{
    if (!initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    if (!wifi_credentials_is_valid_password(password)) {
        return ESP_ERR_INVALID_ARG;
    }

    if (strcmp(house_password, password) == 0) {
        return ESP_OK;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open(WIFI_CREDENTIALS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        return err;
    }

    err = nvs_set_str(handle, WIFI_CREDENTIALS_PASSWORD_KEY, password);
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    nvs_close(handle);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to persist ComNetAR password: %s", esp_err_to_name(err));
        return err;
    }

    size_t password_length = strlen(password);
    memset(house_password, 0, sizeof(house_password));
    memcpy(house_password, password, password_length);
    ESP_LOGI(TAG, "ComNetAR password updated");
    return ESP_OK;
}

esp_err_t wifi_credentials_factory_reset(void)
{
    if (!initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open(WIFI_CREDENTIALS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        return err;
    }

    err = nvs_erase_key(handle, WIFI_CREDENTIALS_PASSWORD_KEY);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        err = ESP_OK;
    } else if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    nvs_close(handle);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to reset ComNetAR credentials: %s", esp_err_to_name(err));
        return err;
    }

    memset(house_password, 0, sizeof(house_password));
    ESP_LOGW(TAG, "ComNetAR credentials restored to factory state");
    return ESP_OK;
}
