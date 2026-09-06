#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "driver/gpio.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "config_portal/config_portal.h"
#include "task_config.h"
#include "wifi_credentials/wifi_credentials.h"

#define BOOT_BUTTON_GPIO GPIO_NUM_0

#define BUTTON_POLL_INTERVAL_MS 50
#define BUTTON_DEBOUNCE_MS 150
#define FACTORY_RESET_HOLD_MS 6000
#define PORTAL_TIMEOUT_MS (5 * 60 * 1000)
#define PASSWORD_APPLY_DELAY_MS 1500

#define FORM_BODY_MAX_LENGTH 511

static const char *TAG = "config_portal";

static httpd_handle_t portal_server = NULL;
static TaskHandle_t button_task_handle = NULL;
static int64_t portal_started_at_us = 0;
static volatile bool password_apply_pending = false;
static config_portal_apply_password_cb_t apply_password_callback = NULL;
static void *apply_password_context = NULL;

static const char PORTAL_HTML[] =
    "<!doctype html>"
    "<html lang=\"es\"><head><meta charset=\"utf-8\">"
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
    "<title>ComNetAR - Configuracion</title>"
    "<style>"
    ":root{color-scheme:light;font-family:system-ui,-apple-system,sans-serif}"
    "body{margin:0;background:#eef3f8;color:#17212b;min-height:100vh;display:grid;place-items:center}"
    "main{width:min(92vw,430px);background:#fff;padding:28px;border-radius:18px;box-shadow:0 14px 40px #17324d24}"
    "h1{margin:0 0 8px;color:#075985;font-size:1.75rem}"
    "p{line-height:1.45;color:#475569}label{display:block;margin-top:18px;font-weight:650}"
    "input{box-sizing:border-box;width:100%;margin-top:7px;padding:12px;border:1px solid #94a3b8;border-radius:9px;font-size:1rem}"
    "button{width:100%;margin-top:24px;padding:13px;border:0;border-radius:9px;background:#0369a1;color:#fff;font-weight:700;font-size:1rem}"
    "button.danger{background:#b91c1c}hr{border:0;border-top:1px solid #cbd5e1;margin:28px 0 0}h2{font-size:1.2rem;margin:22px 0 0}"
    "small{display:block;margin-top:18px;color:#64748b}.check{display:flex;gap:8px;align-items:center;font-weight:400}.check input{width:auto;margin:0}"
    "</style></head><body><main>"
    "<h1>Red ComNetAR</h1>"
    "<p>Ingrese una nueva contrasena para la red. Al guardar, el punto de acceso se actualizara y los dispositivos conectados deberan usar la clave nueva.</p>"
    "<form method=\"post\" action=\"/save\">"
    "<label for=\"password\">Nueva contrasena</label>"
    "<input id=\"password\" name=\"password\" type=\"password\" minlength=\"8\" maxlength=\"63\" required autocomplete=\"new-password\">"
    "<label for=\"confirm\">Confirmar contrasena</label>"
    "<input id=\"confirm\" name=\"confirm\" type=\"password\" minlength=\"8\" maxlength=\"63\" required autocomplete=\"new-password\">"
    "<label class=\"check\"><input id=\"show\" type=\"checkbox\">Mostrar contrasena</label>"
    "<button type=\"submit\">Guardar y aplicar</button>"
    "</form>"
    "<hr><h2>Restablecer configuracion</h2>"
    "<p>Elimina la contrasena guardada y deja ComNetAR como una red abierta.</p>"
    "<form method=\"post\" action=\"/factory-reset\" onsubmit=\"return confirm('Confirma el restablecimiento de fabrica?')\">"
    "<input type=\"hidden\" name=\"confirm_reset\" value=\"yes\">"
    "<button class=\"danger\" type=\"submit\">Restablecer de fabrica</button>"
    "</form>"
    "<small>El portal se cierra automaticamente despues de cinco minutos. Tambien puede restaurar la red manteniendo BOOT presionado durante seis segundos.</small>"
    "<script>document.getElementById('show').onchange=e=>{const t=e.target.checked?'text':'password';document.getElementById('password').type=t;document.getElementById('confirm').type=t}</script>"
    "</main></body></html>";

static const char SUCCESS_HTML[] =
    "<!doctype html><html lang=\"es\"><head><meta charset=\"utf-8\">"
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
    "<title>ComNetAR</title><style>body{font-family:system-ui;background:#eef3f8;color:#17212b;display:grid;place-items:center;min-height:100vh;margin:0}"
    "main{width:min(88vw,420px);background:white;padding:28px;border-radius:18px;box-shadow:0 14px 40px #17324d24}h1{color:#166534}</style>"
    "</head><body><main><h1>Contrasena guardada</h1>"
    "<p>El punto de acceso se actualizara. Vuelva a conectarse a ComNetAR usando la nueva contrasena.</p>"
    "</main></body></html>";

static const char FACTORY_RESET_SUCCESS_HTML[] =
    "<!doctype html><html lang=\"es\"><head><meta charset=\"utf-8\">"
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
    "<title>ComNetAR</title><style>body{font-family:system-ui;background:#eef3f8;color:#17212b;display:grid;place-items:center;min-height:100vh;margin:0}"
    "main{width:min(88vw,420px);background:white;padding:28px;border-radius:18px;box-shadow:0 14px 40px #17324d24}h1{color:#166534}</style>"
    "</head><body><main><h1>Configuracion restaurada</h1>"
    "<p>ComNetAR se actualizara como red abierta. Vuelva a conectarse sin contrasena.</p>"
    "</main></body></html>";

static esp_err_t send_html(httpd_req_t *request, const char *status, const char *html)
{
    httpd_resp_set_status(request, status);
    httpd_resp_set_type(request, "text/html; charset=utf-8");
    httpd_resp_set_hdr(request, "Cache-Control", "no-store");
    return httpd_resp_send(request, html, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t send_error_page(httpd_req_t *request, const char *status,
                                 const char *message)
{
    char response[640];
    int length = snprintf(
        response, sizeof(response),
        "<!doctype html><html lang=\"es\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>ComNetAR</title></head><body style=\"font-family:system-ui;margin:2rem\">"
        "<h1>No se pudo completar</h1><p>%s</p><p><a href=\"/\">Volver</a></p>"
        "</body></html>", message);

    if (length < 0 || length >= sizeof(response)) {
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "Unable to build response");
    }

    return send_html(request, status, response);
}

static int hex_value(char value)
{
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

static bool url_decode(const char *input, size_t input_length,
                       char *output, size_t output_size)
{
    size_t output_length = 0;

    for (size_t i = 0; i < input_length; i++) {
        unsigned char decoded;

        if (input[i] == '+') {
            decoded = ' ';
        } else if (input[i] == '%') {
            if (i + 2 >= input_length) {
                return false;
            }

            int high = hex_value(input[i + 1]);
            int low = hex_value(input[i + 2]);
            if (high < 0 || low < 0) {
                return false;
            }

            decoded = (unsigned char)((high << 4) | low);
            i += 2;
        } else {
            decoded = (unsigned char)input[i];
        }

        if (decoded == '\0' || output_length + 1 >= output_size) {
            return false;
        }

        output[output_length++] = (char)decoded;
    }

    output[output_length] = '\0';
    return true;
}

static bool form_get_value(const char *body, const char *field_name,
                           char *output, size_t output_size)
{
    size_t field_name_length = strlen(field_name);
    const char *field = body;

    while (*field != '\0') {
        const char *separator = strchr(field, '&');
        size_t pair_length = separator == NULL
            ? strlen(field)
            : (size_t)(separator - field);
        const char *equals = memchr(field, '=', pair_length);

        if (equals != NULL &&
            (size_t)(equals - field) == field_name_length &&
            memcmp(field, field_name, field_name_length) == 0) {
            const char *encoded_value = equals + 1;
            size_t encoded_length = pair_length - (size_t)(encoded_value - field);
            return url_decode(encoded_value, encoded_length, output, output_size);
        }

        if (separator == NULL) {
            break;
        }
        field = separator + 1;
    }

    return false;
}

static esp_err_t portal_get_handler(httpd_req_t *request)
{
    return send_html(request, "200 OK", PORTAL_HTML);
}

static void delayed_password_apply_task(void *argument)
{
    (void)argument;
    vTaskDelay(pdMS_TO_TICKS(PASSWORD_APPLY_DELAY_MS));

    esp_err_t err = apply_password_callback(
        wifi_credentials_get_house_password(), apply_password_context);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to apply saved password to AP: %s",
                 esp_err_to_name(err));
    } else {
        ESP_LOGI(TAG, "Saved password applied to running AP");
    }

    password_apply_pending = false;
    vTaskDelete(NULL);
}

static esp_err_t schedule_password_apply(void)
{
    if (password_apply_pending) {
        return ESP_ERR_INVALID_STATE;
    }

    password_apply_pending = true;
    BaseType_t task_created = xTaskCreate(
        delayed_password_apply_task,
        "portal_apply",
        TASK_CONFIG_PORTAL_APPLY_STACK,
        NULL,
        TASK_CONFIG_PORTAL_PRIORITY,
        NULL
    );

    if (task_created != pdPASS) {
        password_apply_pending = false;
        ESP_LOGE(TAG, "Unable to create delayed password apply task");
        return ESP_ERR_NO_MEM;
    }

    return ESP_OK;
}

static esp_err_t portal_save_handler(httpd_req_t *request)
{
    if (password_apply_pending) {
        return send_error_page(request, "409 Conflict",
                               "Ya hay un cambio de contrasena en curso.");
    }

    if (request->content_len <= 0 || request->content_len > FORM_BODY_MAX_LENGTH) {
        return send_error_page(request, "400 Bad Request",
                               "El formulario recibido tiene un tamano invalido.");
    }

    char body[FORM_BODY_MAX_LENGTH + 1];
    size_t total_received = 0;

    while (total_received < request->content_len) {
        int received = httpd_req_recv(request, body + total_received,
                                      request->content_len - total_received);
        if (received == HTTPD_SOCK_ERR_TIMEOUT) {
            continue;
        }
        if (received <= 0) {
            return ESP_FAIL;
        }
        total_received += (size_t)received;
    }
    body[total_received] = '\0';

    char password[WIFI_CREDENTIALS_PASSWORD_MAX_LENGTH + 1] = {0};
    char confirmation[WIFI_CREDENTIALS_PASSWORD_MAX_LENGTH + 1] = {0};

    if (!form_get_value(body, "password", password, sizeof(password)) ||
        !form_get_value(body, "confirm", confirmation, sizeof(confirmation))) {
        return send_error_page(request, "400 Bad Request",
                               "No se recibieron ambas contrasenas o contienen una codificacion invalida.");
    }

    if (strcmp(password, confirmation) != 0) {
        return send_error_page(request, "400 Bad Request",
                               "Las contrasenas no coinciden.");
    }

    if (!wifi_credentials_is_valid_password(password)) {
        return send_error_page(request, "400 Bad Request",
                               "La contrasena debe tener entre 8 y 63 caracteres ASCII imprimibles.");
    }

    esp_err_t err = wifi_credentials_set_house_password(password);
    memset(password, 0, sizeof(password));
    memset(confirmation, 0, sizeof(confirmation));
    memset(body, 0, sizeof(body));

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Password update failed: %s", esp_err_to_name(err));
        return send_error_page(request, "500 Internal Server Error",
                               "La memoria no volatil rechazo el cambio. La clave anterior sigue activa.");
    }

    err = schedule_password_apply();
    if (err != ESP_OK) {
        return send_error_page(request, "500 Internal Server Error",
                               "La clave fue guardada, pero no se pudo aplicar al punto de acceso. Reinicie el nodo manualmente.");
    }

    ESP_LOGI(TAG, "Password saved; AP update scheduled");
    return send_html(request, "200 OK", SUCCESS_HTML);
}

static esp_err_t portal_factory_reset_handler(httpd_req_t *request)
{
    if (password_apply_pending) {
        return send_error_page(request, "409 Conflict",
                               "Ya hay un cambio de contrasena en curso.");
    }

    if (request->content_len <= 0 || request->content_len > FORM_BODY_MAX_LENGTH) {
        return send_error_page(request, "400 Bad Request",
                               "No se recibio la confirmacion del restablecimiento.");
    }

    char body[FORM_BODY_MAX_LENGTH + 1];
    size_t total_received = 0;

    while (total_received < request->content_len) {
        int received = httpd_req_recv(request, body + total_received,
                                      request->content_len - total_received);
        if (received == HTTPD_SOCK_ERR_TIMEOUT) {
            continue;
        }
        if (received <= 0) {
            return ESP_FAIL;
        }
        total_received += (size_t)received;
    }
    body[total_received] = '\0';

    char confirmation[4] = {0};
    bool confirmed = form_get_value(body, "confirm_reset", confirmation,
                                    sizeof(confirmation)) &&
                     strcmp(confirmation, "yes") == 0;
    memset(body, 0, sizeof(body));

    if (!confirmed) {
        return send_error_page(request, "400 Bad Request",
                               "La confirmacion del restablecimiento no es valida.");
    }

    esp_err_t err = wifi_credentials_factory_reset();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Portal factory reset failed: %s", esp_err_to_name(err));
        return send_error_page(request, "500 Internal Server Error",
                               "La memoria no volatil rechazo el restablecimiento.");
    }

    err = schedule_password_apply();
    if (err != ESP_OK) {
        return send_error_page(request, "500 Internal Server Error",
                               "La configuracion fue borrada, pero no se pudo actualizar el punto de acceso. Reinicie el nodo manualmente.");
    }

    ESP_LOGW(TAG, "Factory reset requested from portal; AP update scheduled");
    return send_html(request, "200 OK", FACTORY_RESET_SUCCESS_HTML);
}

static esp_err_t config_portal_start(void)
{
    if (portal_server != NULL) {
        portal_started_at_us = esp_timer_get_time();
        ESP_LOGI(TAG, "Configuration portal activation extended");
        return ESP_OK;
    }

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = 80;
    config.max_uri_handlers = 3;

    esp_err_t err = httpd_start(&portal_server, &config);
    if (err != ESP_OK) {
        portal_server = NULL;
        ESP_LOGE(TAG, "Unable to start configuration portal: %s", esp_err_to_name(err));
        return err;
    }

    const httpd_uri_t root_uri = {
        .uri = "/",
        .method = HTTP_GET,
        .handler = portal_get_handler,
        .user_ctx = NULL,
    };
    const httpd_uri_t save_uri = {
        .uri = "/save",
        .method = HTTP_POST,
        .handler = portal_save_handler,
        .user_ctx = NULL,
    };
    const httpd_uri_t factory_reset_uri = {
        .uri = "/factory-reset",
        .method = HTTP_POST,
        .handler = portal_factory_reset_handler,
        .user_ctx = NULL,
    };

    err = httpd_register_uri_handler(portal_server, &root_uri);
    if (err == ESP_OK) {
        err = httpd_register_uri_handler(portal_server, &save_uri);
    }
    if (err == ESP_OK) {
        err = httpd_register_uri_handler(portal_server, &factory_reset_uri);
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to register portal handlers: %s", esp_err_to_name(err));
        httpd_stop(portal_server);
        portal_server = NULL;
        return err;
    }

    portal_started_at_us = esp_timer_get_time();

    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    esp_netif_ip_info_t ip_info;
    if (netif != NULL && esp_netif_get_ip_info(netif, &ip_info) == ESP_OK) {
        ESP_LOGW(TAG, "Configuration portal enabled for five minutes at http://" IPSTR "/",
                 IP2STR(&ip_info.ip));
    } else {
        ESP_LOGW(TAG, "Configuration portal enabled for five minutes on HTTP port 80");
    }

    return ESP_OK;
}

static void config_portal_stop(void)
{
    if (portal_server == NULL) {
        return;
    }

    httpd_stop(portal_server);
    portal_server = NULL;
    portal_started_at_us = 0;
    ESP_LOGI(TAG, "Configuration portal disabled");
}

static void restore_factory_credentials(void)
{
    config_portal_stop();

    esp_err_t err = wifi_credentials_factory_reset();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Factory reset failed: %s", esp_err_to_name(err));
        return;
    }

    err = apply_password_callback("", apply_password_context);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Factory credentials saved but AP update failed: %s",
                 esp_err_to_name(err));
        return;
    }

    ESP_LOGW(TAG, "Factory reset complete; ComNetAR network is now open");
}

static void boot_button_task(void *argument)
{
    (void)argument;

    bool raw_pressed = gpio_get_level(BOOT_BUTTON_GPIO) == 0;
    bool stable_pressed = false;
    bool press_active = false;
    bool factory_reset_handled = false;
    int64_t raw_changed_at_us = esp_timer_get_time();
    int64_t pressed_at_us = 0;

    while (true) {
        int64_t now_us = esp_timer_get_time();
        bool sampled_pressed = gpio_get_level(BOOT_BUTTON_GPIO) == 0;

        if (portal_server != NULL && !password_apply_pending &&
            now_us - portal_started_at_us >= (int64_t)PORTAL_TIMEOUT_MS * 1000) {
            config_portal_stop();
        }

        if (sampled_pressed != raw_pressed) {
            raw_pressed = sampled_pressed;
            raw_changed_at_us = now_us;
        }

        if (raw_pressed != stable_pressed &&
            now_us - raw_changed_at_us >= (int64_t)BUTTON_DEBOUNCE_MS * 1000) {
            stable_pressed = raw_pressed;

            if (stable_pressed) {
                press_active = true;
                factory_reset_handled = false;
                pressed_at_us = now_us;
            } else if (press_active) {
                if (!factory_reset_handled) {
                    ESP_LOGI(TAG, "Short BOOT press detected; opening portal");
                    config_portal_start();
                }

                press_active = false;
                factory_reset_handled = false;
                pressed_at_us = 0;
            }
        }

        if (stable_pressed && press_active && !factory_reset_handled &&
            now_us - pressed_at_us >= (int64_t)FACTORY_RESET_HOLD_MS * 1000) {
            factory_reset_handled = true;
            ESP_LOGW(TAG, "BOOT held for six seconds; performing factory reset");
            restore_factory_credentials();
        }

        vTaskDelay(pdMS_TO_TICKS(BUTTON_POLL_INTERVAL_MS));
    }
}

esp_err_t config_portal_init(config_portal_apply_password_cb_t apply_password,
                             void *context)
{
    if (apply_password == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (button_task_handle != NULL) {
        return ESP_OK;
    }

    apply_password_callback = apply_password;
    apply_password_context = context;

    gpio_config_t button_config = {
        .pin_bit_mask = 1ULL << BOOT_BUTTON_GPIO,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    esp_err_t err = gpio_config(&button_config);
    if (err != ESP_OK) {
        return err;
    }

    BaseType_t task_created = xTaskCreatePinnedToCore(
        boot_button_task,
        "boot_button",
        TASK_CONFIG_PORTAL_STACK,
        NULL,
        TASK_CONFIG_PORTAL_PRIORITY,
        &button_task_handle,
        TASK_CONFIG_PORTAL_CORE
    );
    if (task_created != pdPASS) {
        button_task_handle = NULL;
        gpio_reset_pin(BOOT_BUTTON_GPIO);
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "BOOT button monitor initialized");
    return ESP_OK;
}
