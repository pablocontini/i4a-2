idf_component_register(
    SRCS "src/config_portal.c"
    INCLUDE_DIRS "include"
    REQUIRES driver esp_http_server esp_hw_support esp_netif esp_timer
             portal_settings wifi_credentials task_config
)
