idf_component_register(
    SRCS "src/portal_settings.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_hw_support mbedtls nvs_flash
)
