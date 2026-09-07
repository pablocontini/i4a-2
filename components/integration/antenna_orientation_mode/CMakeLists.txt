idf_component_register(
    SRCS "src/antenna_orientation_mode.c"
    INCLUDE_DIRS "include"
    REQUIRES node ring_share driver esp_wifi esp_netif lwip
)
