idf_component_register(
    SRCS "src/reset_manager.c"
    INCLUDE_DIRS "include"
    REQUIRES config nvs_flash ring_share
)
