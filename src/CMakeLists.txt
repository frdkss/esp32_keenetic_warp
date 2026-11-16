idf_component_register(
    SRCS main.cpp build_contract.cpp board_profile.cpp network.cpp keenetic.cpp
         monitor.cpp scheduler.cpp status.cpp display.cpp network_protocol.cpp network_esp.cpp runtime_config.cpp
         keenetic_protocol.cpp keenetic_settings.cpp recovery_store.cpp schedule_store.cpp update_probe.cpp config_tag.cpp
    INCLUDE_DIRS ../include
    REQUIRES framework-arduinoespressif32 esp_wifi esp_netif esp_event nvs_flash mbedtls esp-tls app_update
)
set_target_properties(${COMPONENT_LIB} PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS YES)
