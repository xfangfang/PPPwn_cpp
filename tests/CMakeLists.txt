cmake_minimum_required(VERSION 3.12)

message(STATUS "Building exploit, ${PROJECT_NAME}")

add_library(${PROJECT_NAME}_shared SHARED
        ${CMAKE_SOURCE_DIR}/src/exploit.cpp
        ${CMAKE_SOURCE_DIR}/src/packet.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/extern.cpp)
set_target_properties(${PROJECT_NAME}_shared PROPERTIES OUTPUT_NAME ${PROJECT_NAME})
target_link_libraries(${PROJECT_NAME}_shared PUBLIC ${APP_LINK_LIB})
target_compile_options(${PROJECT_NAME}_shared PUBLIC ${APP_BUILD_OPTIONS})
target_include_directories(${PROJECT_NAME}_shared PUBLIC ${CMAKE_SOURCE_DIR}/include)

add_custom_target(${PROJECT_NAME}_py ALL
        DEPENDS ${PROJECT_NAME}_shared
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/packet_builder_test.py $<TARGET_FILE:${PROJECT_NAME}_shared>)

add_custom_target(${PROJECT_NAME}_pybind ALL
        DEPENDS ${PROJECT_NAME}_shared
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/pppwn.py
                --interface=${IFACE} --fw=${FW} --stage1=${STAGE1} --stage2=${STAGE2}
                --libpppwn=$<TARGET_FILE:${PROJECT_NAME}_shared>)

add_executable(${PROJECT_NAME}_output
        ${CMAKE_CURRENT_SOURCE_DIR}/output.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/extern.cpp)
target_link_libraries(${PROJECT_NAME}_output PUBLIC ${PROJECT_NAME}_static)