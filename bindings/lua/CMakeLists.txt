# libtuntap lua binding CMakeLists.txt
# =======================================

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR})

find_package(LuaJit COMPONENTS Development)
add_library(ltuntap MODULE ltuntap.c)

target_include_directories(ltuntap PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(ltuntap PUBLIC tuntap)
if(LUAJIT_FOUND)
    include_directories(${LUAJIT_INCLUDE_DIR})
    target_link_libraries(ltuntap PRIVATE ${LUAJIT_LIBRARIES})
else(LUAJIT_FOUND)
    find_package(Lua REQUIRED COMPONENTS Development)
    include_directories(${LUA_INCLUDE_DIR})
    target_link_libraries(ltuntap PRIVATE ${LUA_LIBRARIES})
endif(LUAJIT_FOUND)

set_target_properties(ltuntap PROPERTIES
    PREFIX "")

install(TARGETS ltuntap
    LIBRARY DESTINATION lib/lua/)

