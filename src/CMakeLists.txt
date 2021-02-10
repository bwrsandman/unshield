LIST(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${CMAKE_INSTALL_PREFIX}/lib" isSystemDir)
IF("${isSystemDir}" STREQUAL "-1")
SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
endif()

add_executable(unshield "unshield.c")
target_link_libraries(unshield libunshield)
if(WIN32)
    if(HAVE_ICONV)
        target_link_libraries(unshield iconv)
    endif()
    target_link_libraries(unshield ${ZLIB_LIBRARIES})
endif()

add_executable(unshield-deobfuscate "unshield-deobfuscate.c")
target_link_libraries(unshield-deobfuscate libunshield)
if(WIN32)
    target_link_libraries(unshield-deobfuscate ${ZLIB_LIBRARIES})
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(cdio REQUIRED IMPORTED_TARGET libcdio)
pkg_check_modules(iso9660 REQUIRED IMPORTED_TARGET libiso9660)

add_executable(isocab isocab.c)
target_link_libraries(isocab PRIVATE PkgConfig::cdio PkgConfig::iso9660 libunshield)

if(BUILD_STATIC AND MSVC)
    set_msvc_runtime_static()
endif()

install(TARGETS unshield RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
