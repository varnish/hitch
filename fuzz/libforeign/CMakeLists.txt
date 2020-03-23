
set(PATH ${CMAKE_SOURCE_DIR}/../src/foreign)
set(FOREIGN_SOURCES
	${PATH}/asn_gentm.c
	${PATH}/flopen.c
	${PATH}/vas.c
	${PATH}/vpf.c
	${PATH}/vsa.c
	${PATH}/vsb.c
)

add_library(foreign STATIC ${FOREIGN_SOURCES})
target_include_directories(foreign PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(foreign PRIVATE ${CMAKE_SOURCE_DIR}/include)
# build hitch into the top binary folder
set_target_properties(foreign
	PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)

if (SANITIZE)
    target_compile_options(foreign PUBLIC "${SANITIZE_FLAGS}")
endif()

if (LIBFUZZER)
    if (NOT "${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
        message(FATAL_ERROR "You can only use Clang when libfuzzer is enabled")
    endif()
    target_compile_options(foreign PUBLIC ${FUZZER_CFLAGS})
	target_link_libraries(foreign ${FUZZER_LFLAGS})
endif()

# libfuzzer is a C++ project, so we need the ability to enable libc++ and LLD
if (LIBCPP)
    target_link_libraries(foreign "-stdlib=libc++ -fuse-ld=lld")
endif()
