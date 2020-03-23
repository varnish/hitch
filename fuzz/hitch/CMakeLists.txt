cmake_minimum_required (VERSION 3.0.2)
project (hitch C)
set(PATH ${CMAKE_SOURCE_DIR}/../src)

### cfg_lex ###
add_custom_command(
    COMMAND lex -o cfg_lex.c ${PATH}/cfg_lex.l
    OUTPUT  cfg_lex.c
    DEPENDS ${PATH}/cfg_lex.l
    COMMENT "Generating cfg_lex.c"
)
add_custom_target(cfglex_generate
    DEPENDS cfg_lex.c
)
### cfg_parser ###
add_custom_command(
    COMMAND yacc -d -o cfg_parser.c ${PATH}/cfg_parser.y
    OUTPUT  cfg_parser.c cfg_parser.h
    DEPENDS ${PATH}/cfg_parser.y
    COMMENT "Generating cfg_parser"
)
add_custom_target(cfgparser_generate
    DEPENDS cfg_parser.c cfg_parser.h
)

set(HITCH_SOURCES
	${PATH}/configuration.c
	${PATH}/hitch.c
	${PATH}/hssl_locks.c
	${PATH}/logging.c
	${PATH}/ocsp.c
	${PATH}/ringbuffer.c
	#${PATH}/shctx.c
	cfg_parser.c
	cfg_lex.c
)

add_executable(hitch ${HITCH_SOURCES})
target_include_directories(hitch PRIVATE ${PATH})
target_include_directories(hitch PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(hitch PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(hitch foreign ev pthread crypto ssl)
add_dependencies(hitch cfglex_generate cfgparser_generate)
# build hitch executable into the top binary folder
set_target_properties(hitch
	PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)

if (SANITIZE)
    target_compile_options(hitch PUBLIC "${SANITIZE_FLAGS}")
endif()

if (LIBFUZZER)
    if (NOT "${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
        message(FATAL_ERROR "You can only use Clang when libfuzzer is enabled")
    endif()
    target_compile_options(hitch PUBLIC ${FUZZER_CFLAGS})
	target_link_libraries(hitch ${FUZZER_LFLAGS})
endif()

# libfuzzer is a C++ project, so we need the ability to enable libc++ and LLD
if (LIBCPP)
    target_link_libraries(hitch "-stdlib=libc++ -fuse-ld=lld")
endif()
