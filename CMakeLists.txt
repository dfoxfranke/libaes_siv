cmake_minimum_required (VERSION 3.1)
project(libaes_siv LANGUAGES C)
set(CMAKE_C_STANDARD 99)
if("${CMAKE_BUILD_TYPE}" STREQUAL "")
set(CMAKE_BUILD_TYPE Release)
endif("${CMAKE_BUILD_TYPE}" STREQUAL "")

include(GNUInstallDirs)

# Warning: don't use the UB sanitizer in production builds. It can introduce timing side-channels
# into otherwise constant-time code.
if("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
set(CMAKE_C_FLAGS_DEBUG "-Wall -Wextra -Wstrict-prototypes -Wconversion -Og -ggdb3 -ftree-vectorize")
set(CMAKE_C_FLAGS_RELEASE "-Wall -Wextra -Wstrict-prototypes -Wconversion -O3 -fomit-frame-pointer -funroll-loops -ftree-vectorize -DNDEBUG")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-Wall -Wextra -Wstrict-prototypes -Wconversion  -ggdb3 -O3 -funroll-loops -ftree-vectorize -DNDEBUG")
set(CMAKE_C_FLAGS_MINSIZEREL "-Wall -Wextra -Wstrict-prototypes -Wconversion -Os -fomit-frame-pointer -ftree-vectorize -DNDEBUG")
endif("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")

if(CMAKE_C_COMPILER_ID STREQUAL Clang OR CMAKE_C_COMPILER_ID STREQUAL AppleClang)
set(CMAKE_C_FLAGS_DEBUG "-Wall -Wextra -Wstrict-prototypes -Wconversion -O0 -ggdb3 -ftree-vectorize")
set(CMAKE_C_FLAGS_RELEASE "-Wall -Wextra -Wstrict-prototypes -Wconversion -O3 -fomit-frame-pointer -funroll-loops -ftree-vectorize -DNDEBUG")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-Wall -Wextra -Wstrict-prototypes -Wconversion -ggdb3 -O3 -funroll-loops -ftree-vectorize -DNDEBUG")
set(CMAKE_C_FLAGS_MINSIZEREL "-Wall -Wextra -Wstrict-prototypes -Wconversion -Os -fomit-frame-pointer -ftree-vectorize -DNDEBUG")
endif(CMAKE_C_COMPILER_ID STREQUAL Clang OR CMAKE_C_COMPILER_ID STREQUAL AppleClang)

find_package(OpenSSL 1.0.1 REQUIRED COMPONENTS Crypto)
if(NOT DISABLE_DOCS)
  find_program(A2X a2x)
endif(NOT DISABLE_DOCS)

configure_file(config.h.in config.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_library(aes_siv SHARED aes_siv.c)
target_include_directories(aes_siv PUBLIC ${OPENSSL_INCLUDE_DIR})
target_link_libraries(aes_siv ${OPENSSL_CRYPTO_LIBRARY})
set_target_properties(aes_siv PROPERTIES VERSION "1.0.1" SOVERSION 1)

add_library(aes_siv_static STATIC aes_siv.c)
target_include_directories(aes_siv_static PUBLIC ${OPENSSL_INCLUDE_DIR})
target_link_libraries(aes_siv_static ${OPENSSL_CRYPTO_LIBRARY})
set_target_properties(aes_siv_static PROPERTIES OUTPUT_NAME aes_siv)

add_executable(demo demo.c)
target_include_directories(demo PUBLIC ${OPENSSL_INCLUDE_DIR})
target_link_libraries(demo ${OPENSSL_CRYPTO_LIBRARY} aes_siv_static)

add_executable(runtests aes_siv_test.c tests.c)
target_include_directories(runtests PUBLIC ${OPENSSL_INCLUDE_DIR})
target_link_libraries(runtests ${OPENSSL_CRYPTO_LIBRARY})
if(ENABLE_COVERAGE)
  target_compile_options(runtests PRIVATE "--coverage")
  target_link_libraries(runtests "--coverage")
endif(ENABLE_COVERAGE)
if(ENABLE_CTGRIND)
  target_link_libraries(runtests "-lctgrind")
endif(ENABLE_CTGRIND)
if(ENABLE_SANITIZER)
  target_compile_options(runtests PRIVATE "-fsanitize=${ENABLE_SANITIZER}")
  target_link_libraries(runtests "-fsanitize=${ENABLE_SANITIZER}")
endif(ENABLE_SANITIZER)

add_executable(bench EXCLUDE_FROM_ALL bench.c)
target_link_libraries(bench aes_siv_static)

install(TARGETS aes_siv LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(TARGETS aes_siv_static ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES aes_siv.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(A2X)
# Only use -D when needed, since it provokes a bogus warning from a2x.
if(NOT "${CMAKE_CURRENT_BINARY_DIR}" STREQUAL "${CMAKE_CURRENT_SOURCE_DIR}")
  set(A2X_DESTOPT "-D ${CMAKE_CURRENT_BINARY_DIR}")
endif(NOT "${CMAKE_CURRENT_BINARY_DIR}" STREQUAL "${CMAKE_CURRENT_SOURCE_DIR}")

add_custom_target(man ALL DEPENDS
  ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_CTX_new.3
  ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_CTX_copy.3
  ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_CTX_cleanup.3
  ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_CTX_free.3
  ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_Init.3
  ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_AssociateData.3
  ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_EncryptFinal.3
  ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_DecryptFinal.3
  ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_Encrypt.3
  ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_Decrypt.3)

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_CTX_new.3
         ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_CTX_copy.3
	 ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_CTX_cleanup.3
	 ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_CTX_free.3
  COMMAND "${A2X}" ARGS -f manpage ${A2X_DESTOPT} ${CMAKE_CURRENT_SOURCE_DIR}/AES_SIV_CTX_new.adoc
  MAIN_DEPENDENCY ${CMAKE_CURRENT_SOURCE_DIR}/AES_SIV_CTX_new.adoc)
add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_Init.3
         ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_AssociateData.3
	 ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_EncryptFinal.3
	 ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_DecryptFinal.3
  COMMAND "${A2X}" ARGS -f manpage ${A2X_DESTOPT} ${CMAKE_CURRENT_SOURCE_DIR}/AES_SIV_Init.adoc
  MAIN_DEPENDENCY ${CMAKE_CURRENT_SOURCE_DIR}/AES_SIV_Init.adoc)
add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_Encrypt.3
         ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_Decrypt.3
  COMMAND "${A2X}" ARGS -f manpage ${A2X_DESTOPT} ${CMAKE_CURRENT_SOURCE_DIR}/AES_SIV_Encrypt.adoc
  MAIN_DEPENDENCY ${CMAKE_CURRENT_SOURCE_DIR}/AES_SIV_Encrypt.adoc)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_CTX_new.3
  ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_CTX_copy.3
  ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_CTX_cleanup.3
  ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_CTX_free.3
  ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_Init.3
  ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_AssociateData.3
  ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_EncryptFinal.3
  ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_DecryptFinal.3
  ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_Encrypt.3
  ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_Decrypt.3
  DESTINATION ${CMAKE_INSTALL_MANDIR}/man3)
endif(A2X)

enable_testing()
add_test(NAME test COMMAND runtests)
