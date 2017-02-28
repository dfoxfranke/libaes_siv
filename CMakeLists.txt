cmake_minimum_required (VERSION 3.0)
project(libaes_siv LANGUAGES C)
set(CMAKE_C_STANDARD 99)
set(CMAKE_CONFIGURATION_TYPESDebug Release RelWithDebInfo MinSizeRel)
if("${CMAKE_BUILD_TYPE}" STREQUAL "")
set(CMAKE_BUILD_TYPE Release)
endif("${CMAKE_BUILD_TYPE}" STREQUAL "")

# Warning: don't use the UB sanitizer in production builds. It can introduce timing side-channels
# into otherwise constant-time code.
if("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
set(CMAKE_C_FLAGS_DEBUG "-Wall -Wconversion -Og -ggdb3 -ftree-vectorize")
set(CMAKE_C_FLAGS_RELEASE "-Wall -Wconversion -O3 -fomit-frame-pointer -funroll-loops -ftree-vectorize -DNDEBUG")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-Wall -Wconversion  -ggdb3 -O3 -funroll-loops -ftree-vectorize -DNDEBUG")
set(CMAKE_C_FLAGS_MINSIZEREL "-Wall -Wconversion -Os -fomit-frame-pointer -ftree-vectorize -DNDEBUG")
endif("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")

if(CMAKE_C_COMPILER_ID STREQUAL Clang OR CMAKE_C_COMPILER_ID STREQUAL AppleClang)
set(CMAKE_C_FLAGS_DEBUG "-Wall -Wconversion -O0 -ggdb3 -ftree-vectorize")
set(CMAKE_C_FLAGS_RELEASE "-Wall -Wconversion -O3 -fomit-frame-pointer -funroll-loops -ftree-vectorize -DNDEBUG")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-Wall -Wconversion -ggdb3 -O3 -funroll-loops -ftree-vectorize -DNDEBUG")
set(CMAKE_C_FLAGS_MINSIZEREL "-Wall -Wconversion -Os -fomit-frame-pointer -ftree-vectorize -DNDEBUG")
endif(CMAKE_C_COMPILER_ID STREQUAL Clang OR CMAKE_C_COMPILER_ID STREQUAL AppleClang)

find_package(OpenSSL 1.0.1 REQUIRED COMPONENTS Crypto)
find_program(A2X a2x)

configure_file(config.h.in config.h)

add_library(aes_siv SHARED aes_siv.c)
target_link_libraries(aes_siv ${OPENSSL_CRYPTO_LIBRARY})
set_target_properties(aes_siv PROPERTIES VERSION "1.0.0" SOVERSION 1)

add_library(aes_siv_static STATIC aes_siv.c)
target_link_libraries(aes_siv_static ${OPENSSL_CRYPTO_LIBRARY})
set_target_properties(aes_siv_static PROPERTIES OUTPUT_NAME aes_siv)

add_executable(runtests aes_siv_test.c tests.c)
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

install(TARGETS aes_siv LIBRARY DESTINATION lib)
install(TARGETS aes_siv_static ARCHIVE DESTINATION lib)
install(FILES aes_siv.h DESTINATION include)

if(A2X)
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
  COMMAND "${A2X}" ARGS -f manpage ${CMAKE_CURRENT_SOURCE_DIR}/AES_SIV_CTX_new.adoc
  MAIN_DEPENDENCY ${CMAKE_CURRENT_SOURCE_DIR}/AES_SIV_CTX_new.adoc)
add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_Init.3
         ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_AssociateData.3
	 ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_EncryptFinal.3
	 ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_DecryptFinal.3
  COMMAND "${A2X}" ARGS -f manpage ${CMAKE_CURRENT_SOURCE_DIR}/AES_SIV_Init.adoc
  MAIN_DEPENDENCY ${CMAKE_CURRENT_SOURCE_DIR}/AES_SIV_Init.adoc)
add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_Encrypt.3
         ${CMAKE_CURRENT_BINARY_DIR}/AES_SIV_Decrypt.3
  COMMAND "${A2X}" ARGS -f manpage ${CMAKE_CURRENT_SOURCE_DIR}/AES_SIV_Encrypt.adoc
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
  DESTINATION share/man/man3)
endif(A2X)

enable_testing()
add_test(NAME test COMMAND runtests)
