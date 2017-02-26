cmake_minimum_required (VERSION 3.0)
set(CMAKE_C_STANDARD 99)
set(CMAKE_CONFIGURATION_TYPESDebug Release RelWithDebInfo MinSizeRel Coverage)
if("${CMAKE_BUILD_TYPE}" STREQUAL "")
set(CMAKE_BUILD_TYPE Release)
endif("${CMAKE_BUILD_TYPE}" STREQUAL "")

if("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
set(CMAKE_C_FLAGS_DEBUG "-Wall -Wconversion -Og -ggdb3 -ftree-vectorize -fsanitize=undefined")
set(CMAKE_C_FLAGS_RELEASE "-Wall -Wconversion -O3 -fomit-frame-pointer -funroll-loops -ftree-vectorize -DNDEBUG")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-Wall -Wconversion  -ggdb3 -O3 -funroll-loops -ftree-vectorize -DNDEBUG")
set(CMAKE_C_FLAGS_MINSIZEREL "-Wall -Wconversion -Os -fomit-frame-pointer -ftree-vectorize -DNDEBUG")
set(CMAKE_C_FLAGS_COVERAGE "--coverage -Wall -Wconversion -Og -ggdb3 -ftree-vectorize -fsanitize=undefined")
endif("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")

if(CMAKE_C_COMPILER_ID STREQUAL Clang OR CMAKE_C_COMPILER_ID STREQUAL AppleClang)
set(CMAKE_C_FLAGS_DEBUG "-Wall -Wconversion -O0 -ggdb3 -ftree-vectorize -fsanitize=undefined")
set(CMAKE_C_FLAGS_RELEASE "-Wall -Wconversion -O3 -fomit-frame-pointer -funroll-loops -ftree-vectorize -DNDEBUG")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-Wall -Wconversion -ggdb3 -O3 -funroll-loops -ftree-vectorize -DNDEBUG")
set(CMAKE_C_FLAGS_MINSIZEREL "-Wall -Wconversion -Os -fomit-frame-pointer -ftree-vectorize -DNDEBUG")
set(CMAKE_C_FLAGS_COVERAGE "--coverage -Wall -Wconversion -O0 -ggdb3 -ftree-vectorize -fsanitize=undefined")
endif(CMAKE_C_COMPILER_ID STREQUAL Clang OR CMAKE_C_COMPILER_ID STREQUAL AppleClang)

find_package(OpenSSL 1.0.1 REQUIRED COMPONENTS Crypto)
find_program(A2X a2x)

add_library(aes_siv aes_siv.c)
target_link_libraries(aes_siv ${OPENSSL_CRYPTO_LIBRARY})
if("${CMAKE_BUILD_TYPE}" STREQUAL "Coverage")
target_link_libraries(aes_siv "--coverage")
endif("${CMAKE_BUILD_TYPE}" STREQUAL "Coverage")

add_executable(runtests aes_siv_test.c tests.c)
target_link_libraries(runtests ${OPENSSL_CRYPTO_LIBRARY})
if("${CMAKE_BUILD_TYPE}" STREQUAL "Coverage")
target_link_libraries(runtests "--coverage")
endif("${CMAKE_BUILD_TYPE}" STREQUAL "Coverage")

install(TARGETS aes_siv ARCHIVE DESTINATION lib LIBRARY DESTINATION lib)
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
