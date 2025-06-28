file(GLOB TEST_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

add_executable(test_blockcrypt ${TEST_SOURCES})

target_link_libraries(test_blockcrypt
    PRIVATE
    blockcrypt_lib
    Catch2::Catch2WithMain
)

# target_compile_options(BlockCryptTests PRIVATE -fno-sanitize=address)
# target_link_options(BlockCryptTests PRIVATE -fno-sanitize=address)

add_test(NAME BlockCryptTests COMMAND test_blockcrypt)