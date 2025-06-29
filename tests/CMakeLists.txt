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

# --- Benchmark executable ---
add_executable(benchmark_performance benchmark_performance.cpp)
target_link_libraries(benchmark_performance
    PRIVATE
      blockcrypt_lib
      Catch2::Catch2WithMain
)

# Register benchmark with CTest
add_test(NAME Benchmarks
         COMMAND benchmark_performance -b)
set_tests_properties(Benchmarks PROPERTIES LABELS "benchmark")

add_test(NAME ECBLatencyBenchmark COMMAND benchmark_performance -b "[ecb][latency]")
add_test(NAME ECBThroughputBenchmark COMMAND benchmark_performance -b "[ecb][throughput]")

add_test(NAME CBCLatencyBenchmark COMMAND benchmark_performance -b "[cbc][latency]")
add_test(NAME CBCThroughputBenchmark COMMAND benchmark_performance -b "[cbc][throughput]")