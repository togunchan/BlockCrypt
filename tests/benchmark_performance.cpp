#define CATCH_CONFIG_MAIN
#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>
#include "blockcrypt.hpp"

TEST_CASE("AES-128 encrypt 10,000 ops per block", "[benchmark][latency]")
{
    BlockCrypt::Key key = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x4d, 0x4d,
        0x09, 0xcf, 0x4f, 0x3c};
    BlockCrypt aes(key);

    BlockCrypt::Block block = {
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2,
        0xe0, 0x37, 0x07, 0x34};

    BENCHMARK_ADVANCED("AES-128 encrypt × 10,000 ops")
    (Catch::Benchmark::Chronometer meter)
    {
        meter.measure([&]
                      {
            for (int i = 0; i < 10'000; ++i) {
                aes.encrypt(block);
            } });
    };
}

TEST_CASE("AES-128 throughput: encrypt 10,000 blocks", "[benchmark][throughput]")
{
    BlockCrypt::Key key = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x4d, 0x4d,
        0x09, 0xcf, 0x4f, 0x3c};
    BlockCrypt aes(key);

    std::vector<BlockCrypt::Block> blocks(10'000);

    for (int i = 0; i < 10'000; ++i)
    {
        for (int j = 0; j < 16; ++j)
        {
            blocks[i][j] = uint8_t((i + j) & 0xFF);
        }
    }

    BENCHMARK("AES-128 encrypt 10,000 blocks (throughput)")
    {
        for (auto &blk : blocks)
        {
            aes.encrypt(blk);
        }
    };
}