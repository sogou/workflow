#include <gtest/gtest.h>
#include <string>
#include <thread>
#include <vector>
#include <atomic>
#include "LFUCache.h"
#include "ConcurrentCache.h"

namespace {

struct IntValue
{
    int val;
    IntValue(int v) : val(v) {}
};

struct IntDeleter
{
    void operator()(const IntValue& v) const {}
};

// --- LFU Tests ---

TEST(LFUCacheTest, BasicPutGet)
{
    LFUCache<int, IntValue, IntDeleter> cache;
    cache.set_max_size(3);

    auto h = cache.put(1, 100);
    cache.release(h);

    auto h2 = cache.get(1);
    ASSERT_TRUE(h2 != nullptr);
    EXPECT_EQ(h2->value.val, 100);
    EXPECT_EQ(h2->get_key(), 1); 
    cache.release(h2);
}

TEST(LFUCacheTest, EvictionPolicy)
{
    LFUCache<int, IntValue, IntDeleter> cache;
    cache.set_max_size(2);

    cache.release(cache.put(1, 10)); // A
    cache.release(cache.put(2, 20)); // B

    auto h1 = cache.get(1); // 访问 A -> A频次=2
    cache.release(h1);

    cache.release(cache.put(3, 30)); // 插入 C -> 淘汰 B (频次1)

    EXPECT_TRUE(cache.get(1) != nullptr);
    EXPECT_TRUE(cache.get(2) == nullptr);
    EXPECT_TRUE(cache.get(3) != nullptr);
    
    if (auto p = cache.get(1)) cache.release(p);
    if (auto p = cache.get(3)) cache.release(p);
}

TEST(LFUCacheTest, TieBreakingLRU)
{
    LFUCache<int, IntValue, IntDeleter> cache;
    cache.set_max_size(2);

    cache.release(cache.put(1, 10)); 
    cache.release(cache.put(2, 20)); 

    cache.release(cache.put(3, 30)); // 淘汰 1 (最久未用)

    EXPECT_TRUE(cache.get(1) == nullptr);
    EXPECT_TRUE(cache.get(2) != nullptr);
    EXPECT_TRUE(cache.get(3) != nullptr);

    if (auto p = cache.get(2)) cache.release(p);
    if (auto p = cache.get(3)) cache.release(p);
}

// --- Concurrent Tests ---

TEST(ConcurrentCacheTest, MultiThreadedAccess)
{
    ConcurrentCache<int, int, LFUCache<int, int, IntDeleter>> cache(100);
    const int THREADS = 8;
    const int OPS = 5000;

    std::atomic<int> hits(0);
    std::vector<std::thread> ths;

    for (int i = 0; i < THREADS; ++i) {
        ths.emplace_back([&, i](){
            for (int k = 0; k < OPS; ++k) {
                int key = k % 200; 
                // [修正] 使用 %3 来混合读写，打破奇偶隔离
                // k=0 (key=0): Put
                // k=200 (key=0): 200%3=2 -> Get (HIT!)
                if (k % 3 == 0) {
                     auto h = cache.put(key, k);
                     cache.release(h);
                } else {
                     auto h = cache.get(key);
                     if (h) {
                         hits++;
                         cache.release(h);
                     }
                }
            }
        });
    }

    for (auto& t : ths) t.join();
    // 现在应该能产生命中了
    ASSERT_GT(hits.load(), 0);
}

} // namespace