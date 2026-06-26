#include <gtest/gtest.h>

#if CLV_ASAN_ENABLED
#include <iostream>
#endif

// Detect ASAN at compile time
#if defined(__SANITIZE_ADDRESS__) || (defined(__has_feature) && __has_feature(address_sanitizer))
#define CLV_ASAN_ENABLED 1
#if defined(__has_include)
#if __has_include(<sanitizer/asan_interface.h>)
#include <sanitizer/asan_interface.h>
#else
// ASAN header is not available, but the runtime may still provide the symbol;
// declare the minimal API we need to compile the test.
extern "C" int __asan_address_is_poisoned(const void *addr);
#endif
#else
#include <sanitizer/asan_interface.h>
#endif
#else
#define CLV_ASAN_ENABLED 0
#endif

TEST(AsanVerification, RuntimeCheck)
{
#if CLV_ASAN_ENABLED
    SUCCEED() << "ASAN is enabled at compile time.";

    volatile int *ptr = new int[10];
    delete[] ptr;

    if (__asan_address_is_poisoned((void *)ptr))
    {
        SUCCEED() << "ASAN runtime verified: Memory is poisoned after free.";
    }
    else
    {
        FAIL() << "ASAN runtime check failed: Memory was not poisoned after free!";
    }
#else
    std::cout << "[   INFO   ] ASAN is NOT enabled in this build." << std::endl;
#endif
}
