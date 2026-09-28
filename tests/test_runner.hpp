#pragma once

#include <functional>
#include <stdexcept>
#include <string>

namespace test_runner {

void register_test(const std::string& name, std::function<void()> func);

} // namespace test_runner

#define TEST_ASSERT(expr) \
    do { \
        if (!(expr)) { \
            throw std::runtime_error(std::string("Assertion failed: (") + #expr + ") at " + __FILE__ + ":" + std::to_string(__LINE__)); \
        } \
    } while (0)
