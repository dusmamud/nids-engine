#include <iostream>
#include <vector>
#include <string>
#include <functional>
#include "test_runner.hpp"

namespace test_runner {

struct TestCase {
    std::string name;
    std::function<void()> func;
};

std::vector<TestCase>& get_registry() {
    static std::vector<TestCase> registry;
    return registry;
}

void register_test(const std::string& name, std::function<void()> func) {
    get_registry().push_back({name, std::move(func)});
}

} // namespace test_runner

int main() {
    std::cout << "=======================================\n";
    std::cout << "  nids-engine Automated Unit Test Suite\n";
    std::cout << "=======================================\n";

    size_t passed = 0;
    size_t failed = 0;

    for (const auto& test : test_runner::get_registry()) {
        std::cout << "RUNNING: " << test.name << " ... ";
        try {
            test.func();
            std::cout << "[PASSED]\n";
            passed++;
        } catch (const std::exception& ex) {
            std::cout << "[FAILED]: " << ex.what() << "\n";
            failed++;
        } catch (...) {
            std::cout << "[FAILED]: Unknown exception\n";
            failed++;
        }
    }

    std::cout << "---------------------------------------\n";
    std::cout << "Results: " << passed << " passed, " << failed << " failed.\n";
    std::cout << "=======================================\n";

    return (failed == 0) ? 0 : 1;
}
