.PHONY: all build test clean format lint

BUILD_DIR ?= build
CONFIG ?= Release

all: build

build:
	cmake -B $(BUILD_DIR) -S . -DCMAKE_BUILD_TYPE=$(CONFIG) -DBUILD_TESTS=ON
	cmake --build $(BUILD_DIR) --config $(CONFIG) --parallel

test: build
	ctest --test-dir $(BUILD_DIR) -C $(CONFIG) --output-on-failure

format:
	find include src tests -name '*.hpp' -o -name '*.cpp' | xargs clang-format -i

lint:
	clang-tidy -p $(BUILD_DIR) src/**/*.cpp

clean:
	rm -rf $(BUILD_DIR)
