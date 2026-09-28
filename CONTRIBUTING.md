# Contributing to nids-engine

Thank you for your interest in contributing to `nids-engine`. We maintain a high standard for systems engineering, test coverage, and documentation.

## Code of Conduct

All contributors and maintainers are expected to uphold a professional, respectful, and collaborative environment free from harassment.

---

## Development Workflow

### 1. Branching Convention

We follow standard short-lived feature branching:
- `main`: Production-ready, verified code.
- `feat/<feature-name>`: New protocol dissector or detection rule.
- `fix/<bug-description>`: Bugfix for parsing edge case or concurrency defect.
- `perf/<optimization>`: Measurable throughput or latency optimization.

### 2. Commit Message Standards

All commits must strictly follow the [Conventional Commits specification](https://www.conventionalcommits.org/en/v1.0.0/):

```text
<type>(<scope>): <short imperative description>
```

Valid types:
- `feat`: New detector or protocol layer.
- `fix`: Memory leak fix, boundary check fix, or endianness correction.
- `perf`: SIMD optimization, allocation reduction, or lock contention fix.
- `refactor`: Clean restructuring without functional change.
- `test`: Adding synthetic PCAP unit tests or boundary test cases.
- `docs`: Updating architecture specs or setup documentation.

Example:
```text
feat(dissector): add IPv6 extension header parsing support
fix(entropy): prevent divide-by-zero on empty payload buffers
perf(flow): replace global mutex with 16-way sharded shared_mutex
```

---

## Code Quality Standards

1. **Modern C++20:** Code must use idiomatic modern C++ constructs:
   - Use `std::span` or `std::string_view` for non-owning memory references.
   - Use RAII wrappers for all operating system handles and PCAP pointers.
   - Prefer `const` references and explicit value moves.
2. **Zero Syntax Commentary:** Do not comment code to narrate syntax. Comments must solely explain non-obvious architecture decisions, hardware interactions, or protocol idiosyncrasies.
3. **Formatting & Linting:** Code must pass format checks before PR submission:
   ```bash
   make format
   make lint
   ```
4. **Verification & Tests:** Every PR adding a detector or dissector must include comprehensive unit tests verifying both valid traffic and adversarial/malformed packets.

---

## Submitting Pull Requests

1. Fork and create your branch from `main`.
2. Ensure your changes compile without warnings:
   ```bash
   cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug -DENABLE_WERROR=ON
   cmake --build build
   ```
3. Run test suite and confirm 100% pass:
   ```bash
   ctest --test-dir build --output-on-failure
   ```
4. Open a PR using the repository PR template, outlining the motivation, benchmarks (if applicable), and testing methodology.
