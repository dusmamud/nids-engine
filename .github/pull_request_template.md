## Summary of Changes

A concise, high-level explanation of the problem being solved or feature introduced.

## Motivation & Context

- Why is this change necessary?
- Which RFC, issue, or performance benchmark motivated this approach?

## Technical Details

- [ ] Zero-copy boundaries maintained (`std::span` used instead of copy allocations)
- [ ] Concurrency synchronization verified (no race conditions, lock order inverted, or deadlocks)
- [ ] Endianness handled correctly (`ntohs`, `ntohl`)
- [ ] Boundary checks in place for packet buffers

## Verification & Testing

Explain how changes were tested:
```bash
# Example verification command
ctest --test-dir build --output-on-failure
```

- [ ] Unit tests added / updated
- [ ] Tested against synthetic malformed PCAP
- [ ] Static analysis and formatting passed (`make lint && make format`)
