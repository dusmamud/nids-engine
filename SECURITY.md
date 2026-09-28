# Security Policy

## Supported Versions

Security updates and patches are actively maintained for the following versions:

| Version | Supported |
| :--- | :--- |
| `0.1.x` (current) | Yes |

---

## Reporting a Vulnerability

As a network security tool operating in promiscuous capture mode and parsing untrusted remote packet payloads, memory safety and buffer boundary validation are paramount.

If you discover a security vulnerability (such as a buffer overrun in protocol dissection, denial-of-service via malformed packet headers, or integer overflow during payload calculation):

1. **Do NOT open a public GitHub issue.**
2. Send a detailed report directly to the maintainer via email:  
   **Dus Mamud** (`dusmamud0@gmail.com`).
3. Include the following details:
   - Type of issue (e.g. out-of-bounds read, assertion failure under fuzzing).
   - Minimal reproduction trace or `.pcap` capture file trigger.
   - Operating system and compiler version.
   - Proposed patch (if available).

We will acknowledge receipt within 48 hours and coordinate a public release timeline following responsible disclosure best practices.
