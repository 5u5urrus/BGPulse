<p align="center">
  <img src="bgpulse.png" width="100%" alt="BGPulse Banner">
</p>

# BGPulse

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

BGPulse is a comprehensive, automated tool for assessing Border Gateway Protocol (BGP) security vulnerabilities in network equipment. This tool helps network administrators and security professionals identify potential security weaknesses in BGP implementations before they can be exploited by malicious actors.

## Features

- Performs 9 different categories of security tests
- Detects common BGP vulnerabilities and misconfigurations
- Provides detailed reports with severity ratings
- Single command operation with minimal dependencies
- Comprehensive security assessment in minutes

## Usage

Basic usage:

```bash
python bgp.py <target_ip> [target_port]
```

Example:

```bash
python bgp.py 192.168.1.1
```

Advanced options:

```bash
python bgp.py 192.168.1.1 179 --timeout 10 --verbose
```

### Command-line Arguments

| Argument | Description |
|----------|-------------|
| `target_ip` | Target BGP router IP address (required) |
| `target_port` | Target BGP port number (default: 179) |
| `-t, --timeout` | Connection timeout in seconds (default: 5) |
| `-v, --verbose` | Enable verbose output |
| `-q, --quiet` | Disable all output except final summary |

## Security Tests Overview

The tool performs the following categories of security tests:

1. **Basic Connectivity Testing**
2. **Protocol Compliance Checks**
3. **Authentication Probing**
4. **Capability Negotiation Testing**
5. **ASN Validation**
6. **Malformed Message Handling**
7. **Route Filtering Assessment**
8. **Session Behavior Analysis**
9. **Resource Exhaustion Resilience**

## Detailed Security Test Descriptions

### 1. Basic Connectivity Testing

**What it is:**  
This test verifies the ability to establish a TCP connection to the BGP port (typically 179) on the target device.

**How we test it:**  
The tool attempts to establish a TCP connection to the specified target IP and port. It measures response time and evaluates connection reliability.

**Why it matters:**  
A successful connection is the foundation for all other tests. If this test fails, it indicates that:
- The BGP service may not be running
- There might be firewall rules blocking access
- The router might be configured to only accept connections from specific IP addresses

**Security implications:**  
While basic connectivity is essential for BGP operation, unrestricted access could potentially allow unauthorized devices to attempt BGP connections. Routers should implement proper access control lists (ACLs) to limit which IP addresses can initiate BGP sessions.

### 2. Protocol Compliance Checks

**What it is:**  
This test verifies whether the BGP implementation adheres to protocol standards defined in RFCs (primarily RFC 4271 and related documents).

**How we test it:**  
The tool attempts to establish BGP sessions using standard messages and parameters, analyzing the responses to ensure they conform to protocol specifications.

**Why it matters:**  
Non-compliant BGP implementations may:
- Introduce interoperability issues
- Create unexpected behaviors when interacting with other vendors' equipment
- Open security vulnerabilities due to improper protocol handling

**Security implications:**  
Protocol non-compliance can lead to vulnerabilities that could be exploited to cause session disruption, information leakage, or even routing manipulation attacks.

### 3. Authentication Probing

**What it is:**  
This test evaluates the BGP peer's authentication mechanisms and requirements.

**How we test it:**  
The tool attempts to establish connections with different authentication parameters, testing whether the router:
- Requires authentication
- Accepts sessions without authentication
- Handles authentication errors appropriately

**Why it matters:**  
Proper authentication is crucial for preventing unauthorized BGP sessions. Without it, attackers could potentially establish BGP sessions with your routers and inject malicious routes.

**Security implications:**  
Weak or missing authentication is one of the most serious BGP security issues. BGP sessions should use MD5 authentication (as defined in RFC 2385) at a minimum, with more modern approaches like RPKI and BGPsec being highly recommended for critical infrastructure.

### 4. Capability Negotiation Testing

**What it is:**  
This test evaluates how the BGP peer handles capability advertisements and negotiation during session establishment.

**How we test it:**  
The tool sends OPEN messages with various combinations of capabilities (like 4-byte ASN support, route refresh, multiprotocol extensions) and analyzes how the peer handles them.

**Why it matters:**  
Capability negotiation allows BGP peers to communicate what features they support. Proper handling of capabilities ensures:
- Interoperability between different BGP implementations
- Support for security-enhancing features
- Proper backward compatibility

**Security implications:**  
Improper capability handling can lead to session establishment failures or, more concerning, might cause the router to disable important security features when interacting with certain peers.

### 5. ASN Validation

**What it is:**  
This test examines how the BGP peer handles different Autonomous System Numbers (ASNs), including reserved ASNs, private ASNs, and 4-byte ASNs.

**How we test it:**  
The tool attempts to establish BGP sessions using various ASNs, including:
- Reserved ASNs (like 0 and 23456)
- Private ASN ranges (64512-65534 for 2-byte and 4200000000-4294967294 for 4-byte)
- Documentation ASNs (like 64496-64511)
- 4-byte ASNs (requiring capabilities negotiation)

**Why it matters:**  
Proper ASN handling is crucial for:
- Preventing route leaks and hijacks
- Maintaining the integrity of the global routing table
- Ensuring proper AS path validation

**Security implications:**  
Improper ASN validation could allow attackers to use spoofed or reserved ASNs in attacks, potentially bypassing route filters or facilitating route hijacking.

### 6. Malformed Message Handling

**What it is:**  
This test evaluates how the BGP implementation responds to malformed and invalid BGP messages.

**How we test it:**  
The tool sends deliberately malformed BGP messages with:
- Invalid markers
- Incorrect length fields
- Unsupported message types
- Invalid BGP versions
- Truncated messages

**Why it matters:**  
Resilient BGP implementations should handle malformed messages gracefully by:
- Sending appropriate NOTIFICATION messages
- Closing connections when necessary
- Logging error details without crashing
- Implementing proper error recovery

**Security implications:**  
Poor handling of malformed messages can lead to:
- Denial-of-service vulnerabilities
- Session instability
- Information leakage through verbose error messages
- Potential buffer overflow or other memory corruption vulnerabilities

### 7. Route Filtering Assessment

**What it is:**  
This test evaluates whether the BGP peer properly filters invalid routes and prefixes that shouldn't be accepted.

**How we test it:**  
The tool attempts to advertise various problematic routes, including:
- Bogon prefixes (private IP ranges, reserved ranges)
- Default routes (0.0.0.0/0)
- Highly specific prefixes (/32s)
- Prefixes with invalid path attributes

**Why it matters:**  
Route filtering is one of the most crucial security controls in BGP. Without proper filtering:
- Invalid routes could propagate through your network
- Private address space could be advertised publicly
- Route leaks could occur

**Security implications:**  
Lack of proper route filtering is a major security concern that has led to numerous real-world incidents, including route hijacks, traffic misdirection, and network outages. Implementing comprehensive inbound and outbound route filters is a critical security practice.

### 8. Session Behavior Analysis

**What it is:**  
This test evaluates the behavior of established BGP sessions, focusing on timer handling, keepalive messages, and session maintenance.

**How we test it:**  
The tool establishes a BGP session and then:
- Tests hold timer enforcement by remaining silent
- Evaluates keepalive message handling
- Monitors response to various session events

**Why it matters:**  
Proper session behavior ensures:
- Timely detection of peer failures
- Resource conservation
- Session stability under various conditions

**Security implications:**  
Improper session handling could lead to:
- Delayed detection of session issues
- Resource exhaustion through unnecessary session maintenance
- Potential denial-of-service vulnerabilities

### 9. Resource Exhaustion Resilience

**What it is:**  
This test evaluates how the BGP implementation handles potential resource exhaustion scenarios.

**How we test it:**  
The tool attempts various resource-intensive operations:
- Rapid connection attempts
- Large UPDATE messages with many attributes
- Updates with numerous prefixes
- Multiple concurrent sessions

**Why it matters:**  
BGP implementations should be resilient to resource exhaustion attempts, with proper:
- Connection rate limiting
- Memory usage controls
- CPU usage protections
- Session prioritization

**Security implications:**  
Vulnerability to resource exhaustion could allow attackers to:
- Cause denial-of-service conditions
- Trigger BGP session flaps
- Potentially crash the routing process
- Impact other network functions

## Understanding Test Results

The tool provides results with severity ratings to help prioritize findings:

- **HIGH**: Critical issues that should be addressed immediately
- **MEDIUM**: Significant concerns that should be addressed soon
- **LOW**: Minor issues that represent best-practice improvements
- **INFO**: Informational findings that provide context about the implementation

Example output:

```
================================================================================
BGP SECURITY ASSESSMENT SUMMARY FOR 192.168.1.1:179
================================================================================

HIGH SEVERITY ISSUES:
--------------------------------------------------------------------------------
[Route Filtering (RFC1918 private)] Router silently accepted bogon prefix 10.0.0.0/8

MEDIUM SEVERITY ISSUES:
--------------------------------------------------------------------------------
[ASN Test (Reserved ASN (0))] Router incorrectly accepted reserved ASN 0

LOW SEVERITY ISSUES:
--------------------------------------------------------------------------------
[Malformed Message (Invalid marker)] Router closed connection without sending NOTIFICATION

PASSING TESTS:
--------------------------------------------------------------------------------
[Basic Connectivity] Successfully established TCP connection to 192.168.1.1:179
[BGP Session Establishment] Successfully established BGP session with peer AS 65000
[Hold Timer Test] Router correctly sent Hold Timer Expired notification

SUMMARY COUNTS:
--------------------------------------------------------------------------------
Total Tests: 24
Passing: 15
High Severity Issues: 2
Medium Severity Issues: 3
Low Severity Issues: 1
Informational Results: 3
================================================================================
```

## Best Practices for BGP Security

Based on the tests performed by this tool, consider implementing these BGP security best practices:

1. **Implement MD5 authentication** (RFC 2385) for all BGP sessions
2. **Deploy comprehensive route filtering**:
   - Inbound filters to block bogon, martian, and unexpected prefixes
   - Outbound filters to prevent route leaks
3. **Implement RPKI** for origin validation
4. **Use BGPsec** when available for path validation
5. **Set appropriate maximum prefix limits** to prevent resource exhaustion
6. **Implement BCP38** (ingress filtering) to prevent spoofed source addresses
7. **Use TTL security (GTSM)** as defined in RFC 5082
8. **Monitor BGP announcements** using services like RIPE RIS or BGPMon
9. **Deploy DDoS protection** for BGP infrastructure
10. **Maintain current software** with security patches

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Vahe Demirkhanyan 
Contact: https://www.linkedin.com/in/vahearamian/
