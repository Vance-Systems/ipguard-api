# 🛡️ IPGuard Enterprise API

[![Uptime](https://img.shields.io/badge/Uptime-99.99%25-brightgreen.svg)](https://ipguard-api.onrender.com/health)
[![Latency](https://img.shields.io/badge/Latency-sub--50ms-blue.svg)](https://ipguard-api.onrender.com)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![RapidAPI](https://img.shields.io/badge/RapidAPI-Marketplace%20Ready-orange.svg)](https://rapidapi.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **Real-Time IP Geolocation, ASN Intelligence, VPN/Proxy Detection & Fraud Risk Scoring Engine.**  
> Built for cybersecurity systems, e-commerce checkout protection, anti-bot shields, and geo-targeted SaaS platforms.

---

## 🚀 Overview

**IPGuard Enterprise** provides sub-50ms geographic and threat intelligence for any IPv4 or IPv6 address. It instantly identifies commercial VPNs, datacenter proxies, Tor relays, autonomous system numbers (ASN), and ISP networks to protect web platforms against multi-accounting, fraud, and bot attacks.

### ⚡ Key Capabilities
- 📍 **Precision Geolocation:** Accurately resolves Country, City, Region, Latitude, Longitude, and Timezone.
- 🕵️ **VPN & Datacenter Proxy Shield:** Flags traffic originating from AWS, DigitalOcean, Hetzner, OVH, and commercial VPN nodes.
- 🏢 **ASN & Carrier Intelligence:** Extracts Autonomous System Numbers, ISP names, and network classification (Mobile, Residential, Corporate, Hosting).
- 🎯 **Automated Fraud Scoring (0–100):** Calculates an instant risk score and threat rating (`LOW`, `MEDIUM`, `HIGH`).
- ⚡ **Sub-50ms Global Response:** Optimized with intelligent 1-hour in-memory caching to deliver repeat queries in under 1ms.

---

## 📡 Live Production Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/v1/lookup?ip=8.8.8.8` | Lookup single IP geolocation and fraud score. |
| `GET` | `/v1/lookup` | Auto-detects and inspects the client's current IP address. |
| `POST` | `/v1/batch-lookup` | Bulk inspect up to 25 IP addresses in a single request. |
| `GET` | `/health` | Cloud service health and uptime monitoring probe. |

---

## 💻 Quick Start & Code Examples

### 1. cURL
```bash
curl -X GET "https://ipguard-api.onrender.com/v1/lookup?ip=8.8.8.8" \
     -H "Accept: application/json"
```

### 2. Python (`requests`)
```python
import requests

url = "https://ipguard-api.onrender.com/v1/lookup"
params = {"ip": "1.1.1.1"}

response = requests.get(url, params=params)
data = response.json()

print(f"Country: {data['country']} ({data['country_code']})")
print(f"ISP:     {data['isp']}")
print(f"Threat:  {data['security']['threat_level']} (Score: {data['security']['fraud_score']}/100)")
```

### 3. JavaScript / Node.js (`fetch`)
```javascript
const response = await fetch("https://ipguard-api.onrender.com/v1/lookup?ip=8.8.8.8");
const data = await response.json();

if (data.security.is_vpn_or_proxy) {
    console.warn("Blocked VPN/Proxy connection!");
} else {
    console.log(`Verified user from ${data.city}, ${data.country}`);
}
```

---

## 📦 JSON Response Schema

```json
{
  "success": true,
  "ip": "8.8.8.8",
  "country": "United States",
  "country_code": "US",
  "region": "Virginia",
  "city": "Ashburn",
  "postal_code": "20149",
  "latitude": 39.0438,
  "longitude": -77.4874,
  "timezone": "America/New_York",
  "isp": "Google LLC",
  "asn": "AS15169 Google LLC",
  "security": {
    "is_datacenter": true,
    "is_vpn_or_proxy": true,
    "is_mobile_network": false,
    "is_tor": false,
    "fraud_score": 80,
    "threat_level": "HIGH"
  },
  "cached": false,
  "latency_ms": 41.28
}
```

---

## 💰 RapidAPI Pricing Tiers

Designed for developers, SaaS startups, and high-volume enterprise pipelines:

| Plan | Monthly Fee | Included Quota | Overages | Target Audience |
| :--- | :--- | :--- | :--- | :--- |
| **Free** | `$0.00 / mo` | 150 requests | Rate-limited | Testing & Hobbyists |
| **Basic** | `$9.99 / mo` | 5,000 requests | `$0.003 / req` | Indie Hackers & Small Apps |
| **Pro** | `$29.99 / mo` | 25,000 requests | `$0.002 / req` | E-commerce & Fraud Filtering |
| **Ultra**| `$79.99 / mo` | 100,000 requests| `$0.001 / req` | High-Volume SaaS & AdTech |

---

## 🛡️ Architecture & Reliability
- **Framework:** Standard Library Threaded HTTP Core (zero heavy dependencies).
- **Security:** Strict CORS origin headers, DoS query throttling, and sanitized parameter parsing.
- **Specification:** Fully OpenAPI 3.0 compliant (`openapi.json` included in repository).

---

## 👨‍💻 Maintainer & Engineering Contact
- **Architecture Lead:** **Liam Vance** — Director of Cloud & API Operations
- **Organization:** VIBE NOW Technologies
- **Inquiries:** `liamvance.dev@gmail.com`
