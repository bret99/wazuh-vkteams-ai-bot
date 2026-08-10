# 🛡️ Wazuh SIEM AI Copilot for VK Teams

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: PEP8](https://img.shields.io/badge/code%20style-PEP8-orange.svg)](https://www.python.org/dev/peps/pep-0008/)

**Wazuh SIEM AI Copilot** is an Enterprise-grade integration bot for **VK Teams** designed for Security Operations Centers (SOC). It queries OpenSearch / Wazuh alerts for specific hosts or users, processes and cleanses telemetry data in real-time, and leverages Large Language Models (LLMs) to perform automated incident triage and deliver actionable SOC analysis.

---

## ✨ Features

- **🎯 Target Tracking**: Instant search across hostnames (`agent.name`) and multi-field user entities (`data.src_user`, `syscheck.uname_after`, etc.).
- **⚡ In-Memory Filtering**: High-performance log reduction stripping non-essential metadata fields without external dependencies (`jq`).
- **🤖 AI SOC Analysis**: Automated threat evaluation, IoC verdict generation, and mitigation recommendations powered by LLM API integration.
- **📱 VK Teams Interactive UI**: Asynchronous polling, FSM state management, inline keyboards, and auto-chunking for long messages.
- **🔒 Enterprise Security**: Isolated configuration management ensuring secrets remain excluded from repository source code.

---

## 🚀 Quick Start

### 1. Prerequisites

- Python 3.9+
- Access to a Wazuh SIEM / OpenSearch instance (port `9200`)
- VK Teams Bot API Token
- AI / RouterAI API Key

### 2. Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/bret99/wazuh-vkteams-ai-bot.git
cd wazuh-vkteams-ai-bot
```

### 3. Configuration

Copy the example configuration file and set your credentials:

```bash
cp config/access_tokens.py.example config/access_tokens.py
```

Edit `config/access_tokens.py`:

```python
VK_TEAMS_TOKEN = "your_vk_teams_bot_token"
VK_TEAMS_API_URL = "[https://myteam.mail.ru/bot/v1](https://myteam.mail.ru/bot/v1)"

WAZUH_HOST = "http://localhost:9200"
WAZUH_USER = "admin"
WAZUH_PASS = "your_wazuh_password"

AI_KEY = "your_ai_api_key"
AI_URL = "https://example-ai.com/api/v1/chat/completions" # substitute for actual one
AI_MODEL = "qwen/qwen3.7-plus" # substitute for actual one
```

### 4. Running the Bot

Start the service using Python:

```bash
python3 wazuh_vkteams_bot.main
```

---

## 🛠️ Usage Example

1. Open a conversation with the bot in **VK Teams**.
2. Send `/start` to open the main menu.
3. Select **👤 User activity** or **💻 Host activity**.
4. Enter the target entity name (e.g., `j.doe` or `srv-db-01`).
5. Choose the time timeframe (`1 hour`, `24 hours`, `7 days`, etc.).
6. Confirm sending the filtered telemetry payload to the AI Copilot for analysis.

---

## 💎 Support the Project

If this tool helps protect your infrastructure, consider supporting the developer! 

### Crypto Wallets
| Asset | Network | Address |
| :--- | :--- | :--- |
| **BTC** | Bitcoin | `bc1qjwl80sv06xj2yhumn6k6xemchryem923wwts5x` |
| **USDT / ETH** | Ethereum (ERC20) | `0xc01b996c7b08ccfad463f27e54f1e74e6ac6f9ff` |
| **USDT / SOL** | Solana | `D7a5CdLaDwkKehnH82y6VJEF3hADWuupuhWCXecHvEnt` |
| **TON** | TON Network | `UQBhPLwdFiJdh6sZ96sZfxrxD9Lu6NFtaUecWeoHSM-EPc0P` |
| **LTC** | Litecoin | `ltc1qkm58ks5kuc64rjwd74sfalc5xsn7h6sr4vt45w` |
| **SOL** | Solana | `D7a5CdLaDwkKehnH82y6VJEF3hADWuupuhWCXecHvEnt` |

---

📜 License

This project is licensed under the MIT License - see the LICENSE file for details.
