<a href="https://github.com/Athexblackhat/athex-vortex"><img src="logo.png" alt="0" border="0" /></a> 

# ⬡ ATHEX VORTEX

**Tunneling & Port Forwarding Suite**  
Expose local servers to the internet with a single click — TCP, UDP, and hybrid forwarding with real‑time monitoring.

[![Python](https://img.shields.io/badge/Python-3.7%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-Proprietary-red)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)]()

---

## 🚀 Overview

ATHEX VORTEX is a cross‑platform port‑forwarding client that creates secure public tunnels to your local services. It features a beautiful web dashboard with WebSocket‑powered live stats, a 3D globe marking active tunnels, and a hardware‑locked licensing system.

> Perfect for developers, gamers, and self‑hosters who need temporary or permanent public access to local applications.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔁 **TCP, UDP & Hybrid Forwarding** | Relay any TCP or UDP traffic — or both simultaneously |
| 🌐 **Public Endpoints** | Each tunnel gets a unique public IP and port |
| 📊 **Live Dashboard** | Real‑time bandwidth graphs, CPU/RAM meters, and event logs |
| 🗺 **Interactive 3D Globe** | Visual markers show active tunnel locations |
| 🔐 **License Protection** | RSA‑2048 signed keys bound to your hardware (HWID) |
| ⚙ **Auto‑Setup** | Installs missing Python dependencies on first run |
| 💾 **Persistent Storage** | SQLite database keeps tunnel history and logs |
| 🖥 **Cross‑Platform** | Tested on Windows and Linux |

---

## 📦 Requirements

- Python **3.7** or higher
- `pip` (Python package manager)
- Internet connection (for initial dependency installation and license validation)

The following packages are **automatically installed** on first run:

```
fastapi  uvicorn[standard]  websockets  cryptography  psutil  rich  aiofiles
```

---

## 🔧 Installation

1. **Clone or download** the repository:

   ```bash
   git clone https://github.com/Athexblackhat/athex-vortex.git
   cd athex-vortex
   ```

2. **Run the client:**

   ```bash
   python run.py
   ```

On first execution the script will:
- Install missing Python packages
- Start the web server at `http://localhost:8770`

---

## 🖥 Usage

1. Open your browser and navigate to `http://localhost:8770`.
2. The dashboard displays your unique **HWID** (hardware fingerprint).
3. **Obtain a license** – Send your HWID to the developer via WhatsApp to purchase a key.
4. **Activate your license** – Paste the received key into the dashboard and click **INSTALL KEY**.
5. **Create a tunnel:**
   - Enter the local port your service is running on (e.g., `8080` for a web server).
   - Select the protocol: **TCP**, **UDP**, or **HYBRID**.
   - Click **LAUNCH TUNNEL**.
6. The tunnel will appear with a public address (e.g., `123.45.67.89:23456`). Share this address with your users.

---

## 🔑 License Activation

- Each license is tied to your machine's **HWID** and cannot be transferred.
- Licenses may be **lifetime** or **time‑limited**.
- The dashboard shows remaining validity and maximum allowed tunnels.

> **To purchase a license, contact the developer via WhatsApp.**

---

## 🧭 Dashboard Sections

| Section | Description |
|---|---|
| **License** | HWID, license status, key installation, WhatsApp purchase link |
| **Create Tunnel** | Input local port and protocol, launch new tunnel |
| **Active Tunnels** | List of running tunnels with live stats and stop button |
| **Live Stats** | CPU, RAM, total in/out traffic, real‑time bandwidth graph |
| **Event Log** | System messages (tunnel created, errors, etc.) |

The **3D globe** in the background rotates and displays glowing markers for each active tunnel.

---

## 📁 Configuration

All data is stored in the script's directory:

| Path | Description |
|---|---|
| `config/config.json` | Web server port (default `8770`) and other settings |
| `config/license.key` | Your installed license key |
| `db/vortex.db` | SQLite database of tunnels and events |
| `logs/` | Reserved for future logging |

---

## 🛠 Troubleshooting

| Issue | Solution |
|---|---|
| Port already in use | Stop the tunnel and create a new one — a fresh random port is assigned |
| Cannot connect from outside | Ensure your OS firewall allows inbound connections on the public port |
| License invalid / expired | Check that the key was pasted completely; if expired, renew your license |
| Dependencies fail to install | Run manually: `pip install fastapi uvicorn[standard] websockets cryptography psutil rich aiofiles` |

---

## 🔒 Security Notes

- **Public endpoints** are simulated IPs derived from the tunnel ID — they are not real internet‑routable addresses. This tool is intended for local testing and controlled environments.
- **License keys** are RSA‑2048 signed and verified (public key must be present in `config/public.pem`).
- **Traffic is unencrypted** between the public endpoint and your local service. Do not use for sensitive data unless you add TLS yourself.

---

## 📞 Support & Licensing

For license purchase, feature requests, or support — contact via **WhatsApp**.

---

## ⚠️ Disclaimer

ATHEX VORTEX is proprietary software. Unauthorised distribution, modification, or use without a valid license is prohibited.  

The developer assumes no liability for misuse of this tool.