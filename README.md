# 🔒 PCI-DSS Segmentation Scanner

A fast, automated tool to verify network segmentation between **Non-CDE** and **CDE** environments for PCI-DSS compliance.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Shell](https://img.shields.io/badge/shell-bash-green.svg)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey.svg)

---

## 🎯 What It Does

Tests network isolation between your **Non-Cardholder Data Environment** and **Cardholder Data Environment** by:

1. **Scanning** all 65,535 ports on CDE targets from your Non-CDE source
2. **Verifying** discovered ports with Nmap for accurate service detection
3. **Generating** a professional HTML report ready for PCI-DSS audits

> **PCI-DSS Requirement 11.4.5**: Organizations must perform segmentation penetration testing to verify that out-of-scope systems cannot access CDE systems.

---

## ⚡ Quick Start

### 1. Install Dependencies

```bash
# Auto-install (recommended)
./install_deps.sh

# Or install manually
# macOS:  brew install masscan nmap
# Debian: sudo apt install masscan nmap
# RHEL:   sudo dnf install masscan nmap
```

### 2. Configure Targets

```bash
# Copy the example file
cp config/targets.example.txt config/targets.txt

# Edit with your CDE IP ranges (one per line)
nano config/targets.txt
```

Example `targets.txt`:
```
10.100.50.0/24
10.100.51.0/24
192.168.200.0/27
```

### 3. Run the Scan

```bash
sudo ./cde_scan.sh
```

You'll be prompted to enter your **source segment** (Non-CDE range) for the report.

---

## 📋 Features

| Feature | Description |
|---------|-------------|
| 🚀 **Fast Scanning** | Uses Masscan for high-speed port discovery (up to 10M pps) |
| 🔍 **Nmap Verification** | Validates findings with service/version detection |
| 💾 **Session Resume** | Pick up where you left off if interrupted |
| 📊 **HTML Reports** | Professional PCI-DSS compliant audit report |
| 🎯 **Target-by-Target** | Scans each subnet individually for better tracking |

---

## 🔄 Resume Interrupted Scans

If your scan is interrupted (Ctrl+C, network issue, etc.):

```bash
sudo ./cde_scan.sh --resume
```

The scanner remembers which targets were completed and continues from where it stopped.

---

## 📁 Output Structure

```
scan_results/
└── sessions/
    └── 10_240_32_0_21/              # Named by source segment
        ├── per_target/              # Individual scan results
        │   ├── 10_100_50_0_24.json
        │   ├── 10_100_50_0_24.xml
        │   └── ...
        ├── nmap_verification/       # Nmap validation results
        ├── summary.md               # Markdown summary
        ├── console.log              # Full console output
        └── *_pcidss_report.html     # 📄 PCI-DSS Audit Report
```

---

## ⚙️ Command Options

| Option | Description | Default |
|--------|-------------|---------|
| `--resume` | Resume previous session | - |
| `--rate <N>` | Packets per second | 1000 |
| `--ports <RANGE>` | Port range to scan | 0-65535 |
| `--no-nmap` | Skip Nmap verification | false |
| `--help` | Show help message | - |

### Examples

```bash
# Full scan (all ports)
sudo ./cde_scan.sh

# Fast scan with higher rate
sudo ./cde_scan.sh --rate 5000

# Scan only common ports
sudo ./cde_scan.sh --ports 1-1024

# Skip Nmap verification
sudo ./cde_scan.sh --no-nmap
```

---

## 🛡️ Exclusions

To exclude specific IPs from scanning, edit `config/exclude.txt`:

```
# Exclude critical infrastructure
10.100.50.1
10.100.50.2
```

---

## 📊 Sample Report Output

The HTML report includes:

- **Executive Summary** - Pass/Fail status with key metrics
- **Scope Details** - Source and target ranges, scan parameters
- **Findings Table** - All open ports with services detected
- **Compliance Notes** - PCI-DSS specific recommendations

---

## 🔧 Troubleshooting

### "Permission denied"
```bash
sudo ./cde_scan.sh  # Must run as root
```

### "masscan: not found"
```bash
./install_deps.sh  # Install dependencies
```

### Scan is too slow
```bash
sudo ./cde_scan.sh --rate 5000  # Increase rate (careful on production)
```

---

## ⚠️ Legal Notice

**IMPORTANT**: Only scan networks you are **explicitly authorized** to test.

Unauthorized scanning may violate:
- Computer Fraud and Abuse Act (US)
- Computer Misuse Act (UK)
- Similar laws in your jurisdiction

---

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

<p align="center">
  Made with ❤️ for PCI-DSS Compliance
</p>
# PCIDSS-Segmentation-Scanner
