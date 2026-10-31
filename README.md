# NucMap-scripts

[![License: MIT](https://img.shields.io/badge/License-MIT-emerald?style=flat-square)](LICENSE)
[![NucMap](https://img.shields.io/badge/Companion-NucMap-06b6d4?style=flat-square)](https://github.com/johestephan/NucMap)

Custom **Nmap Scripting Engine (NSE)** scripts, **ProjectDiscovery Nuclei** templates, and auxiliary detection scripts designed for [**NucMap**](https://github.com/johestephan/NucMap).

---

## 🗂️ Repository Structure

```text
NucMap-scripts/
├── LICENSE                                 # MIT License
├── README.md                               # Repository documentation
├── nse/                                    # Custom Nmap Scripting Engine (.nse) Lua scripts
│   ├── ssl-emudhra-compromise.nse          # Detects compromised eMudhra Intermediate CAs (CVE-2026-111943)
│   ├── php-php2shell.nse                   # Detects PHP2Shell RCE vulnerabilities (CVE-2026-109618, CVE-2026-109619)
│   └── nucmap-template.nse                 # Starter NSE template for NucMap
├── nuclei/                                 # Custom ProjectDiscovery Nuclei (.yaml) templates
│   ├── ssl-emudhra-compromise.yaml         # Nuclei SSL template for compromised eMudhra CAs
│   └── php-php2shell.yaml                  # Nuclei template for PHP2Shell detection
├── scripts/                                # Auxiliary audit & deployment helpers
│   ├── audit-emudhra-truststore.sh         # Local trust-store & PEM bundle auditor for eMudhra CAs
│   └── audit-php2shell.sh                  # Local and remote PHP version auditor for PHP2Shell
└── research/                               # (Git-ignored) Local research notes, advisories, and PCAPs
```

---

## 🔍 Available Scripts & Templates

### 1. eMudhra Compromised Intermediate CA Scanner (`CVE-2026-111943` / Bug 2083449)
Detects TLS/SSL services presenting certificates issued by or chaining to the **8 compromised eMudhra (emSign) Intermediate CAs** (16 certificates total across native `emSign Root G3` and `Sectigo AAA Certificate Services` cross-signed hierarchies) or distrusted eMudhra G3 roots.

* **Nmap NSE Script (`nse/ssl-emudhra-compromise.nse`)**:
  ```bash
  # Scan a target for compromised eMudhra certificates:
  nmap -sV -p 443,8443 --script ./nse/ssl-emudhra-compromise.nse <TARGET>

  # Show certificate issuer details even when the target is not vulnerable:
  nmap -sV -p 443 --script ./nse/ssl-emudhra-compromise.nse --script-args ssl-emudhra-compromise.showall=1 <TARGET>
  ```
* **Nuclei Template (`nuclei/ssl-emudhra-compromise.yaml`)**:
  ```bash
  nuclei -u <TARGET>:443 -t ./nuclei/ssl-emudhra-compromise.yaml
  ```
* **Local Trust Store Auditor (`scripts/audit-emudhra-truststore.sh`)**:
  ```bash
  # Audit default system trust stores (/etc/ssl/certs, /usr/share/ca-certificates):
  ./scripts/audit-emudhra-truststore.sh

  # Audit a custom PEM bundle or directory (e.g., Python certifi or app certs):
  ./scripts/audit-emudhra-truststore.sh /path/to/certs
  ```

---

## 🛠️ Installing into Nmap & NucMap

To make custom `.nse` scripts globally available to Nmap and **NucMap**:

```bash
sudo cp nse/*.nse /usr/share/nmap/scripts/
sudo nmap --script-updatedb
```

---

## 📄 License

Distributed under the **MIT License** (matching NucMap). See [`LICENSE`](LICENSE) for full details.
