# FortiCheck

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

**Security Analysis for FortiGate Firewalls**

FortiCheck is a powerful, offline static analysis tool designed to uncover security risks, misconfigurations, and attack paths in FortiGate firewall configurations. Unlike simple compliance checkers, FortiCheck builds a graph-based model of your network to understand the *intent* and *impact* of your policies.

---

## Key Features

*   **Deep Policy Analysis:** Detects shadow rules, redundancy, and ordering anomalies.
*   **Attack Path Simulation:** Simulates multi-hop attack vectors (e.g., Internet → DMZ → Internal) using graph theory.
*   **Exposure Analysis:** Identifies internal assets exposed to the Internet or other untrusted zones.
*   **User & VPN Auditing:** accurate checks for MFA violations, weak VPN encryption (DES/3DES/MD5), and legacy IKEv1 usage.
*   **Security Profile Gaps:** Finds policies missing critical security profiles (IPS, AV, Web Filter).
*   **Context-Aware Risk Scoring:** Assigns a risk score (0-100) to every finding based on exposure, asset sensitivity, and trust levels.
*   **Professional Reporting:** Generates a self-contained, interactive HTML dashboard suitable for C-level executives and technical teams.

## Installation

Prerequisites: Python 3.11+

**Using requirements.txt**

```bash
git clone https://github.com/cumakurt/forticheck.git
cd forticheck
pip install -r requirements.txt
pip install -e .
```

- `pip install -r requirements.txt` installs the runtime dependencies (click, pydantic, netaddr, networkx, jinja2, rich, pyyaml).
- `pip install -e .` installs FortiCheck in editable mode and registers the `forticheck` command. Use `pip install .` for a normal (non-editable) install.

**Using Poetry**

```bash
git clone https://github.com/cumakurt/forticheck.git
cd forticheck
poetry install
```

**Install from GitHub**

```bash
pip install git+https://github.com/cumakurt/forticheck.git
```

For development (tests, linting), use Poetry or install with dev extras: `pip install -e ".[dev]"`.

## Docker

FortiCheck can be run in a container without installing Python or dependencies on the host. You only need Docker installed.

### Build the image

From the project root:

```bash
git clone https://github.com/cumakurt/forticheck.git
cd forticheck
make docker-build
# or: docker build -t forticheck:latest .
```

### Quick start

Place your FortiGate config in the current directory, mount it as `/workspace`, and run:

```bash
# Config and report in current directory (recommended)
docker run --rm -v "$(pwd):/workspace" forticheck:latest analyze -c sample_fortigate.conf -o /workspace/report.html
# Report: ./report.html
```

### Where reports are written

The container uses `/workspace` as the working directory. **You must mount your current directory** so the config file is visible and the report is written to your host:

| Goal | Mount | Config | Output |
|------|--------|--------|--------|
| Current directory | `-v $(pwd):/workspace` | `-c sample.conf` or `-c /workspace/sample.conf` | `-o /workspace/report.html` |
| `/tmp` on host | `-v /tmp:/tmp` | Config must be in `/tmp` | `-o /tmp/report.html` |

> **Note:** On some systems, writing to `/tmp` may cause permission errors. Prefer `/workspace` (current directory) for output.

### Example: Using Make

```bash
make docker-build
make docker-run CONFIG=sample_fortigate.conf
# Report: ./forticheck_report.html (default)

make docker-run CONFIG=sample_fortigate.conf OUTPUT=audit.html
# Report: ./audit.html
```

### Example: Report in current directory

```bash
docker run --rm -v "$(pwd):/workspace" forticheck:latest analyze -c /workspace/fortigate.conf -o /workspace/audit_report.html
# Report: ./audit_report.html
```

### Example: Report in /tmp

```bash
cp /path/to/fortigate.conf /tmp/
docker run --rm -v /tmp:/tmp forticheck:latest analyze -c /tmp/fortigate.conf -o /tmp/forticheck_report.html
# Report on host: /tmp/forticheck_report.html
```

### Example: HTML and JSON, custom trust, custom rules

Mount a directory that contains your config, optional `trust_levels.yaml`, and optional `custom_rules.yaml`. Output is written to the same directory.

```bash
docker run --rm -v "$(pwd):/workspace" forticheck:latest analyze \
  -c /workspace/fortigate.conf \
  -o /workspace/audit \
  -f both \
  --zones-trust /workspace/trust_levels.yaml \
  --rules /workspace/custom_rules.yaml
# Creates: ./audit.html and ./audit.json
```

### Example: Config diff with Docker

Mount a directory containing both configs; output the diff JSON to the same directory.

```bash
docker run --rm -v "$(pwd):/workspace" forticheck:latest diff \
  --before /workspace/old.conf \
  --after /workspace/new.conf \
  -o /workspace/diff_result.json
```

### Docker run options summary

| Option | Description |
|--------|-------------|
| `--rm` | Remove the container after the run (recommended). |
| `-v $(pwd):/workspace` | Mount current directory; config and report paths use your local files. |
| `-v /tmp:/tmp` | Mount `/tmp` (optional) for output to host's `/tmp`. |
| `-c file.conf` | Config path (relative to `/workspace` when mounted). |
| `-o /workspace/report.html` | Output path; use `/workspace/` to write to current directory. |

## Usage

FortiCheck runs entirely offline. You only need a configuration backup file (`.conf`) from your FortiGate device.

### Commands

| Command | Description |
|---------|-------------|
| `forticheck analyze -c CONFIG [options]` | Analyze a FortiGate config and produce an HTML and/or JSON report. |
| `forticheck diff --before OLD --after NEW [-o OUTPUT]` | Compare two configs and output a JSON diff of policies. |
| `forticheck --help` | Show main help. |
| `forticheck analyze --help` | Show all analyze options. |

### Basic analysis

```bash
forticheck analyze -c /path/to/fortigate.conf
```

By default, the report is saved as `{config_filename}_{date}_{time}.html` in the current directory (e.g. `fortigate_2025-02-13_143022.html`).

### Analyze options (summary)

| Option | Short | Description |
|--------|-------|-------------|
| `--config` | `-c` | Path to FortiGate config file (required). |
| `--output` | `-o` | Report file path. Default: `{config_stem}_{YYYY-MM-DD_HHMMSS}.html`. |
| `--format` | `-f` | `html`, `json`, or `both`. Default: `html`. |
| `--zones-trust` | `-z` | YAML file with zone trust levels (0–100). |
| `--rules` | `-r` | YAML file with custom rules (forbid_service, require_security_profile). |
| `--min-severity` | | Only include findings with this severity or higher: `info`, `low`, `medium`, `high`, `critical`. |
| `--verbose` | `-v` | Enable verbose logging. |

### Advanced usage examples

```bash
# HTML + JSON to a specific path
forticheck analyze -c fw.conf -o ./reports/audit_results.html -f both

# Verbose logging for debugging
forticheck analyze -c fw.conf -v

# Custom zone trust levels (improves risk scoring)
forticheck analyze -c fw.conf --zones-trust trust_levels.yaml

# Custom security rules
forticheck analyze -c fw.conf --rules custom_rules.yaml

# Only medium-and-above findings in the report
forticheck analyze -c fw.conf --min-severity medium
```

### Config diff

Compare two configuration files (policy add/remove/change):

```bash
forticheck diff --before old.conf --after new.conf -o forticheck_diff.json
```

### Custom Zone Trust (`trust_levels.yaml`)

Define the trust level (0-100) for your zones to improve analysis accuracy. You can use either a simple `zone_name: value` format or an object with `trust_level`:

```yaml
zones:
  internet: 0
  dmz: 30
  guest: 10
  lan: 90
  servers: 100
  # Alternative format: zone_name: { trust_level: 50 }
```

If the file is missing or invalid, FortiCheck uses built-in default trust levels and continues the analysis.

### Custom Rules (`custom_rules.yaml`)

Optional. Define your own checks (e.g. forbid RDP between zones, require security profiles):

```yaml
rules:
  - id: R1
    type: forbid_service
    zones: [dmz, lan]
    service: RDP
    severity: high
  - id: R2
    type: require_security_profile
    zones: [wan, lan]
    severity: medium
```

## Report Sample

The HTML report provides:
- **Executive Dashboard:** Risk score, critical finding count, and compliance summary.
- **Attack Path Visualization:** Visual representation of how an attacker could move laterally.
- **Detailed Findings:** Actionable remediation steps for every issue.
- **VPN & User Audit:** Dedicated sections for remote access security.

![FortiCheck Report Overview](img/sample.png)

| Executive Summary & Risk Dashboard | Zone Exposure Matrix | CIS Benchmark |
|-----------------------------------|----------------------|---------------|
| ![Sample Report](img/sample2.png) | ![Zone Heatmap](img/zone.png) | ![CIS Compliance](img/cis.png) |

![Network Interfaces](img/interface.png)

## Architecture

FortiCheck processes configurations in 8 layers:
1.  **Parsing:** Converts raw config to AST.
2.  **Normalization:** Builds a vendor-neutral canonical model.
3.  **Topology:** Maps interfaces, routes, and zones into a network graph.
4.  **Logic:** Mathematical analysis of policy sets (intersection/subset).
5.  **Exposure:** Zone-to-zone reachability analysis.
6.  **Simulation:** BFS/DFS based attack path discovery.
7.  **Scoring:** Multi-factor risk calculation.
8.  **Reporting:** Jinja2-based HTML generation.

## Development

```bash
make install-dev    # Install with dev dependencies
make test           # Run tests
make lint           # Run ruff
make typecheck      # Run mypy
make clean          # Remove build artifacts, caches (.pytest_cache, .ruff_cache, etc.)
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request on [GitHub](https://github.com/cumakurt/forticheck).

## Developer

- **Name:** Cuma KURT
- **Email:** [cumakurt@gmail.com](mailto:cumakurt@gmail.com)
- **LinkedIn:** [linkedin.com/in/cuma-kurt-34414917](https://www.linkedin.com/in/cuma-kurt-34414917/)

## License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0-or-later). See [LICENSE](LICENSE) for details.
