# RBOM-PUBLIC

**RBOM (Router Bill of Materials)** is a security framework that integrates Software Bill of Materials (SBOM) and vulnerability intelligence into the [SCION](https://github.com/netsec-ethz/scion) next-generation networking architecture. It enables risk-aware path selection by evaluating the software security posture of border routers and deprioritizing paths that traverse devices with known, unpatched vulnerabilities.

This implementation is built on top of [SCION Quantum](https://github.com/juagargi/quantum.git).

> **Research paper:** *RBOM: Path-Level Security Assessment in Inter-domain Networks Using Router SBOMs*

---

## Overview

Modern routing infrastructure lacks visibility into the software integrity of transit routers. RBOM addresses this gap by:

1. Generating signed SBOMs for each router.
2. Performing CVE analysis and VEX filtering.
3. Computing a risk score per router using a weighted hybrid evaluation model
4. Injecting risk metadata into SCION's control plane beaconing via `StaticInfoConfig`
5. Enabling path selection that avoids high-risk routers

RBOM operates without requiring new hardware and maintains backward compatibility with existing SCION deployments.

---

## System Requirements

| Component | Requirement |
|-----------|-------------|
| OS | Ubuntu 22.04 LTS (x86-64) |
| CPU | Intel/AMD x86-64 (ARM not tested) |
| RAM | 16 GB minimum |
| Disk | 256 GB minimum |
| Go | 1.21+ |
| Java | JDK 17+ |
| Bazel | 6.4.0 |

---

## Installation

### 1. System dependencies

```bash
sudo apt update && sudo apt upgrade -y

sudo apt install -y wget golang-go default-jdk locate graphviz python3-graphviz \
  python3-pip libsqlite3-dev gcc clang llvm libbpf-dev linux-headers-$(uname -r) \
  libelf-dev linux-tools-common linux-tools-$(uname -r) \
  build-essential cmake git pkg-config libssl-dev ninja-build supervisor

pip install pyyaml toml plumbum
```

### 2. Docker

```bash
sudo apt install -y apt-transport-https ca-certificates curl software-properties-common

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update && sudo apt install -y docker-ce docker-compose-plugin

# Add your user to the docker group
sudo usermod -aG docker $USER
newgrp docker
```

Verify Docker is running:
```bash
docker run hello-world
```

### 3. Bazel 6.4.0

```bash
sudo apt install -y apt-transport-https curl gnupg

curl -fsSL https://bazel.build/bazel-release.pub.gpg | gpg --dearmor > bazel-archive-keyring.gpg
sudo mv bazel-archive-keyring.gpg /usr/share/keyrings

echo "deb [arch=amd64 signed-by=/usr/share/keyrings/bazel-archive-keyring.gpg] \
  https://storage.googleapis.com/bazel-apt stable jdk1.8" | \
  sudo tee /etc/apt/sources.list.d/bazel.list

sudo apt update && sudo apt install -y bazel-6.4.0
bazel version
```

### 4. Post-quantum cryptography libraries (liboqs)

```bash
# Build and install liboqs
cd /tmp
git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir -p build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON ..
ninja && sudo ninja install && sudo ldconfig

# Set up liboqs-go bindings
cd /tmp
git clone --depth 1 https://github.com/open-quantum-safe/liboqs-go.git

sudo mkdir -p /usr/local/lib/pkgconfig
sudo tee /usr/local/lib/pkgconfig/liboqs-go.pc > /dev/null << 'EOF'
prefix=/usr/local
exec_prefix=${prefix}
libdir=${exec_prefix}/lib
includedir=${prefix}/include

Name: liboqs-go
Description: Go bindings for liboqs
Version: 1.0.0
Requires: liboqs
Cflags: -I${includedir}
Libs: -L${libdir} -loqs
EOF

# Add pkg-config path to shell environment
echo 'export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH"' >> ~/.bashrc
source ~/.bashrc

# Verify
pkg-config --modversion liboqs
ldconfig -p | grep liboqs

# Clean up
cd /tmp && rm -rf liboqs liboqs-go
```

---

## Building SCION-RBOM

If a prior SCION instance is running, stop it first:
```bash
./scion.sh stop
docker stop $(docker ps -a -q)
```

Clone and build:
```bash
cd ~
git clone https://github.com/CNK2100/SCION-SBOM-DEV
cd SCION-SBOM-DEV/scion-sbom

# Install Bazel wrapper and dependencies
chmod +x -R .
./tools/install_bazel
./tools/install_deps

# Start Bazel remote cache
./scion.sh bazel-remote
```

Expected output:
```
[+] up 1/1
 Container bazel-remote-cache  Running
```

Build the project (3 to 8 minutes depending on hardware):
```bash
make
make protobuf
make test
```

Build Docker images:
```bash
make docker-images
```

For full build documentation, see the [SCION build guide](https://docs.scion.org/en/latest/dev/build.html).

---

## Running SCION-RBOM

### 1. Start a topology

```bash
./scion.sh topology -c topology/tiny4.topo
```

### 2. Attach RBOM metadata to an AS

Copy the RBOM-generated `staticInfoConfig.json` to the target AS directory before starting SCION. This file is produced automatically by the RBOM pipeline (see [SBOM Generation](#sbom-generation)).

```bash
cp ../sbom-gen/staticInfoConfig.json gen/ASff00_0_110/
```

For details on `StaticInfoConfig`, see the [SCION control plane documentation](https://docs.scion.org/en/latest/manuals/control.html#control-conf-path-metadata).

### 3. Start SCION

```bash
./scion.sh run
```

### 4. Verify connectivity

```bash
bin/end2end_integration
bin/scion showpaths --sciond $(./scion.sh sciond-addr 112) 1-ff00:0:110
```

### 5. Inspect RBOM path metadata

Use `--extended` to view SBOM and vulnerability fields on each path:

```bash
bin/scion showpaths --extended --sciond $(./scion.sh sciond-addr 112) 1-ff00:0:110
```

Example output:
```
Available paths to 1-ff00:0:110
2 Hops:
[0] Hops: [1-ff00:0:112 ~~ 1>2 1-ff00:0:110 ~~]
    MTU:              1400
    NextHop:          127.0.0.25:31012
    PQC-secured:      true
    Expires:          2026-02-24 11:54:13 +0000 UTC (5h59m41s)
    Latency:          40ms
    CarbonIntensity:  400gCO2/TB
    Sbom:             455725
    Vuln:             39576
    Fixed:            27173
    Affected:         12326
    Status:           alive
```

The `Sbom`, `Vuln`, `Fixed`, and `Affected` fields reflect the RBOM security assessment for each path hop.

### 6. Stop SCION

```bash
./scion.sh stop
```

---

## SBOM Generation

Install the SBOM and vulnerability scanning tools:

```bash
curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin
curl -sSfL https://get.anchore.io/grype | sudo sh -s -- -b /usr/local/bin
grype db update
```

Run the RBOM pipeline:

```bash
cd ~/SCION-SBOM-DEV/sbom-gen
python3 ./rbom.py
```

The pipeline performs the following steps automatically:

1. Generates a full system SBOM (CycloneDX JSON format)
2. Scans for CVEs
3. Applies VEX exploitability filtering
4. Computes a composite security score per router
5. Outputs an updated `staticInfoConfig.json` for injection into the SCION control plane

---

## Topology Visualization

Generate a `.dot` graph image of any topology file:

```bash
./scion.sh topodot -s topology/tiny4.topo
./scion.sh topodot -s topology/wide.topo
./scion.sh topodot -s topology/default.topo
```

---

## Troubleshooting

**Build errors after source changes:**
```bash
bazel clean --expunge
make
```

**Stale Bazel cache:**
```bash
bazel clean
# Only if necessary -- removes entire cache
rm -rf ~/.cache/bazel
```

**Docker permission errors:**
```bash
sudo usermod -aG docker $USER
newgrp docker
```

**Bazel version mismatch:** Install the exact required version explicitly:
```bash
sudo apt install bazel-6.4.0
```

---

## Repository Structure

```
SCION-SBOM-DEV/
├── scion-sbom/          # Modified SCION source with RBOM extensions
│   ├── topology/        # Network topology definitions
│   └── gen/             # Generated AS configurations
└── sbom-gen/            # RBOM pipeline
    ├── rbom.py          # Main pipeline script
    └── staticInfoConfig.json  # Generated SCION path metadata
```

---

## Related Work

RBOM is built on top of the following projects:

- [SCION](https://github.com/netsec-ethz/scion) by ETH Zurich Network Security Group
- [SCION Quantum](https://github.com/juagargi/quantum.git) (post-quantum SCION extensions)
- [Syft](https://github.com/anchore/syft) (SBOM generation)
- [Grype](https://github.com/anchore/grype) (vulnerability scanning)
- [liboqs](https://github.com/open-quantum-safe/liboqs) (post-quantum cryptography)

---

## Contributing and Issues

Bug reports and contributions are welcome. Please open an issue on the GitHub repository.

---

## License

See [LICENSE](LICENSE) for details.
