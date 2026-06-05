# RBOM-PUBLIC
The implementation of RBOM into SCION infrastructure.
The code is based on [the SCION implementation](https://github.com/netsec-ethz/scion).

## Installation 

Installation packages for Debian and derivatives are available for x86-64, arm64, x86-32 and arm.
These packages can be found in the [latest release](https://github.com/scionproto/scion/releases/latest).
Packages for in-development versions can be found from the [latest nightly build](https://buildkite.com/scionproto/scion-nightly/builds/latest).

Alternatively, "naked" pre-built binaries are available for Linux x86-64 and
can be downloaded from the [latest release](https://github.com/scionproto/scion/releases/latest) or the
[latest nightly build](https://buildkite.com/scionproto/scion-nightly/builds/latest).

SCION-RBOM is implemented fom [SCION Quantum](https://github.com/juagargi/quantum.git).

## Hardware details
- OS: Installation on Ubuntu 22.04 Laptop.
- CPU arch: AMD64. We did not tested on Arm cpu such as Apple Silicon.
- CPU Hardware: Intel Core i7.
- RAM: 16 GB.
- DISK: 256 GB

## Ubuntu 22.04 version details
```
lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 22.04.5 LTS
Release:	22.04
Codename:	jammy

```
Update & upgrade
```
sudo apt update
sudo apt upgrade

```


### Requirements

```
sudo apt update
sudo apt upgrade

sudo apt install wget
sudo apt install golang-go
go version

sudo apt install default-jdk
sudo apt install locate
updatedb

sudo apt-get install -y graphviz python3-graphviz
sudo apt install python3-pip
pip install pyyaml toml plumbum

sudo apt-get install -y libsqlite3-dev gcc

sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r) libelf-dev
sudo apt install -y linux-tools-common linux-tools-$(uname -r)
bpftool version

sudo apt-get install -y build-essential cmake git pkg-config libssl-dev ninja-build
sudo apt-get install -y supervisor

```
### Docker
```
sudo apt install apt-transport-https ca-certificates curl software-properties-common

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
apt-cache policy docker-ce
sudo apt install docker-ce

sudo apt-get install docker-compose-plugin
sudo systemctl status docker

sudo apt-get update
sudo groupadd docker

# Add your user to docker group
sudo usermod -aG docker $USER
sudo usermod -aG docker #YourUsername

# Verify it's added to system
getent group docker

# Update the configuration
newgrp docker
groups
```
Close the terminal and open it again.

Verify if your username is added into  docker group.

If not add again with below commands

```
sudo usermod -aG docker YourUsername
newgrp docker
groups
```
Running initial docker instance
```
sudo systemctl status docker

# Wait for docker to download the hello prg
docker run hello-world     
```

### Bazel

```
sudo apt install apt-transport-https curl gnupg -y
curl -fsSL https://bazel.build/bazel-release.pub.gpg | gpg --dearmor >bazel-archive-keyring.gpg

sudo mv bazel-archive-keyring.gpg /usr/share/keyrings

echo "deb [arch=amd64 signed-by=/usr/share/keyrings/bazel-archive-keyring.gpg] https://storage.googleapis.com/bazel-apt stable jdk1.8" | sudo tee /etc/apt/sources.list.d/bazel.list

sudo apt update && sudo apt install bazel

bazel --version

```


### Install liboqs and liboqs-go

Build and install liboqs

```
cd ~
mkdir tmp
cd tmp/
# Clean up if exists
rm -rf liboqs  

# Clone repository
git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git
cd liboqs

# Configure
mkdir -p build && cd build

cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON ..

# Compile (takes 2-8 minutes)
ninja

# Install
sudo ninja install
sudo ldconfig

```
Verify liboqs
```
# Check installation
ldconfig -p | grep liboqs
pkg-config --modversion liboqs
```
Set up liboqs-go

```
cd /tmp
# Clean up if exists
rm -rf liboqs-go  

# Clone repository
git clone --depth 1 https://github.com/open-quantum-safe/liboqs-go.git
cd liboqs-go
```
Create pkg-config file
```
sudo mkdir -p /usr/local/lib/pkgconfig
```
```
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
```

Verify the last command input.
```
nano /usr/local/lib/pkgconfig/liboqs-go.pc 
## exit nano
ctrl+x
```
Update environment.
```
# Add to ~/.bashrc
echo '' >> ~/.bashrc
echo '# liboqs and liboqs-go pkg-config path' >> ~/.bashrc
echo 'export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH"' >> ~/.bashrc

# Reload
source ~/.bashrc
```
Final verification.
```
pkg-config --modversion liboqs
pkg-config --cflags liboqs-go
ldconfig -p | grep liboqs

## output
owner@owner:~$ pkg-config --modversion liboqs
0.15.0
owner@owner:~$ pkg-config --cflags liboqs-go
-I/usr/local/include
owner@owner:~$ ldconfig -p | grep liboqs
	liboqs.so.9 (libc6,x86-64) => /usr/local/lib/liboqs.so.9
	liboqs.so (libc6,x86-64) => /usr/local/lib/liboqs.so
owner@owner:~$ 


```
Clean up

```
cd /tmp
rm -rf liboqs liboqs-go

```



## SCION-RBOM Installation

If you have existing SCION running, then stop all current SCION and docker containers; else move to Build.
```
./scion.sh stop
docker ps
docker stop $(docker ps -a -q)
```

Verify if your username is in docker group.
If not, add your username in docker group.

```
groups
sudo usermod -aG docker YourUsername

newgrp docker
groups
```

### Build
```
cd ~

git clone https://github.com/CNK2100/RBOM-PUBLIC/
cd SCION-SBOM-DEV/
cd scion-sbom
```
If you get an error: e.g., "the project you're trying to build requires Bazel 6.4.0", but it wasn't found in /usr/bin. Then install the correct Bazel version 6.4.0.
```
sudo apt update && sudo apt install bazel-6.4.0
bazel version

./tools/install_bazel
# If you get "Permission denied error" then do below
cd ..
chmod +x -R ./scion-sbom
cd scion-sbom
./tools/install_bazel

# Install extra dependencies: plumbum-1.6.9 pyyaml-6.0.1 setuptools-69.1.0 six-1.15.0 supervisor-4.2.5 supervisor-wildcards-0.1.3

./tools/install_deps

./scion.sh bazel-remote

# If you get permission denied error. Verify first if your user is added in Docker group as of above.
# Then try again

sudo ./scion.sh bazel-remote


```
Wait for 3 sec and if you see no container running, then try again above command. 

Below  is the output:
```
 ./scion.sh bazel-remote
WARN[0000] /bazel-remote.yml: the attribute `version` is obsolete, it will be ignored, please remove it to avoid potential confusion 
WARN[0000] No services to build                         
[+] up 1/1
 ✔ Container bazel-remote-cache Running
``` 

Check SCION documentation to either build all the packages or  build only needed SCION services.

https://docs.scion.org/en/latest/dev/build.html


Below "make" command will run for about 3 to 8 minutes depending on your PC specs.
```
make

## proto files are used to create new *.pb.go files
make protobuf   

make test
# if you get serrors, run below and make test again
$(bazel info output_base)/external/go_sdk/bin/go test ./pkg/private/serrors/... -update
make test


# Optional make test-integration. 
# May get error due to the low-speed downloading "@openwrt_x86_64_SDK".
# Just move to the Running  SCION-RBOM Section.

make test-integration
```

## Running SCION-RBOM


```
# Locate in scion-sbom folder if not already.
cd ~
cd scion-sbom
# Below initial command will take  2 to 5 min depending on your specs.
# Next time it will run faster.

make docker-images

## if make docker-images does not run then run first ./scion.sh bazel-remote.
Then run again make docker-images
```
### Run a desired Scion topology

```
./scion.sh topology -c topology/tiny4.topo
```
### Adding StaticInfoConfig to ASes.
The "staticInfoConfig.json" will be updated automatically after collecting SBOM & VEX info using RBOM python program.

For more details about StaticInfoConfig read [here](https://docs.scion.org/en/latest/manuals/control.html#control-conf-path-metadata).

```
cd ..
cp ./sbom-gen/staticInfoConfig.json ./scion-sbom/gen/ASff00_0_110/
cd scion-sbom
```
### Start SCION
```
./scion.sh run
```
Testing the SCION network
```
bin/end2end_integration
bin/scion showpaths --sciond $(./scion.sh sciond-addr 112) 1-ff00:0:110
```
If you want to see extended details for the command showpaths just add --extended

```
bin/scion showpaths --extended --sciond $(./scion.sh sciond-addr 112) 1-ff00:0:110

```
Output with SBOM, Vulnerabilities, Fixed, Affected
```
bin/scion showpaths --extended --sciond $(./scion.sh sciond-addr 112) 1-ff00:0:110
Available paths to 1-ff00:0:110
2 Hops:
[0] Hops: [1-ff00:0:112 ~~ 1>2 1-ff00:0:110 ~~]
    MTU: 1400
    NextHop: 127.0.0.25:31012
    PQC-secured: true
    Expires: 2026-02-24 11:54:13 +0000 UTC (5h59m41s)
    Latency: 40ms
    CarbonIntensity: 400gCO2/TB
    Sbom: 455725
    Vuln: 39576
    Fixed: 27173
    Affected: 12326
    Notes: [1-ff00:0:110: "asdf"]
    SupportsEPIC: false
    Status: alive
    LocalIP: 127.0.0.1

```

Testing the path from 112 to another AS 1-ff00:0:111 with different.
SBOM values will update for this link.

```
bin/scion showpaths --extended --sciond $(./scion.sh sciond-addr 112) 1-ff00:0:111
Available paths to 1-ff00:0:111
3 Hops:
[0] Hops: [1-ff00:0:112 ~~ 1>2 1-ff00:0:110 ~~ 1>41 1-ff00:0:111 ~~]
    MTU: 1280
    NextHop: 127.0.0.25:31012
    PQC-secured: true
    Expires: 2026-02-24 12:20:33 +0000 UTC (5h56m32s)
    Latency: 80ms
    CarbonIntensity: 1480gCO2/TB
    Sbom: 1367175
    Vuln: 118728
    Fixed: 81519
    Affected: 36978
    InternalHops: [1-ff00:0:110: 2]
    Notes: [1-ff00:0:110: "asdf"]
    SupportsEPIC: false
    Status: alive
    LocalIP: 127.0.0.1

```

### Generate an image of any SCION topology located in /topology/ folder

Generate the topology image. You can also save the image on your PC.
```
./scion.sh topodot -s topology/peering-test.topo
./scion.sh topodot -s topology/peering-test-multi.topo
./scion.sh topodot -s topology/tiny.topo
./scion.sh topodot -s topology/tiny4.topo
./scion.sh topodot -s topology/wide.topo
./scion.sh topodot -s topology/default.topo
./scion.sh topodot -s topology/default-no-peers.topo

```
Stop Scion
```
./scion.sh stop
```

### Troubleshooting

Optional: If you encouter errors during new installation; you may clean the previous SCION.
```
make clean
bazel clean
## Not recommanded!!! : remove entire Bazel directory
rm -rf ~/.cache/bazel
```

## SBOM GENERATION
### Syft and Grype installation
```
curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin
curl -sSfL https://get.anchore.io/grype | sudo sh -s -- -b /usr/local/bin
grype db update
grype db status
```
Then locate to the sbom-gen folder
```
cd ..
cd sbom-gen
python3 ./rbom.py
```
RBOM will generate an SBOM of the whole system; will conduct a vulnerability scan; will provide VEX evaluation; and will generate a security score.
Any needed attribute could be included in SCION AS information (e.g., SBOM as of above).

## About

For reporting bugs, you can submit an issue to the GitHub repository.



