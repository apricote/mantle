# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Security

### Added

- `DefaultUser` parameter when registering a test to use a user different from `core` ([#424](https://github.com/flatcar/mantle/pull/424))
- `systemd.sysext.custom-oem` for testing the activation of the OEM sysext image ([#423](https://github.com/flatcar/mantle/pull/423))
- Kubernetes 1.27 tests ([#441](https://github.com/flatcar/mantle/pull/441))
- Add tests for testing the installation/integrity of the NVIDIA drivers ([#433](https://github.com/flatcar/mantle/pull/433))
- `--azure-disk-controller` parameter for selecting a disk controller for an Azure VM ([#517](https://github.com/flatcar/mantle/pull/517))

### Changed

- Some tests dealing with OEM partition were duplicated or adapted for the OEM partition mountpoint move. The older versions of Flatcar will run tests for the old mountpoint location, the new enough versions - for both mountpoint locations. ([#423](https://github.com/flatcar/mantle/pull/423))
- The `systemd.sysext.custom-docker` test now tries to figure out the distributed Docker version by searching for both `app-emulation/docker` and `app-containers/docker` package information. The older versions of Flatcar use the former, the new versions will use the latter ([#438](https://github.com/flatcar/mantle/pull/438))
- DigitalOcean now supports deleting images with the same name ([#440](https://github.com/flatcar/mantle/pull/440))

### Removed

### Fixed
- Remove /etc/samba with an -f option in `cl.overlay.cleanup` for samba 4.18+ ([#455](https://github.com/flatcar/mantle/pull/455))

## [v0.20.0] - 16/03/2023
### Security
- mod: Update golang.org/x/text to 0.3.8 ([#400](https://github.com/flatcar/mantle/pull/400))

### Added
- AMI publishing on the AWS Marketplace ([#369](https://github.com/flatcar-linux/mantle/pull/369))
- plume: generate AMI ID files locally ([#373](https://github.com/flatcar/mantle/pull/373))
- Kola test for devcontainer ([#367](https://github.com/flatcar-linux/mantle/pull/367))
- `--qemu-grow-base-disk-by` flag to grow the base disk ([#367](https://github.com/flatcar-linux/mantle/pull/367))
- `--force-flatcar-key` flag to force injecting the Flatcar production key when testing the Flatcar update with `cl.update.payload` ([#398](https://github.com/flatcar/mantle/pull/398))
- kubernetes 1.26.0 tests ([#406](https://github.com/flatcar/mantle/pull/406))
- new flags `--devcontainer-binhost-url`, `--devcontainer-url` and `--devcontainer-file` to customize devcontainer tests ([#419](https://github.com/flatcar/mantle/pull/419))

### Changed
- organization renaming (`flatcar-linux` -> `flatcar`) ([#372](https://github.com/flatcar/mantle/pull/372), [#374](https://github.com/flatcar/mantle/pull/374))
- plume: consume images from bincache ([#371](https://github.com/flatcar/mantle/pull/371))
- sdk: add new subkey ([#418](https://github.com/kinvolk/mantle/pull/418))

### Removed

- dropped Kubernetes 1.22 tests ([#392](https://github.com/flatcar/mantle/pull/392))
- dropped Kubernetes 1.23 tests ([#416](https://github.com/flatcar/mantle/pull/416))

### Fixed
- Fixed `cl.internet/DockerPing` test failures, because it was pinging a non-existent address ([#386](https://github.com/flatcar/mantle/pull/386))
- Fixed `linux.ntp` test failures by adding output message for systemd-timesyncd v251 ([#402](https://github.com/flatcar/mantle/pull/402))

## [v0.19.0] - 15/09/2022
### Security
- go: Update golang.org/x/net ([#279](https://github.com/flatcar-linux/mantle/pull/279))
- go: Update golang.org/x/crypto ([#332](https://github.com/flatcar-linux/mantle/pull/332))

### Added
- plume: Add new AWS regions, af-south-1, ap-southeast-3, eu-south-1 ([#274](https://github.com/flatcar-linux/mantle/pull/274))
- kubernetes test for release 1.23.0 ([#275](https://github.com/flatcar-linux/mantle/pull/275))
- arm64 kubeadm test for `calico` CNI ([#278](https://github.com/flatcar-linux/mantle/pull/278))
- `Metro` to Equinix Metal options ([#281](https://github.com/flatcar-linux/mantle/pull/281))
- `update-offer` ore subcommand for AWS marketplace publishing ([#282](https://github.com/flatcar-linux/mantle/pull/282))
- kola test `cl.swap_activation` for swap activation with CLC ([#284](https://github.com/flatcar-linux/mantle/pull/284))
- Azure: support for running Kola within an existing vnet and with private addressing ([#295](https://github.com/flatcar-linux/mantle/pull/295))
- kola tests `cl.cgroupv1` and `kubeadm.*.*.cgroupv1.base` that test functionality with cgroupv1 ([#298](https://github.com/flatcar-linux/mantle/pull/298))
- Added private network support to qemu-unpriv platform ([#307](https://github.com/flatcar-linux/mantle/pull/307))
- Ignition v3 support and tests ([#301](https://github.com/flatcar-linux/mantle/pull/301), [#311](https://github.com/flatcar-linux/mantle/pull/311))
- Butane config support ([#318](https://github.com/flatcar-linux/mantle/pull/318))
- GCP: support testing with GVNIC ([#322](https://github.com/flatcar-linux/mantle/pull/322))
- `networkd` Ignition translation test ([#344](https://github.com/flatcar-linux/mantle/pull/334))
- kola test `cl.misc.falco` that tests falco kmod building ([#339](https://github.com/flatcar-linux/mantle/pull/339))
- Kubernetes test for release 1.24.1 ([#337](https://github.com/flatcar-linux/mantle/pull/337))
- Added storage abstraction for Equinix Metal tests (SSH can be used in addition of Google Cloud Storage) ([#340](https://github.com/flatcar-linux/mantle/pull/340))
- `plume prune` support for soft-deleting AWS images and more advanced retention strategies ([#343](https://github.com/flatcar-linux/mantle/pull/343))
- Added simple wireguard test ([#348](https://github.com/flatcar-linux/mantle/pull/348))
- Added SSH proxy jump to Openstack platform ([#349](https://github.com/flatcar-linux/mantle/pull/349))
- Added URL support for Openstack image creation ([#350](https://github.com/flatcar-linux/mantle/pull/350))
- kola tests for Cilium IPSec encryption ([#292](https://github.com/flatcar-linux/mantle/pull/292))
- Kubernetes test for release 1.25.0 ([#360](https://github.com/flatcar-linux/mantle/pull/360))
- Configurable timeouts for installation and launching Equinix Metal instances through `--equinixmetal-install-timeout` and `--equinixmetal-launch-timeout` flags ([#354](https://github.com/flatcar-linux/mantle/pull/354))
- Configurable timeouts for attaching to machine's journal and for machine checks through `--ssh-retries` and `--ssh-timeout` flags ([#354](https://github.com/flatcar-linux/mantle/pull/354))

### Changed
- removed `packet` occurrences in favor of `equinixmetal` ([#277](https://github.com/flatcar-linux/mantle/pull/277))
- kola: fixed cl.filesystem test for systemd 250 and newer ([#280](https://github.com/flatcar-linux/mantle/pull/280))
- PXE boots now over HTTPS on Equinix Metal ([#288](https://github.com/flatcar-linux/mantle/pull/288))
- Bumped cilium tested version to 1.11.0 ([291](https://github.com/flatcar-linux/mantle/pull/291))
- Bumped `etcd` and `cobra` dependencies ([#293](https://github.com/flatcar-linux/mantle/pull/293))
- Bumped Kubernetes binaries and CNI versions ([#297](https://github.com/flatcar-linux/mantle/pull/297))
- GCP images are now published/tested with UEFI boot mode ([#322](https://github.com/flatcar-linux/mantle/pull/322))
- Bumped Go version to 1.19 ([#352](https://github.com/flatcar-linux/mantle/pull/352))
- Bumped Cilium version to 1.12.1 ([#365](https://github.com/flatcar-linux/mantle/pull/365))
- Set SELinux in permissive mode for Cilium ([#365](https://github.com/flatcar-linux/mantle/pull/365))

### Removed
- Remove `--repo-branch` option from cork ([#283](https://github.com/flatcar-linux/mantle/pull/283))
- Removed Kubernetes test for release 1.21.10 ([#337](https://github.com/flatcar-linux/mantle/pull/337))
- Removed enforced SELinux for `kubeadm.flannel.*` tests ([#337](https://github.com/flatcar-linux/mantle/pull/337))

### Fixed
- Fix version check in kubeadm tests ([#353](https://github.com/flatcar-linux/mantle/pull/353))
- Make Calico testing in kubeadm tests more reliable ([#359](https://github.com/flatcar-linux/mantle/pull/359))
- Fix running tests on Equinix Metal s3.xlarge.x86 instanes ([#364](https://github.com/flatcar-linux/mantle/pull/364))

## [0.18.0] - 12/01/2022
### Security
- go: Update golang.org/x/{text,crypto} ([#262](https://github.com/flatcar-linux/mantle/pull/262))

### Added
- kola: add raid0 tests for root and data devices ([#36](https://github.com/flatcar-linux/mantle/pull/36))
- kola: Update the EM options to use sv15 region, c3.small plan ([#248](https://github.com/flatcar-linux/mantle/pull/248))
- plume: Enable arm64 board uploads for the Beta channel ([#249](https://github.com/flatcar-linux/mantle/pull/249))
- plume: Restore anonymous access with `--gce-json-key none` ([#255](https://github.com/flatcar-linux/mantle/pull/255))
- BPF test with DNS gadget from Inspektor Gadget ([#260](https://github.com/flatcar-linux/mantle/pull/260))
- BPF execsnoop test ([#233](https://github.com/flatcar-linux/mantle/pull/233))
- plume: Enable arm64 board uploads for the Stable channel ([#266](https://github.com/flatcar-linux/mantle/pull/266))
- A way to reuse Equinix Metal devices during tests ([#268](https://github.com/flatcar-linux/mantle/pull/268))
- plume: Enable arm64 board uploads for Azure ([#270](https://github.com/flatcar-linux/mantle/pull/270))
- kola: Support for using gallery images on Azure ([#270](https://github.com/flatcar-linux/mantle/pull/270))

### Changed
- `lsblk --json` output handling ([#244](https://github.com/flatcar-linux/mantle/pull/244))
- Flannel version to 0.14.0 ([#245](https://github.com/flatcar-linux/mantle/pull/245))
- Renamed the project name from `github.com/coreos/mantle` to `github.com/flatcar-linux/mantle` ([#241](https://github.com/flatcar-linux/mantle/pull/241))
- Default server on Equinix Metal ([#256](https://github.com/flatcar-linux/mantle/pull/256), [#257](https://github.com/flatcar-linux/mantle/pull/257))
- Azure: reworked resource cleanup to rely on automatic NIC/IP/OS disk removal ([#271](https://github.com/flatcar-linux/mantle/pull/271))

### Removed
- Legacy Kola Kubernetes tests ([#250](https://github.com/flatcar-linux/mantle/pull/250))
- `rkt` kola tests ([#261](https://github.com/flatcar-linux/mantle/pull/261))

## [0.17.0] - 05/10/2021
### Security
- go: update github.com/gogo/protobuf to v1.3.2 ([#229](https://github.com/kinvolk/mantle/pull/229))

### Added
- `kubeadm` proper support for ARM64 ([#217](https://github.com/kinvolk/mantle/pull/217))
- docker logs forwarding to `journald` for `kubeadm.*` tests ([#228](https://github.com/kinvolk/mantle/pull/228))
- `OEM` ignitions tests ([#235](https://github.com/flatcar-linux/mantle/pull/235))
- `--json-key` to `cork/create` and `cork/download` subcommands ([#239](https://github.com/flatcar-linux/mantle/pull/239))
- `--sdk-url` to allow passing a SDK location ([#240](https://github.com/flatcar-linux/mantle/pull/240))

### Changed
- Enabled SELinux for ARM64 ([#222](https://github.com/kinvolk/mantle/pull/222/))
- Enabled `docker.selinux` test for ARM64 ([#225](https://github.com/kinvolk/mantle/pull/225))
- Fixed `amd64` checksums for Kubernetes `v1.21.0` tests ([#226](https://github.com/kinvolk/mantle/pull/226))
- Used `clc` to set `enable_v2` option ([#227](https://github.com/kinvolk/mantle/pull/227))
- Used `ignition` instead of `clc` to provision instance in `raid` test ([#234](https://github.com/flatcar-linux/mantle/pull/234))
- Bumped `CiliumCLI` version to pull `Cilium-1.10.4` ([#230](https://github.com/kinvolk/mantle/pull/230))
- Certificate generation for `coreos.locksmith.tls` test ([#237](https://github.com/flatcar-linux/mantle/pull/237))

### Removed
- Duplicated `etcd-member` in the `kubeadm.*` config ([#232](https://github.com/kinvolk/mantle/pull/232))

## [0.16.0] - 30/08/2021

### Security
- go: update github.com/ulikunitz/xz and github.com/gorilla/websocket ([#206](https://github.com/kinvolk/mantle/pull/206))
- go: update github.com/golang-jwt/jwt to v4.0.0 ([#207](https://github.com/kinvolk/mantle/pull/207))
- go: Update golang.org/x/crypto and golang.org/x/net ([#173](https://github.com/kinvolk/mantle/pull/173))

### Added
- Improve AWS subcommands in ore, support AWS Pro downloading in cork, adjust LTS handling in plume ([#152](https://github.com/kinvolk/mantle/pull/152))
- kola: Add a filter to run tests based on offering ([#158](https://github.com/kinvolk/mantle/pull/158))
- cmd/cork: Allow to apply a patch on top of the manifest references ([#163](https://github.com/kinvolk/mantle/pull/163))
- kola: provide internet access to qemu VM ([#167](https://github.com/kinvolk/mantle/pull/167))
- platform: allow CLC templating for dynamic IP address insertion ([#168](https://github.com/kinvolk/mantle/pull/168))
- kola: add kubeadm tests ([#171](https://github.com/kinvolk/mantle/pull/171))
- kola/docker: add selinux test ([#177](https://github.com/kinvolk/mantle/pull/177))
- kola/kubeadm: test various CNIs ([#182](https://github.com/kinvolk/mantle/pull/182))
- kola/docker: accept 'cgroupns' security option ([#188](https://github.com/kinvolk/mantle/pull/188))
- kola/kubeadm: add kubernetes 1.22 test ([#196](https://github.com/kinvolk/mantle/pull/196))
- kola: support nightly version in version comparisons ([#198](https://github.com/kinvolk/mantle/pull/198))
- kola/harness: detect LTS major version ([#200](https://github.com/kinvolk/mantle/pull/200))
- Add platform for external provisioning ([#212](https://github.com/kinvolk/mantle/pull/212))
- update Azure SDK for Gen2 VM support ([#214](https://github.com/kinvolk/mantle/pull/214))

### Changed
- kola/tests/misc/network.go: Allow systemd-resolved to run ([#153](https://github.com/kinvolk/mantle/pull/153))
- kola/tests/misc/network.go: Disallow the CRI plugin to listen on TCP ([#154](https://github.com/kinvolk/mantle/pull/154))
- kola/tests/misc/network.go: Allow the containerd CRI plugin to listen ([#155](https://github.com/kinvolk/mantle/pull/155))
- cmd/cork/downloadimage: Make check for version.txt optional ([#156](https://github.com/kinvolk/mantle/pull/156))
- cmd/plume: Don't try to publish GCE LTS images ([#157](https://github.com/kinvolk/mantle/pull/157))
- kola: fix cgroup parameters for docker ([#29](https://github.com/kinvolk/mantle/pull/29))
- Update git URLs to kinvolk org ([#159](https://github.com/kinvolk/mantle/pull/159))
- kola/tests/flannel: use docker0's interface address as destination ([#161](https://github.com/kinvolk/mantle/pull/161))
- Update Kubernetes test ([#162](https://github.com/kinvolk/mantle/pull/162))
- cork: Apply patches with a dummy committer ([#164](https://github.com/kinvolk/mantle/pull/164))
- kola/readme: update example to use container linux ([#166](https://github.com/kinvolk/mantle/pull/166))
- kola/kubeadm: exclude azure platform ([#174](https://github.com/kinvolk/mantle/pull/174))
- kola: update containernetworking/plugins to v0.8.7 ([#175](https://github.com/kinvolk/mantle/pull/175))
- kubernetes and kubeadm tests: make it work on azure ([#176](https://github.com/kinvolk/mantle/pull/176))
- tests/cl.filesystem: skip "/run", fix test failure on arm64 ([#178](https://github.com/kinvolk/mantle/pull/178))
- kola/docker: make selinux optional ([#179](https://github.com/kinvolk/mantle/pull/179))
- platform/util: enable selinux logs for SELinux tests ([#180](https://github.com/kinvolk/mantle/pull/180))
- cork: fix handling of /dev/shm -> /run/shm symlinks ([#184](https://github.com/kinvolk/mantle/pull/184))
- platform/qemu: specify raw backing_fmt explicitly ([#185](https://github.com/kinvolk/mantle/pull/185))
- platform: provide Board access to the runtime ([#186](https://github.com/kinvolk/mantle/pull/186))
- kola/tests/util/update: use correct command name ([#187](https://github.com/kinvolk/mantle/pull/187))
- kola/tests/update: increase update timeout for arm64 ([#189](https://github.com/kinvolk/mantle/pull/189))
- kola/tests/verity: fall back to expected dm-verity offset ([#190](https://github.com/kinvolk/mantle/pull/190))
- kola/test: disable tests that won't work with docker 20.10 ([#192](https://github.com/kinvolk/mantle/pull/192))
- kola/test/update: reconfigure the instance once rebooted ([#193](https://github.com/kinvolk/mantle/pull/193))
- Expect kernel panic when dm-verity detects corruption ([#197](https://github.com/kinvolk/mantle/pull/197))
- platform/qemu: retry if OEM btrfs filesystem is in use ([#201](https://github.com/kinvolk/mantle/pull/201))
- kola/tests/misc/verity: add recursive list to provoke panic ([#202](https://github.com/kinvolk/mantle/pull/202))
- sdk: add new subkey ([#203](https://github.com/kinvolk/mantle/pull/203))
- build: remove deprecated flags ([#204](https://github.com/kinvolk/mantle/pull/204))
- kola/kubeadm: fix CNI selection [(#205](https://github.com/kinvolk/mantle/pull/205))
- sdk: pass '--quiet' to repo sync ([#208](https://github.com/kinvolk/mantle/pull/208))
- kola/test/selinux: exclude arm64 architecture ([#209](https://github.com/kinvolk/mantle/pull/209))
- kola: Use github container registry for test images ([#210](https://github.com/kinvolk/mantle/pull/210))
- test: fixes for ARM64 ([#211](https://github.com/kinvolk/mantle/pull/211))
- etcdctl: use v3 ([#213](https://github.com/kinvolk/mantle/pull/213))
- kola/tests/etcd: bind :2379 on all interfaces ([#215](https://github.com/kinvolk/mantle/pull/215))
- etcd: enable v2 support for various tests ([#216](https://github.com/kinvolk/mantle/pull/216))
- kola/tests/misc/verity: check arm64 board on all platforms ([#218](https://github.com/kinvolk/mantle/pull/218))
- platform/api/azure: cleanup after Azcopy ([#219](https://github.com/kinvolk/mantle/pull/219))
- kubeadm: use ghcr for Calico ([#220](https://github.com/kinvolk/mantle/pull/220))

### Removed
- kola: do not test Docker torcx profile tests for alpha, beta ([#160](https://github.com/kinvolk/mantle/pull/160)) ([#165](https://github.com/kinvolk/mantle/pull/165))
- remove rkt and kubelet-wrapper from kubernetes tests ([#169](https://github.com/kinvolk/mantle/pull/169))
- kola/tests/rkt: remove the rkt test from running on Alpha, Beta, Stable ([#170](https://github.com/kinvolk/mantle/pull/170)) ([#181](https://github.com/kinvolk/mantle/pull/181)) ([#194](https://github.com/kinvolk/mantle/pull/194))
- kola/kubeadm: exclude esx from tested platforms ([#172](https://github.com/kinvolk/mantle/pull/172))
- kola/tests/docker: exclude stable from torcx ([#195](https://github.com/kinvolk/mantle/pull/195))
