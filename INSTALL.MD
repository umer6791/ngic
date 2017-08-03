NGIC Installation Guide
=======================

1. System Topology
------------------

```text
                             +----------+
                             | MME-     |
                             | System5: |
                             | ng4t     |
                             |          |
                             +----------+
                                 |1G
                  +-----------------------------+
                  |           NGIC VNF          |
                  |                             |
                  | +-------------------------+ |
                  | |      ControlPlane       | |
                  | |                         | |
                  | +-----+---------+---------+ |
                  | |     |         |           |
+------------+    | |     |IPC/     +fpc        |    +------------+
| Traffic    |    | |     |UDP     SDN          |    | Traffic    |
| Generator  |    | |     |         +zmq        |    | Generator  |
| System3:   | 10G| +-----+-------------------+ |10G | System3:   |
| ixia, ng4t,+------+        DataPlane        +------+ ixia, ng4t,|
| pktgen etc |    | |                         | |    | pktgen etc |
+------------+    | +-------------------------+ |    +------------+
                  +-----------------------------+
```

* Data Plane and Control plane can run on two different systems using SDN or UDP interfaces
* If DataPlane and Control plane run on the same system, IPC can be used for communication
* CP and DP can be run in a Virtualized Environment.
* With SDN communication, CP to SDN works on FPC and SDN to DP works on ZMQ.
* System3 and System4 are the traffic generators connected to VNF over 10G interfaces.
* System5 hosts the MME. Currently NGIC VNF has been tested with ng4t MME.
* MME sends commands to ControlPlane over 1G interface. This can be higher
speed interface also.

2. Configuration
-----------------

#### 2.1 Configuration files

Following config files contain static rule information:
adc_rules.cfg - Contains Application Detection Control (ADC) rules
static_pcc.cfg - Contains packet filters and policy, charging, & control
		information that the Control Plane uses to install PCC and
		Filters on the DP on initialization.

Following config files should be configured properly with ports information
and interface for communication needed by the applications:
cp_config.cfg - Configure port IPs and other parameters needed by control
		plane application
dp_config.cfg - Configure port IPs and MACs needed by data plane app
interface.cfg - To add interface details between CP and DP. For example, for
		UDP set ip address and ports.

Following config files are referenced only for specific use case:
rules_ipv4.cfg - Set ACL ipv4 filter if ACL_READ_CFG is to be used
rules_ipv6.cfg - Set ACL ipv6 filter if ACL_READ_CFG is to be used
simu_cp.cfg - Use this to set info in simulated control plane testing.
		See `Simulated CP config'

#### 2.2 CP Configuration
`static_pcc.cfg` contains packet filters and policy, charging, & control information
that the Control Plane uses to install PCC and Filters on the DP on initialization. (For this
reason, the DP must be executed prior to the CP). Currently, packet filters are static, and may
not be altered during execution, thus any bearer resource commands received by the CP from the
MME must utilize the predefined filters contained within this file.

CP dpdk run parameters:

```text
    -c coremask                - The control plane requires 2 cores (one dedicated to displaying statistics to console)
    -n 4                       - Recommend using all available memory channels
    --socket-mem X,Y           - Memory has been allocated according to NUMA-awareness, suggest using memory on socket corresponding to coremask
    --file-prefix cp           - Required for collocated Control and Dataplane
    --no-pci                   - Does not require use of DPDK bound NICs
```

CP application run parameters to be supplied in cp_config.cfg:

| ARGUMENT          | PRESENCE    | DESCRIPTION                                |
|:------------------|:------------|:-------------------------------------------|
| -s11_sgw_ip       | MANDATORY   | Local interface IP exposed to Linux        |
|		    |		  | networking stack to be used by the Control |
|                   |             | Plane for messaging with the MME           |
| -s11_mme_ip       | MANDATORY   | MME IP                                     |
| -s1u_sgw_ip       | MANDATORY   | Network interface IP exposed by DP; must be|
|                   |             | equivalent to --s1u_ip parameter of DP     |
| -ip_pool_ip       | MANDATORY   | Along with mask, defines pool of IP        |
|                   |             | addresses that CP may assign to UEs        |
| -ip_pool_mask     | MANDATORY   | ip_pool_mask                               |
| -apn_name         | MANDATORY   | Access Point Name label supported by CP;   |
|                   |             | must correspond to APN referenced in create|
|                   |             | session request messages along the s11     |
| -pcap_file_in     | OPTIONAL    | Ignores s11 interface and acts as if       |
|                   |		  | packets contained in input file arrived    |
|		    |		  | from MME                                   |
| -pcap_file_out    | OPTIONAL    | Creates a capture of messages created by   |
|		    |		  | CP. Mainly for development purposes        |


#### 2.3 DP Configuration :
DP dpdk run parameters:

```text
        -c coremask             - Enable the cores needed by DP (5 cores for s1u rx/tx, sgi rx/tx, stats, mct and iface, plus number of worker cores)
For example, to enable 1 worker core and 5 fixed cores on socket 0, set coremask as 0x3f
        -n                      - Recommend using all available memory channels
        --socket-mem X,Y        - Memory has been allocated according to NUMA-awareness, suggest using memory on socket corresponding to coremask
        --file-prefix cp        - Required for collocated Control and Dataplane.
```

DP application parameters to be supplied in dp_config.cfg:

Dataplane supported command line arguments are:


| ARGUMENT          | PRESENCE    | DESCRIPTION                                |
|:------------------|:------------|:-------------------------------------------|
| --s1u_ip          | MANDATORY   | S1U IP address of the SGW.                 |
| --s1u_mac         | MANDATORY   | S1U port mac address of the SGW.           |
| --sgi_ip          | MANDATORY   | SGI IP address of the SGW.                 |
| --sgi_mac         | MANDATORY   | SGI port mac address of the PGW.           |
| --s1uc            | OPTIONAL    | core number to run s1u rx/tx.              |
| --sgic            | OPTIONAL    | core number to run sgi rx/tx.              |
| --bal             | OPTIONAL    | core number to run load balancer.          |
| --mct             | OPTIONAL    | core number to run mcast pkts.             |
| --iface           | OPTIONAL    | core number to run Interface for IPC.      |
| --stats           | OPTIONAL    | core number to run timer for stats.        |
| --num_workers     | MANDATORY   | no. of worker instances.                   |
| --log             | MANDATORY   | log level, 1- Notification, 2- Debug.      |

* Enter the mac addresses for s1u and sgi ports obtained from step 2.1
  respectively
* ngic_dataplane application will pick the available cores as enabled by
  the coremask if the s1uc, sgic, bal, mct, iface and stats options are not
  supplied.

Please refer to `dp/run.sh` for example configuration.

#### 2.4 Simulated CP config (Optional):
This option can be used to test Dataplane with a simulated ControlPlane
without the need of MME.
Please enable SIMU_CP in dp/Makefile to use this.
Edit `config/simu_cp.cfg` with following information:

|       __Key__         |                __Value__                      |
|:----------------------|:----------------------------------------------|
|__enodeb_ip__          | eNodeB (Base station) IP address              |
|__max_ue_sess__        | Max number of UE sessions                     |
|__ue_ip_start__        | UE start ip from which max no. of UEs will be configured. Should be in sync with the traffic flow|
|__ue_ip_start_range__  | Set this to start of user equipment address.  |
|__as_ip_start__        | Application Server IP                         |
|__max_entries__        | Max SDF table entries                         |
|__max_rules__          | Number of SDF rules                           |
|__max_ul_rules__       | Number of uplink SDF rules                    |
|__max_dl_rules__       | Number of downlink SDF rules                  |
|__max_meter_profile_entries__ | maximum meter profiles to be created.  |
|__default_bearer__     | Default bearer number, this is set to 5.      |
|__dedicated_bearer__   | Set this to 0 if dedicated bearer is not reqd.|

Example configuration:

```conf
        enodeb_ip = 11.1.1.101
        ue_ip_start = 16.0.0.1
        ue_ip_start_range = 16.0.0.0
        as_ip_start = 13.1.1.110
        max_entries = 100
        max_rules = 24
        max_ul_rules = 12
        max_dl_rules = 12
        max_ue_sess = 1000
        max_meter_profile_entries = 100
        default_bearer = 5
        dedicated_bearer = 0
```
To test Sponsored Domain Names with SIMU CP:
Domain names should be mentioned in adc_config.cfg
Setup a "veth" pair such as

sudo ip link add s1u type veth peer name s1u_peer
sudo ip link add sgi type veth peer name sgi_peer

To work with these interfaces, the dp is launched with the
foll. arguments
 --no-pci --vdev eth_af_packet0,iface=s1u --vdev eth_af_packet1,iface=sgi

The DNS response is then sent to the sgi interface as below

sudo tcpreplay  --intf1=sgi_peer <path to>/dnsresp.pcap

The DNS response matches any of the  preconfigured domain names
you should see a message saying that the corresponding rule ID has
been added

3. Installation and Compilation
-------------------------------

###### Dependencies
* DPDK 16.04: Downloaded as a submodule, using `--recursive` when cloning this repo or using the `install.sh` script.
Alternatively, it can be downloaded and installed manually from [here](http://fast.dpdk.org/rel/dpdk-16.04.tar.xz)
Both the options are avialble as part of install.sh below.
* libpcap-dev
* libzmq
* libcurl

###### Environment variables

```shell
export RTE_SDK=<dpdk 16.04 directory>
export RTE_TARGET=x86_64-native-linuxapp-gcc
```

DPDK configuration file `dpdk-16.04_common_linuxapp` provided, is to be
copied/moved to `$RTE_SDK/config/common_linuxapp` before building dpdk.
This is done by install.sh script.

###### Initial Compilation

#### 3.1 Using install.sh:

Run "./install.sh" in ngic root folder.

Following are the options for setup:

```text

----------------------------------------------------------
 Step 1: Environment setup.
----------------------------------------------------------
[1] Check OS and network connection

----------------------------------------------------------
 Step 2: Download and Install
----------------------------------------------------------
[2] Agree to download
[3] Download packages
[4] Download DPDK submodule
[5] Download DPDK zip (optional, use it when option 4 fails)
[6] Install DPDK
[7] Setup hugepages

----------------------------------------------------------
 Step 3: Build NGIC
----------------------------------------------------------
[8] Build NGIC

[9] Exit Script

```

[1] This will check the OS version and network connectivity and report
    any anomaly. If the system is behind a proxy, it will ask for a proxy
    and update the required environment variables.
[2] Select yes in this option to be able to download the required packages.
[3] Actual download of the dependent packages like libpcap, build essentials
    etc.
[4] This option downloads dpdk which is added as a git submodule in the
    ngic repo and then sets the dpdk directory to this directory.
[5] Alternatively dpdk can be downloaded as a zip file using this option.
[6] Build and set environment variables to use DPDK.
[7] Setup hugepages for the system
[8] Build controlplane and dataplane applications. This sets the RTE_SDK
    environment variable and builds the applications.

#### 3.2 Manual build:

Control Pland and Data Plane applications can be built using install.sh using
"Step 3 Build NGIC" or can be done manually as follows:

1. Setup RTE_SDK and RTE_TARGET variables using ./setenv.sh.
   Point RTE_SDK to the path where dpdk is downloaded.
2. Use "make" in ngic root directory to build both CP and DP.
   OR
   Use respective "make" in CP and DP to build them individually.

Sponsered DNS setup:
Dependencies:
hyperscan-4.1.0 library is dependent on libbost version greater than 1.58. On Ubuntu 14.04,
libboost version supported is 1.55. So it is preferable to use Ubuntu 16.04 for SPONSDN setup.

a. Download and untar hyperscan-4.1.0.tar.gz
b. apt-get install cmake
c. apt-get install libboost-all-dev (Make sure it is > 1.58 version)
d. apt-get install ragel
e. cd hyperscan-4.1.0
f. mkdir build; cd build
g. cmake -DCMAKE_CXX_COMPILER=c++ ..
h. cmake --build .

4.2 Build libsponsdn
a. export HYPERSCANDIR=<path_of_hyperscan_directory>
b. cd lib/libsponsdn
c. make

#### 3.3 Setup traffic generator for dataplane traffic:

Below is sample flows to test the Uplink and Downlink flows with traffic generator:

* __Uplink__:
    -   Uplink traffic should be sent on s1u port ,say port 0.
    -   Each flow in this example is identified by dst ip from 13.1.1.110-13.1.1.121.

            SrcIP/Mask DstIP/Mask   Sport   : Sport Dport   : Dport Prot/Prot
            16.0.0.0/8 13.1.1.110/32 0      : 65535 0       : 65535 0x0/0x0
            16.0.0.0/8 13.1.1.111/32 0      : 65535 0       : 65535 0x0/0x0
            16.0.0.0/8 13.1.1.112/32 0      : 65535 0       : 65535 0x0/0x0
            16.0.0.0/8 13.1.1.113/32 0      : 65535 0       : 65535 0x0/0x0
            16.0.0.0/8 13.1.1.114/32 0      : 65535 0       : 65535 0x0/0x0
            16.0.0.0/8 13.1.1.115/32 0      : 65535 0       : 65535 0x0/0x0
            16.0.0.0/8 13.1.1.116/32 0      : 65535 0       : 65535 0x0/0x0
            16.0.0.0/8 13.1.1.117/32 0      : 65535 0       : 65535 0x0/0x0
            16.0.0.0/8 13.1.1.118/32 0      : 65535 0       : 65535 0x0/0x0
            16.0.0.0/8 13.1.1.119/32 0      : 65535 0       : 65535 0x0/0x0
            16.0.0.0/8 13.1.1.120/32 0      : 65535 0       : 65535 0x0/0x0
            16.0.0.0/8 13.1.1.121/32 0      : 65535 0       : 65535 0x0/0x0

    -   For above flows to hit, all UEs IP should be with in range 16.0.0.1 - 16.255.255.255.
    -   Teid in flow should match with the teid configured, else the flow will be not be processed.
        By default teid = 1 is installed with UE ip 16.0.0.1,
        teid = 2 is installed with UE ip 16.0.0.2 and so on.

* __Downlink__:
    -   Downlink traffic should be sent on sgi port ,say port 1.
    -   Each flow in this example is identified by src ip from range 13.1.1.110 - 13.1.1.121.

            SrcIP/Mask    DstIP/Mask Sport  : Sport Dport   : Dport Prot/Prot
            13.1.1.110/32 16.0.0.0/8 11     : 11    0       : 65535 0x0/0x0
            13.1.1.111/32 16.0.0.0/8 12     : 12    0       : 65535 0x0/0x0
            13.1.1.112/32 16.0.0.0/8 13     : 13    0       : 65535 0x0/0x0
            13.1.1.113/32 16.0.0.0/8 14     : 14    0       : 65535 0x0/0x0
            13.1.1.114/32 16.0.0.0/8 15     : 15    0       : 65535 0x0/0x0
            13.1.1.115/32 16.0.0.0/8 11     : 11    0       : 65535 0x0/0x0
            13.1.1.116/32 16.0.0.0/8 12     : 12    0       : 65535 0x0/0x0
            13.1.1.117/32 16.0.0.0/8 13     : 13    0       : 65535 0x0/0x0
            13.1.1.118/32 16.0.0.0/8 14     : 14    0       : 65535 0x0/0x0
            13.1.1.119/32 16.0.0.0/8 15     : 15    0       : 65535 0x0/0x0
            13.1.1.120/32 16.0.0.0/8 11     : 11    0       : 65535 0x0/0x0
            13.1.1.121/32 16.0.0.0/8 12     : 12    0       : 65535 0x0/0x0

    -   For above flows to hit, all UEs IP should be with in range 16.0.0.1 - 16.255.255.255.
        Please refer the packet capture files `pcap/uplink_100flows.pcap` and `pcap/downlink_100flows.pcap` for other fields.

#### 3.4 Running CP and DP

a. Setup 10G ports for VNF to run:
   Two 10G ports are used for S1U and SGI interfaces by dataplane(dp).

  1. cd dpdk
  2. ./tool/dpdk_nic_bind.py --status <--- List the network device
  3. Use `lshw` or `ip addr show <port>` to find the mac address
  4. ./tool/dpdk_nic_bind.py -b igb_uio <PCI Port 0> <PCI Port 1>
    OR
    Use `$RTE_SDK/tools/setup.sh` for binding the ports.

  For more details refer
  http://dpdk.org/doc/guides-16.04/linux_gsg/build_dpdk.html#binding-and-unbinding-network-ports-to-from-the-kernel-modules

b. Add the mac addresses of port0 and port1 in config/dp_config.cfg to run ngic_dataplane.

```shell
cd dp
Edit run.sh to add coremask
./run.sh ---> start ngic_dataplane.
```

c. Update cp_config.cfg with required parameters.

```shell
cd dp
./run.sh
```

d. Then start the traffic generator and MME if applicable.

#### 3.5 Standalone Virtualization:
Dataplane has been tested with SRIOV and OVS with SIMU_CP configuration:

* SRIOV Setup:
    -   OS : Ubuntu 16.04 LTS Server Edition.
    -   DPDK: 16.04 version
    -   Hypervisor: KVM
        Please refer [setup sriov](http://dpdk.org/doc/guides-16.04/nics/intel_vf.html)

* OVS Setup:
    -   OS : Ubuntu 16.04 LTS Server Edition.
    -   DPDK: 16.04 version
    -   OVS: 2.5
    -   Hypervisor: KVM
    -   Supported deployment : PHY-VM-PHY
    -   Please refer below link to setup ovs:
        *   [Using OvS with DPDK on Ubuntu](https://software.intel.com/en-us/articles/using-open-vswitch-with-dpdk-on-ubuntu)
        *   [OvS INSTALL.DPDK-ADVANCED](http://openvswitch.org/support/dist-docs/INSTALL.DPDK-ADVANCED.md.html#ovstc)

* BIOS for Standalone Virtualization:

    -   Open `/etc/default/grub` configuration file.
    -   Append `iommu=pt intel_iommu=on` to the `GRUB_CMDLINE_LINUX` entry.

4. Generating API documentation
-------------------------------

Run "doxygen doxy-api.conf" in ngic root directory to generate doxygen
documentation.
