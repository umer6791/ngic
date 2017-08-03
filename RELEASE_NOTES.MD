---------------------------------------------------------------------------------------------
Next Generation Infrastructure Core (NGIC) Release Notes
---------------------------------------------------------------------------------------------
1.	Introduction
-----------------
This is the beta release for NGIC VNF.
NGIC application can be run independently or as part of the test harness.

2.	User Guide
--------------
Refer to README.MD for further details on NGIC, HLD, features supported, test
plan. For build configurations and execution requisites please refer to
INSTALL.MD.

3. Feature for this release
----------------------------
This release supports following features as part of NGIC:
-	NGIC can run as a standalone application on bare-metal linux server or on a
	virtual machine using SRIOV and OVS dpdk.
-	Packet Filters for Service Data Flow (SDF)
-	ADC(Application Detection and control) rules
-	PCC(Policy Control and Charging) rules
-	UE sessions with multiple Bearer support
-	SDF and APN based Qos Metering for MBR
-	Gtpv2c messages supported by CP on S11 interface
-	Charging by volume and asynchronous notification.
-	Ipv4 support
-	Sponsored Domain Name support


4. OS and kernel version
------------------------
This is supported on Ubuntu 14.04 and Ubuntu 16.04 and kernel version less than 4.5

5. Known Bugs and limitations
-----------------------------
-	The current tested ADC rules are not fully conformant to 3GPP release 12 ADC AVPs.
-	Rating Group based charging feature is supported with ADC_UPFRONT and
	tested under SIMU_CP enviroment.
-	APN Metering and SDF Metering featurs are tested under SIMU_CP enviroment.
-	ARP expiry timer not supported.
-	No ICMP support.
-	IPV4 fragmentation and option header not supported.
-	IPSec not supported.
-	Only ethernet v2 frame format is supported.
-	GTPv1-U sequence number, path management, header extension and
	tunnel management messages not supported.
-	Downlink egress hierarchical scheduling not supported.
-	Downlink data indication feature is not supported.
-	Scaling linearity loses after 3 worker cores.
-	For detailed ControlPlane limitations, please refer to docs/CP_README.MD.

6. Future Work
--------------
-	Limitations will be addressed
-	Performance optimization
-	IPV6 support
-	Neighbour Discovery and ICMPv6 stack support
