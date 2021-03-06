Copyright (c) 2017 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

DP rule verification tool
==============================================
1. Introduction
-------------------------------------------
DP rule verification tool is designed to verify SDF, ADC and PCC rules applied
by DP on the traffic passing through S1U and SGi. 

Rule verification is done on the extended CDR file generated by DP. This file
is generated when build time flag is enabled in DP for generating this file.

Rule verification is based on the following rules configuration files :
* PCC (Policy Control and Charging) rules configuration.
* ADC (Application Detection and control) rules configuration.
* SDF (Service Data Flow) rules configuration.

2.	DP rule verification tool Configuration
-------------------------------------------
To run the DP rule verification tool, install the following prerequisite packages:
	-	python - 2.7
	-	pprint
	-	ipaddress
	-	ConfigParser

3.	Run DP rule verification tool
-------------------------------------------
#### 3.1 Required input files
		a. Extended csv file
		b. Configuration files
			-	adc_rules.cfg
			-	pcc_rules.cfg
			-	sdf_rules.cfg

#### 3.2 Execute the following command to run the tool

Go to the folder 'ngic/dp/dp_rules_verify'

Execute command :
> python dp_rules_verify.py <Path to extended csv file>  <Path to rules configuration files>

For ex : 
python dp_rules_verify.py test_Default_rule/xcdr_default_match.csv Rule_verfication/test_Default_rule

4. Output
--------------------------------------------
Sample output : In case of success
******************************
Pass : All packets matched
******************************
Total Uplink Packets :      13085
Total Downlink Packets :    35410
Total Packets :             48495
******************************

Sample output in case of failure:
******************************Fail Packets******************************
------------------------------------------------------------------------------------------------------------------------------------------------------
Actual           Actual           Actual         Actual         Actual         Actual         Expected       Expected       Expected       Expected
ue_ip            app_ip           pcc_rule_id    filter_type    rule_name      action         pcc_rule_id    filter_type    rule_name      action
------------------------------------------------------------------------------------------------------------------------------------------------------
16.255.255.237   13.2.1.110       6              ADC            adc_rule_2     CHARGED        5              ADC            adc_rule_2     CHARGED
------------------------------------------------------------------------------------------------------------------------------------------------------
******************************Summary******************************
Total Uplink Packets :      13085    PASS: 13084  FAIL: 1
Total Downlink Packets :    35410    PASS: 35410  FAIL: 0
Total Packets :             48495    PASS: 48494  FAIL: 1
*******************************************************************

5. Debug level
---------------------------------------------
Debug level is disabled by default.
To enable debug level please set obj.debugging_flag to 'True' in file dp_rules_verify.py
