#! /bin/bash
# Copyright (c) 2017 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

source ../config/cp_config.cfg

APP_PATH="./build"
APP="ngic_controlplane"

ARGS="-c 0x00ff -n 4 --socket-mem $MEMORY,0 --file-prefix cp --no-pci -- \
  -s $S11_SGW_IP          \
  -m $S11_MME_IP          \
  -w $S1U_SGW_IP          \
  -i $IP_POOL_IP          \
  -p $IP_POOL_MASK        \
  -a $APN"

USAGE=$"Usage: run.sh [ debug | log ]
	debug:	executes $APP under gdb
	log:	executes $APP with logging enabled to date named file under
		$APP_PATH/logs. Requires Control-C to exit even if $APP exits"

if [ -z "$1" ]; then

	$APP_PATH/$APP $ARGS

elif [ "$1" == "log" ]; then

	if [ "$#" -eq "2" ]; then
		FILE="${FILE/.log/.$2.log}"
		echo "logging as $FILE"
	fi
	trap "killall $APP; exit" SIGINT
	stdbuf -oL -eL $APP_PATH/$APP $ARGS </dev/null &>$FILE & tail -f $FILE

elif [ "$1" == "debug" ];then

	GDB_EX="-ex 'set print pretty on'"
	gdb $GDB_EX --args $APP_PATH/$APP $ARGS

else
	echo "$USAGE"
fi
