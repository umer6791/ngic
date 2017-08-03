#! /bin/bash

source ../config/dp_config.cfg

APP_PATH="./build"
APP="ngic_dataplane"
LOG_LEVEL=1

ARGS="-c 0xfff800000 -n 4 --socket-mem 0,$MEMORY \
            --file-prefix dp -w $PORT0 -w $PORT1 -- \
            --s1u_ip $S1U_IP --s1u_mac $S1U_MAC \
            --sgi_ip $SGI_IP --sgi_mac $SGI_MAC \
            --num_workers $NUM_WORKER --log $LOG_LEVEL"

if [ -n "${S1U_GW_IP}" ]; then
	ARGS="$ARGS --s1u_gw_ip $S1U_GW_IP"
	if [ -n "${S1U_MASK}" ]; then
		ARGS="$ARGS --s1u_mask $S1U_MASK"
	fi
fi

if [ -n "${SGI_GW_IP}" ]; then
	ARGS="$ARGS --sgi_gw_ip $SGI_GW_IP"
	if [ -n "${SGI_MASK}" ]; then
		ARGS="$ARGS --sgi_mask $SGI_MASK"
	fi
fi


echo $ARGS | sed -e $'s/--/\\\n\\t--/g'

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

elif [ "$1" == "debug" ]; then

	GDB_EX="-ex 'set print pretty on' "
	echo $GDB_EX
	gdb $GDB_EX --args $APP_PATH/$APP $ARGS

else
	echo "$USAGE"
fi
