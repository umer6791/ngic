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
