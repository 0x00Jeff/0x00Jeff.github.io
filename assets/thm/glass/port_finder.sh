if [ $# != 1 ];then
	echo "usage : port.sh IP"
	exit
fi

LOW=1
HIGH=2
last_state=0
current_state=0
port=$(( ($RANDOM % 4999 ) + 9000))
step=1000


#echo port is $port

while true; do

	echo -n "$port -> "

	response=$(ssh $1 -p $port -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null 2>/dev/null)
	echo $response


	#echo response is $response

	if [ "$(echo $response)" == "$(echo -en "Higher\r")" ];then
			while (( $(( $port - $step )) < 9000 ));do
				step=$(( $step / 2))
			done

			if [ $last_state == $LOW ];then # response change from "Lower" to "Higher"
				step=$(( $step / 2))
			fi

		port=$(( $port - $step ))
		current_state=$HIGH

	elif [ "$(echo $response)" == "$(echo -en "Lower\r")" ];then
			while (( $(( $port + $step)) > 13999 ));do
				step=$(( $step / 2))
			done

			if [ $last_state == $HIGH ];then # response changed from "Hihger" to "Lower"
				step=$(( $step / 2))
			fi
		
		port=$(( $port + $step ))
		current_state=$LOW

	else
		# this doesn't work, instead the scripts freezes duo the connection persisting 
		# and asking for a password instead of closing up like the other ports
	       	# when this script freezes you know you found your target port	
		echo the right port is $port !
		exit

	fi


	if [ $last_state == 0 ];then # first iteration
		last_state=$current_state
	fi


	last_state=$current_state

done
