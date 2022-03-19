#!/bin/bash
set -e

if [[ -z "$HTTP_RPC" ]]; then
  ARG1=""
else
  ARG1="--http-rpc="
fi
if [[ -z "$ETH_RPC_URL" ]]; then
  ARG2=""
else
  ARG2="--ethereum.url="
fi
if [[ -z "$ETH_PASSWORD" ]]; then
  ARG3=""
else
  ARG3="--ethereum.password="
fi
if [ "$IDLE" == "1" ]; then
    echo "Detected \$IDLE=1 env variable"
    echo "Starknet Pathfinder will now idle"
    echo "To restart normally, remove the env variable and the container will restart"
    tail -f /dev/null
else
  tini -s -- /usr/local/bin/pathfinder $ARG1$HTTP_RPC $ARG2$ETH_RPC_URL $ARG3$ETH_PASSWORD
fi
