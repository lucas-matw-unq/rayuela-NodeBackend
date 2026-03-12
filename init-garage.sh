#!/bin/bash

# Get Node ID from logs
NODE_ID=$(docker logs garage 2>&1 | grep "Node ID" | tail -n 1 | awk '{print $NF}')

if [ -z "$NODE_ID" ]; then
  echo "Error: Could not find Garage Node ID. Is the container running?"
  exit 1
fi

echo "Initializing Garage Cluster with Node ID: $NODE_ID"

# Assign and Apply layout
docker exec garage /garage layout assign -z local -c 10G "$NODE_ID"
docker exec garage /garage layout apply --version 2

# Import key (matching .env defaults)
docker exec garage /garage key import GKeb4b3ddceb7b51753a68f6ea 65cbf335e26752e15e0d3d88c3479d273b7355af1e8102007e7b27e4a0475150 -n rayuela --yes

# Create bucket
docker exec garage /garage bucket create rayuela-checkins
docker exec garage /garage bucket allow --read --write --owner rayuela-checkins --key rayuela

echo "Garage initialization complete."
