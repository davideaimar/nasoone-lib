#!/bin/bash

cd ./tests
sh delete.sh
cd ..

filenames=$(cargo test --no-run --message-format=json | jq -r "select(.profile.test == true) | .filenames[]")

for file in $filenames
do
  sudo setcap cap_net_raw,cap_net_admin=eip $file
  $file --ignored
done

