#!/bin/bash -xe

chain_id=$(/usr/local/bin/namadac utils init-network \
  --unsafe-dont-encrypt \
  --genesis-path ${GENESIS_PATH} \
  --chain-prefix namada-test \
  --localhost \
  --dont-archive \
  --wasm-checksums-path ${CHECKSUM_PATH} \
  | awk '$1 == "Derived" {print $4}')

if [ -z ${chain_id} ]
then
  echo "ERROR: init-network failed"
  exit 1
fi



rm /home/namada/chains/${chain_id}/config.toml
cp -r /home/namada/chains/${chain_id}/setup/validator-0/.namada/${chain_id}/* /home/namada/chains/${chain_id}

# copy wasm
cp -r /home/namada/wasm/checksums.json /home/namada/chains/${chain_id}/wasm/
cp -r /home/namada/wasm/*.wasm /home/namada/chains/${chain_id}/wasm/

# expose rpc
sed -i -e "s/127.0.0.1:26657/0.0.0.0:26657/g" /home/namada/chains/${chain_id}/config.toml

rm -rf /home/namada/chains/${chain_id}/setup
