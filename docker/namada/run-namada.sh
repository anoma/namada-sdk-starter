#!/bin/bash -xe

/usr/local/bin/namadan ledger run
pid=$!

trap "kill ${pid}; exit 0" INT
wait