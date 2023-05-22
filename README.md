# namada-sdk-starter


* Build docker containers
    * for local testnet: docker build -t namada-v0.16.0:latest .
    * for current testnet: docker build -t namada-v0.15.4:latest .
* Run containers:
    * docker run -d -p 127.0.0.1:26657:26657 -v namada-v0.15.4-chaindata:/home/namada/chains namada-v0.15.4:latest
    * Pick the right container
* Attach to running container:
    * docker exec -it <container_name> /bin/bash
* Logs are shown in the UI

* `cargo run` to execute an action
