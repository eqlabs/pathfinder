# Running a node on GCP

TL;DR copy/paste (require a GCP project) to run a mainnet node:

```bash
gcloud config set project <unique project id>
gcloud config set compute/region europe-west1
gcloud config set compute/zone europe-west1-b
gcloud compute firewall-rules create starknet-node --allow tcp:9545 --target-tags starknet-mainnet,starknet-goerli
export $(xargs <.env)
gcloud compute instances create-with-container starknet-mainnet \
  --container-image=eqlabs/pathfinder:latest \
  --container-restart-policy on-failure \
  --container-env PATHFINDER_ETHEREUM_API_URL=${PATHFINDER_ETHEREUM_API_URL_MAINNET} \
  --create-disk name=mainnet-data \
  --container-mount-disk mount-path="/usr/share/pathfinder/data",name=mainnet-data \
  --tags starknet-mainnet
gcloud compute ssh starknet-mainnet
```

And once on the remote machine:

```bash
sudo lsblk
sudo chmod a+w /mnt/disks/gce-containers-mounts/gce-persistent-disks/mainnet-data
curl https://pathfinder-starknet-node-backup.s3.eu-west-3.amazonaws.com/mainnet/mainnet.sqlite \
  --output /mnt/disks/gce-containers-mounts/gce-persistent-disks/mainnet-data/mainnet.sqlite
```

## GCP Setup

We use the [Google Cloud CLI](https://cloud.google.com/sdk/docs/install) to deploy the nodes.

If you have already a gcloud project, you can simply use it. Otherwise, or if prefer, you will need to create one:

```bash
gcloud projects create <unique project id>
gcloud config set project <unique project id>
```

We use Compute Engine to run the node. First, we set the region and zone where we want to deploy (see [regions/zones](https://cloud.google.com/compute/docs/regions-zones)).
For example:

```bash
gcloud config set compute/region europe-west1
gcloud config set compute/zone europe-west1-b
```

We also create a firewall rule for opening the node port (9454 by default)

```bash
gcloud compute firewall-rules create starknet-node \
  --allow tcp:9545 \
  --target-tags starknet-mainnet,starknet-goerli
```

## Deployment

You first need to load then env variables defined in the .env file. For example: `export $(xargs <.env)`

Then run the following command to pop a mainnet node
(note that only the `PATHFINDER_ETHEREUM_API_URL_MAINNET` makes this node a mainnet one, the other "mainnet" are just naming):

```bash
gcloud compute instances create-with-container starknet-mainnet \
  --container-image=eqlabs/pathfinder:latest \
  --container-restart-policy on-failure \
  --container-env PATHFINDER_ETHEREUM_API_URL=${PATHFINDER_ETHEREUM_API_URL_MAINNET} \
  --create-disk name=mainnet-data \
  --container-mount-disk mount-path="/usr/share/pathfinder/data",name=mainnet-data \
  --tags starknet-mainnet
```

Note that in the previous command, we explicitely create a `disk`. If you kill your node at some point and want to pop another container,
you can reuse the same `disk` by replace `--create-dist` with `--disk`. You can check your disks with `gcloud compute disks list`.

Then, log into the host machine using ssh to update the disk permission (beware of the naming of the disk, see previous comment):

```bash
gcloud compute ssh starknet-mainnet
```

Once on the container:

```bash
sudo lsblk
sudo chmod a+w /mnt/disks/gce-containers-mounts/gce-persistent-disks/mainnet-data
curl https://pathfinder-starknet-node-backup.s3.eu-west-3.amazonaws.com/mainnet/mainnet.sqlite \
  --output /mnt/disks/gce-containers-mounts/gce-persistent-disks/mainnet-data/mainnet.sqlite
```

Once connected to the host, you can also see that your node is running:

```bash
docker ps
```

And perform all the usual actions (`docker logs`, `docker attach`, `docker inspect`, etc.).

You can then retrieve the node urls using :

```bash
gcloud compute instances list
```

You can eventually then check that the node are running using curl:

```bash
curl '<IP starknet-goerli>:9545' \
  -H 'content-type: application/json' \
  --data-raw '{"method":"starknet_chainId","jsonrpc":"2.0","params":[],"id":0}' \
  --compressed | jq .result | xxd -rp
# SN_GOERLI
curl '<IP starknet-mainnet>:9545' \
  -H 'content-type: application/json' \
  --data-raw '{"method":"starknet_chainId","jsonrpc":"2.0","params":[],"id":0}' \
  --compressed | jq .result | xxd -rp
# SN_MAIN
```

## Monitoring

You can find info about your deployment and containers in the [Compute Engine instances' page](https://console.cloud.google.com/compute/instances)
