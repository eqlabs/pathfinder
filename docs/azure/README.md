# Running a node on Microsoft Azure

TL;DR copy/paste:

```bash
docker login azure
docker context create aci starknet-aci
docker context use starknet-aci
docker volume create goerli-data --storage-account starknetnodes
docker volume create mainnet-data --storage-account starknetnodes
docker compose --project-name starknet-nodes -f docker-compose.yml -f docs/azure/docker-compose.azure.yml up
```

## Azure Setup

You may want to create a subscription for the nodes (not available for free single user account)
[create a Subscription](https://portal.azure.com/?quickstart=true#view/Microsoft_Azure_SubscriptionManagement/SubscriptionCreateBlade)

Then:

- [create a Resource group](https://portal.azure.com/?quickstart=true#create/Microsoft.ResourceGroup) for the nodes and chose an appropriate region for your application

## Deployement

We use the docker aci context to deploy an AWS Cloudformation stack:

- create a docker aci context: `docker context create aci <chose a context name`>
  - use the above created resource group
- `docker context use <context name>`
  - or pass the `--context <context name>` to every following commands
- create volumes:
  - `docker volume create goerli-data --storage-account <storage account name>`
  - `docker volume create mainnet-data --storage-account <storage account name>`
- execute `docker compose --project-name <chose a name project name> -f docker-compose.yml -f docs/azure/docker-compose.azure.yml up`

You can then retrieve the node urls using :

```bash
docker ps
```

You can then check that the node are running using curl:

```bash
curl '<PORTS value for starknet-goerli>' \
  -H 'content-type: application/json' \
  --data-raw '{"method":"starknet_chainId","jsonrpc":"2.0","params":[],"id":0}' \
  --compressed | jq .result | xxd -rp
# SN_GOERLI
curl '<PORTS value for starknet-mainnet>' \
  -H 'content-type: application/json' \
  --data-raw '{"method":"starknet_chainId","jsonrpc":"2.0","params":[],"id":0}' \
  --compressed | jq .result | xxd -rp
# SN_MAIN
```

## Monitoring

You can find info about your deployment and containers in the Resource group's page.
