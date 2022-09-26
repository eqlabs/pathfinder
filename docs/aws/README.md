# Running a node on AWS

## AWS Setup

If you don't have yet AWS credentials, you can follow these steps. Otherwise, just check the required [policy.json](./policy.json) against your user one and proceed to the next step.

- [create an AWS policy](https://us-east-1.console.aws.amazon.com/iam/home#/policies$new?step=edit) using the [policy.json](./policy.json) file attached
- [create a AWS user group](https://us-east-1.console.aws.amazon.com/iamv2/home?region=eu-west-1#/groups/create) and add it the above created policy
- [create an AWS User](https://us-east-1.console.aws.amazon.com/iam/home#/users$new?step=details)
  - select only "Access key - Programmatic access"
  - add it to the above created group
- create an AWS profile for deploying the node using the generated credentials
  - `aws configure --profile <chose a profile name>`
    - for example `aws configure --profile pathfinder-deployer`

## Deployement

We use the docker ecs context to deploy an AWS Cloudformation stack:

- create a docker ecs context: `docker context create ecs <chose a context name`>
  - for example, `docker context create ecs pathfinder-deployer`
  - use the above created profile
- `docker context use <context name>`
- execute `docker compose --project-name <chose a name visible in aws console> -f docker-compose.yml up`
  - for example, `docker compose --project-name starknet-nodes -f docker-compose.yml up`
  - ignore the `WARNING services.scale: unsupported attribute`

The created enpoint can be found in the ECS Cluster page:

- Cluster > Services > Networking > DNS names

You can then check that the node are running using curl:

```bash
curl '<DNS name>:9545' \
  -H 'content-type: application/json' \
  --data-raw '{"method":"starknet_chainId","jsonrpc":"2.0","params":[],"id":0}' \
  --compressed | jq .result | xxd -rp
# SN_GOERLI
curl '<DNS name>:9546' \
  -H 'content-type: application/json' \
  --data-raw '{"method":"starknet_chainId","jsonrpc":"2.0","params":[],"id":0}' \
  --compressed | jq .result | xxd -rp
# SN_MAIN
```

## Monitoring

The deployed stack can be monitored on the [AWS CloudFormation home page](https://eu-west-3.console.aws.amazon.com/cloudformation/home).
The `docker compose logs` command will output the logs otherwise found in CloudWatch.
The `docker compose convert` command will generate the corresponding yaml file to be used with `aws cloudformation deploy` for further manual tweakings.

```bash
docker compose convert > stack.yaml
aws cloudformation deploy --template-file stack.yml --stack-name pathfinder-node --capabilities CAPABILITY_IAM --profile pathfinder-deployer
```
