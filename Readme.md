# cidr-house-rules

A lightweight API and collection system to expose important AWS resource information across multiple accounts in near-realtime

![cidr-house-rules - page 1](https://user-images.githubusercontent.com/538171/33156099-3b810b1a-cfab-11e7-9005-79c0ee7bf506.png)

#### Collection subsystem

Centralized AWS Lambda functions assume role on monitored AWS accounts to collect the following:

* [NAT Gateway IPs](https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/vpc-nat-gateway.html) with associated VPCs and environment tags
* [EIPs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html)
* [VPC CIDR blocks](https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/working-with-vpcs.html) (including associated CIDR blocks)

#### API interface

An API interface is provided to expose collected data for consumption. Example usage is through Terraform's [http data source](https://www.terraform.io/docs/providers/http/data_source.html)

* retrieve all NAT Gateways for a given AWS account (team)
* retrieve all EIPs for a given AWS account (team)
* lookup a given CIDR block, i.e. 10.0.16.0/16 for potential VPC peering conflicts

#### Terraform modules that use cidr-house-rules for dynamic data

* todo: open source example data driven TF modules that use cidr-house-rules

#### Deployment

1. Requires [serverless-aws-documentation plugin](https://www.npmjs.com/package/serverless-aws-documentation)
2. Pick an AWS account to deploy cidr-house-rules to.
3. On remote accounts applying the supporting terraform see link below to generate role access
4. With roles generated on remote accounts you can now move serverless.yml.example to serverless.yml and add your target account roles
5. Run ```serverless deploy --stage prod```

#### Onboarding new AWS accounts

1. Apply the following Terraform and obtain outputs

```hcl
provider "aws" {
  region = "us-west-2"
}

module "cidr-house-rules-role" {
  cidr_house_rules_account_number = "123456770"
  serverless_stage                = "prod"
  serverless_region               = "us-west-2"
  source                          = "git::ssh://git@github.com/silvermullet/cidr-house-rules-role.git?ref=v0.0.1"
}

output "account_alias" {
  value = "${module.cidr-house-rules-role.account_alias}"
}

output "account_id" {
  value = "${module.cidr-house-rules-role.account_id}"
}

output "cidr-house-rules-role" {
  value = "${module.cidr-house-rules-role.cidr-house-rules-role}"
}
```

2. With the account_alias, account_id to app

```
curl \
  --header "X-Api-Key: <GET_KEY_FROM_AWS_API_GATEWAY>" \
  https://yourapigateway-endpoint-generated-by-serverless.com/prod/add_account?team=trucomms?account=35682931234
```

3. Add the role for Lambda functions to use in serverless.yml

```
Under this section add the new role, there should be a list of them already
iamRoleStatements:
  - Effect: Allow
    Action: sts:AssumeRole
    Resource:
      arn:aws:iam::<remote_aws_account_number_here>:role/role_cidr_house
```

4. Run deployment job in Jenkins noted in the "Deployment" section


#### Example API calls

##### Obtain NAT gateways for platform team

```
curl \
  --header "X-Api-Key: <GET_KEY_FROM_AWS_API_GATEWAY>" \
   https://yourapigateway-endpoint-generated-by-serverless.com/prod/get_nat_gateways_for_team?team=platform
```

##### Check for a VPC CIDR conflict

```
curl \
  --header "X-Api-Key: <GET_KEY_FROM_AWS_API_GATEWAY>" \
  https://yourapigateway-endpoint-generated-by-serverless.com/dev/check_conflict?cidr=10.17.0.0/16
```

##### Add a new account

```
curl \
  --header "X-Api-Key: <GET_KEY_FROM_AWS_API_GATEWAY>" \
  https://yourapigateway-endpoint-generated-by-serverless.com/dev/add_account?team=my_aws_account_alias_here?account=35682931234
```

#####  Supporting Terraform

[cird-house-rules-role](https://github.com/trulia/cidr-house-rules-role) - use this Terraform on your accounts you would like your cidr-house-rules deployment to have access to. The outputs on this Terraform can then be used in your serverless.yml. The account number of the remote account can then be added using the `add_account` API endpoint.
