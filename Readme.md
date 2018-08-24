# cidr-house-rules
[![Build Status](https://travis-ci.org/trulia/cidr-house-rules.svg)](https://travis-ci.org/trulia/cidr-house-rules)

A lightweight API and collection system to centralize important AWS resource information across multiple accounts in near-realtime

![cidr-house-rules](https://user-images.githubusercontent.com/538171/37231223-3ee8eda2-239f-11e8-8ca6-6cb58da11d48.png)

#### Collection subsystem

Centralized AWS Lambda functions assume role on monitored AWS accounts to collect the following:

* [NAT Gateway IPs](https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/vpc-nat-gateway.html) with associated VPCs and environment tags
* [EIPs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html)
* [VPC CIDR blocks](https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/working-with-vpcs.html) (including associated CIDR blocks)
* [Classic ELBs](http://docs.aws.amazon.com/elasticloadbalancing/latest/classic/introduction.html)
* [ALBs, NLBs (elbv2)](https://aws.amazon.com/documentation/elastic-load-balancing/)
* Available IPv4 Addresses per subnet (Note that the IPv4 addresses for any stopped instances are considered unavailable)

Items collected into Dynamodb will expire if no longer found (default is 48 hours). TTLs are controlled via environment variables passed to each import function. TTL time is expressed in seconds. It is a calculation of current time + TTL. Each import related DynamoDB table leverages [TTL](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/TTL.html) for object expiration

##### Collection subsystem runner process

The above noted cidr-house-rules collection functions are triggered by a [runner function](https://github.com/trulia/cidr-house-rules/blob/master/runner.py) which invokes the necessary number of
import functions based upon the number of AWS accounts managed and number of regions provided by AWS. The runner process allows for cidr-house-rules to scale given any number of AWS accounts to collect information from.

###### Import functions invokation visual

![import-function-invoke](https://user-images.githubusercontent.com/538171/37374885-71c37074-26da-11e8-9531-182c228088a9.png)

#### API interface

An API interface is provided to expose collected data for consumption. Example usage is through Terraform's [http data source](https://www.terraform.io/docs/providers/http/data_source.html)

* retrieve all NAT Gateways for a given AWS account (team)
* retrieve all EIPs for a given AWS account (team)
* lookup a given CIDR block, i.e. 10.0.16.0/16 for potential VPC peering conflicts

#### Terraform modules that use cidr-house-rules for dynamic data

* [Dynamic NAT Gateway Security Group Terraform Module](https://github.com/trulia/cidr-house-rules-terraform-nat-gateway-sg)

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
  source                          = "git::ssh://git@github.com/trulia/cidr-house-rules-role.git?ref=v0.0.1"
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

```bash
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

##### Obtain NAT gateways for platform, webteam and dataeng teams

```bash
curl \
  --header "X-Api-Key: <GET_KEY_FROM_AWS_API_GATEWAY>" \
   https://yourapigateway-endpoint-generated-by-serverless.com/prod/get_nat_gateways_for_team?platform&webteam&dataeng

# Or just one team
curl \
  --header "X-Api-Key: <GET_KEY_FROM_AWS_API_GATEWAY>" \
  https://yourapigateway-endpoint-generated-by-serverless.com/prod/get_nat_gateways_for_team?team=platform
```

##### Obtain NAT gateways for all monitored accounts

```bash
curl \
  --header "X-Api-Key: <GET_KEY_FROM_AWS_API_GATEWAY>" \
   https://yourapigateway-endpoint-generated-by-serverless.com/prod/get_nat_gateways_for_all
```

##### Obtain number of result pages for NAT gatways, useful for Terraform to count out resources on

```bash
# Default is 50 results per page
curl --header "X-Api-Key: <GET_KEY_FROM_AWS_API_GATEWAY>" 'https://yourapigateway-endpoint-generated-by-serverless.com/prod/get_number_of_nat_gateway_pages'
```

```bash
# Request number of results per page to be 10, and return total number of pages
curl --header "X-Api-Key: <GET_KEY_FROM_AWS_API_GATEWAY>" 'https://yourapigateway-endpoint-generated-by-serverless.com/prod/get_number_of_nat_gateway_pages?results_per_page=10'
```

##### Obtain paged results of Nat gateways results

```bash
curl --header "X-Api-Key: <GET_KEY_FROM_AWS_API_GATEWAY>" 'https://yourapigateway-endpoint-generated-by-serverless.com/prod/get_nat_gateways_for_all?results_per_page=10&page=4'
```

##### Check for a VPC CIDR conflict

```bash
curl \
  --header "X-Api-Key: <GET_KEY_FROM_AWS_API_GATEWAY>" \
  https://yourapigateway-endpoint-generated-by-serverless.com/dev/check_conflict?cidr=10.17.0.0/16
```

##### Obtain all ELBs, ALBs, NLBs across all accounts

```bash
curl \
--header "X-Api-Key: <GET_KEY_FROM_AWS_API_GATEWAY>" \
https://yourapigateway-endpoint-generated-by-serverless.com/dev/get_elbs_for_all
```

##### Obtain all PrivateLink endpoint services across all accounts

```bash
curl \
--header "X-Api-Key: <GET_KEY_FROM_AWS_API_GATEWAY>" \
https://yourapigateway-endpoint-generated-by-serverless.com/dev/get_service_endpoints_for_all
```

##### Obtain a specific PrivateLink endpoint service based upon the "Name" tag of an NLB associated with it. (AWS presently doesn't allow tagging of PrivateLink endpoint services, so next best option is to use tags of NLB associated with PrivateLink)

```bash
curl \
--header "X-Api-Key: <GET_KEY_FROM_AWS_API_GATEWAY>" \
https://yourapigateway-endpoint-generated-by-serverless.com/dev/get_service_endpoints_for_nlb?nlb=my-nlb
```

##### Add a new account

```bash
curl \
  --header "X-Api-Key: <GET_KEY_FROM_AWS_API_GATEWAY>" \
  https://yourapigateway-endpoint-generated-by-serverless.com/dev/add_account?team=my_aws_account_alias_here&account=35682931234
```

#####  Supporting Terraform

[cird-house-rules-role](https://github.com/trulia/cidr-house-rules-role) - use this Terraform on your accounts you would like your cidr-house-rules deployment to have access to. The outputs on this Terraform can then be used in your serverless.yml. The account number of the remote account can then be added using the `add_account` API endpoint.
