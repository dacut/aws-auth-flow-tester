# aws-auth-flow-tester
Test AWS authentication flows for order-of-operations.

This is used to determine how AWS behaves when authenication is incorrect or corrupt.
The results from this are used to guide how [Scratchstack](https://github.com/dacut/scratchstack) behaves.

## Running
In order to run these tests, you need to have a valid AWS configuration (credentials and region
selected). This library intentionally does not use the Boto standard settings to avoid mixing
AWS credentials and possible test system credentials.

This looks for configuration and credentials in the file named `test-config.ini`, which uses the
Python [`configparser`](https://docs.python.org/3/library/configparser.html#supported-ini-file-structure)
INI-style format. This is similar, but not identical, to the Boto and AWS CLI configuration format.

### Sample config file
```
# Default values for other services
[DEFAULT]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-west-2

# STS testing
[sts]
host = sts.us-west-2.amazonaws.com
service = sts
path = /

# S3 testing
[s3]
host = test-bucket.s3.us-west-2.amazonaws.com
service = s3
path = /test/
```