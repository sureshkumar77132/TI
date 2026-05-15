package main

# Check for AWS S3 Buckets
deny[msg] {
    # 1. Look for resources of type S3 Bucket
    bucket := input.Resources[_]
    bucket.Type == "AWS::S3::Bucket"
    
    # 2. Check if PublicAccessBlockConfiguration is missing
    not bucket.Properties.PublicAccessBlockConfiguration
    
    # 3. Return this message if it fails
    msg = "CRITICAL: S3 Buckets must have PublicAccessBlockConfiguration to prevent public leaks."
}
