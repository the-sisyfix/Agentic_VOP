output "build_instance_id" {
  description = "Instance ID of the build EC2 (use with: aws ssm start-session --target <id>)"
  value       = aws_instance.build.id
}

output "build_instance_private_ip" {
  description = "Private IPv4 address of the build EC2"
  value       = aws_instance.build.private_ip
}

output "ecr_repository_url" {
  description = "URL of the test ECR repository (docker tag/push target)"
  value       = aws_ecr_repository.hardened_base_test.repository_url
}

output "ecr_repository_arn" {
  description = "ARN of the test ECR repository"
  value       = aws_ecr_repository.hardened_base_test.arn
}

output "start_session_hint" {
  description = "Convenience command to open a shell on the build box via SSM"
  value       = "aws ssm start-session --target ${aws_instance.build.id} --region ${var.aws_region}"
}

output "ci_image_sign_role_arn" {
  description = "ARN of the GitHub Actions CI signing role (configure as the role-to-assume in the signing workflow)"
  value       = aws_iam_role.ci_image_sign.arn
}

output "sbom_bucket_name" {
  description = "Name of the S3 bucket where the build box uploads SBOMs (keyed by digest under sboms/)"
  value       = aws_s3_bucket.sbom.bucket
}
