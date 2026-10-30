# ------------------------------------------------------------------------------
# Build EC2 instance + AMI lookup
# ------------------------------------------------------------------------------
# Ubuntu 22.04 LTS ARM64 (Canonical), matching the app-hosting convention.
# user-data installs the supply-chain toolchain (Docker, cosign, syft, trivy).
# No key pair / SSH — access is via SSM Session Manager only.

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd*/ubuntu-jammy-22.04-arm64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_instance" "build" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.build.id]
  iam_instance_profile   = aws_iam_instance_profile.build.name

  root_block_device {
    volume_size = var.volume_size
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = templatefile("${path.module}/templates/user-data.sh", {
    aws_region     = var.aws_region
    cosign_version = var.cosign_version
    syft_version   = var.syft_version
    trivy_version  = var.trivy_version
    copa_version   = var.copa_version
    buildkit_image = var.buildkit_image
  })
  user_data_replace_on_change = true

  tags = {
    Name = "${local.name}-build"
    Role = "build-ec2"
  }
}
