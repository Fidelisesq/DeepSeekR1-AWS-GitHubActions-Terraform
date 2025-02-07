# Provider configuration
provider "aws" {
  region = "us-east-1"
}

# Security Group for ALB
resource "aws_security_group" "alb_sg" {
  name        = "deepseek_alb_sg"
  description = "Security group for ALB"
  vpc_id      = var.vpc_id

  # Allow HTTPS traffic from anywhere
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "TCP"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow HTTP traffic for testing (optional, remove if not needed)
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow TCP traffic on port 11434 from anywhere
  ingress {
    from_port = 11434
    to_port = 11434
    protocol = "HTTP"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Security Group for EC2 (only allows traffic from ALB)
resource "aws_security_group" "deepseek_ec2_sg" {
  name        = "deepseek_ec2_sg"
  description = "Security group for EC2 instance"
  vpc_id      = var.vpc_id

  # Allow traffic from ALB on port 8080
  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  # Allow SSH for administration (optional, restrict CIDR in production)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${var.my_ip}/32"] # Change to your IP for security
  }

  #Allow tcp traffic on port 11434 from ALN
  ingress {
    from_port = 11434
    to_port = 11434
    protocol = "HTTP"
    security_groups = [aws_security_group.alb_sg.id]
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Load Balancer (ALB)
resource "aws_lb" "deepseek_lb" {
  name               = "deepseek-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = var.subnet_ids

  enable_deletion_protection = false
}

# Listener for ALB (HTTPS) forwards traffic to the openwebUI
resource "aws_lb_listener" "https_listener" {
  load_balancer_arn = aws_lb.deepseek_lb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.deepseek_tg.arn
  }
}

# HTTP Listener (Port 80) - Redirects to HTTPS
resource "aws_lb_listener" "http_listener" {
  load_balancer_arn = aws_lb.deepseek_lb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# Listener for ALB (Ollama API on port 11434)
resource "aws_lb_listener" "ollama_listener" {
  load_balancer_arn = aws_lb.deepseek_lb.arn
  port              = 11434
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ollama_api_tg.arn
  }
}


# Open_WebUI Target Group for ALB
resource "aws_lb_target_group" "deepseek_tg" {
  name     = "deepseek-target-group"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = var.vpc_id

  health_check {
    path                = "/"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
}
# Ollama container Target Group for ALB
resource "aws_lb_target_group" "ollama_api_tg" {
  name       = "ollama-api-target-group"
  port       = 11434
  protocol   = "HTTP"
  target_type = "instance"
  vpc_id     = var.vpc_id

  health_check {
    path                = "/"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
}

# Attach EC2 instance to Target Group
resource "aws_lb_target_group_attachment" "deepseek_ec2_attachment" {
  target_group_arn = aws_lb_target_group.deepseek_tg.arn
  target_id        = aws_instance.deepseek_ec2.id
  port             = 8080
}

# IAM Role for EC2
resource "aws_iam_role" "deepseek_ec2_role" {
  name = "deepseek_ec2_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}



# IAM Instance Profile for EC2
resource "aws_iam_instance_profile" "deepseek_ec2_profile" {
  name = "deepseek_ec2_profile"
  role = aws_iam_role.deepseek_ec2_role.name
}

data "aws_key_pair" "existing_key" {
  key_pair_id = var.key_id
}

# EC2 Instance with IAM Role and gp3 EBS (48GB)
resource "aws_instance" "deepseek_ec2" {
  ami             = var.ami_id
  instance_type   = var.instance_type
  key_name        = data.aws_key_pair.existing_key.key_name
  subnet_id       = var.public_subnet_id
  security_groups = [aws_security_group.deepseek_ec2_sg.id]
  iam_instance_profile = aws_iam_instance_profile.deepseek_ec2_profile.name

  root_block_device {
    volume_size           = 48
    volume_type           = "gp3"
    delete_on_termination = true
  }

  tags = {
    Name = "DeepSeekModelInstance"
  }
}



# Route 53 DNS Record for ALB
resource "aws_route53_record" "deepseek_dns" {
  zone_id = var.hosted_zone_id
  name    = "deepseek.fozdigitalz.com"
  type    = "A"

  alias {
    name                   = aws_lb.deepseek_lb.dns_name
    zone_id                = aws_lb.deepseek_lb.zone_id
    evaluate_target_health = true
  }
}

# Terraform Backend (S3 for State Management)
terraform {
  backend "s3" {
    bucket         = "foz-terraform-state-bucket"
    key            = "infra.tfstate"
    region         = "us-east-1"
    encrypt        = true
  }
}

