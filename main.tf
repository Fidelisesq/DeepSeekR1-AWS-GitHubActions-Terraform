# Provider configuration
provider "aws" {
  region = var.region
}

# Security Group for ALB (Restrict access to CloudFront only)
resource "aws_security_group" "alb_sg" {
  name        = "deepseek_alb_sg"
  description = "Security group for ALB"
  vpc_id      = var.vpc_id

  # Allow HTTPS traffic only from CloudFront
  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_group_id = aws_security_group.alb_sg.id
    source_prefix_list_id = "pl-68a54001" # AWS-managed CloudFront Prefix List
  }

  # Allow Ollama API traffic from CloudFront
  ingress {
    from_port       = 11434
    to_port         = 11434
    protocol        = "tcp"
    security_group_id = aws_security_group.alb_sg.id
    source_prefix_list_id = "pl-68a54001"
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Security Group for EC2 (Only ALB can access it)
resource "aws_security_group" "deepseek_ec2_sg" {
  name        = "deepseek_ec2_sg"
  description = "Security group for EC2 instance"
  vpc_id      = var.vpc_id

  # Allow traffic from ALB on OpenWebUI & Ollama API
  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  ingress {
    from_port       = 11434
    to_port         = 11434
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  # Allow SSH only from your IP
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${var.my_ip}/32"]
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Internal ALB (Private Subnet)
resource "aws_lb" "deepseek_lb" {
  name               = "deepseek-alb"
  internal           = true
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = var.private_subnet_ids
}

# Listener for ALB (HTTPS) forwards traffic to OpenWebUI
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

# Listener for Ollama API
resource "aws_lb_listener" "ollama_listener" {
  load_balancer_arn = aws_lb.deepseek_lb.arn
  port              = 11434
  protocol          = "HTTPS"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ollama_api_tg.arn
  }
}

# Target Groups
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

# EC2 Instance (Private Subnet)
resource "aws_instance" "deepseek_ec2" {
  ami             = var.ami_id
  instance_type   = var.instance_type
  key_name        = var.key_id
  subnet_id       = var.private_subnet_ids[0]
  security_groups = [aws_security_group.deepseek_ec2_sg.id]

  root_block_device {
    volume_size           = 48
    volume_type           = "gp3"
    delete_on_termination = true
  }

  tags = {
    Name = "DeepSeekModelInstance"
  }
}

# CloudFront Distribution
resource "aws_cloudfront_distribution" "deepseek_cloudfront" {
  origin {
    domain_name = aws_lb.deepseek_lb.dns_name
    origin_id   = "deepseek-alb"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  enabled = true
  default_root_object = "index.html"

  default_cache_behavior {
    target_origin_id       = "deepseek-alb"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true
    forwarded_values {
      query_string = true
      headers      = ["Authorization"]
      cookies {
        forward = "all"
      }
    }
  }

  viewer_certificate {
    acm_certificate_arn = var.certificate_arn
    ssl_support_method  = "sni-only"
  }
}

# Route 53 DNS Record for CloudFront
resource "aws_route53_record" "deepseek_dns" {
  zone_id = var.hosted_zone_id
  name    = "deepseek.fozdigitalz.com"
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.deepseek_cloudfront.domain_name
    zone_id                = aws_cloudfront_distribution.deepseek_cloudfront.hosted_zone_id
    evaluate_target_health = false
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
