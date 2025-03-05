# Provider configuration
provider "aws" {
  region = "us-east-1"
}

# Declare the caller identity data resource
data "aws_caller_identity" "current" {}


# Security Group for ALB (Allows direct access)
resource "aws_security_group" "alb_sg" {
  name        = "deepseek_alb_sg"
  description = "Security group for ALB"
  vpc_id      = var.vpc_id

  # Allow HTTPS and Ollama API access from anywhere (or restrict it to your needs)
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Adjust if needed
  }

  ingress {
    from_port   = 11434
    to_port     = 11434
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Adjust if needed
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

# Application Load Balancer (Public Subnet)
resource "aws_lb" "deepseek_lb" {
  name               = "deepseek-alb"
  internal           = false   # Public ALB
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = var.public_subnet_ids  # ALB must be in public subnets
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
  name        = "ollama-api-target-group"
  port        = 11434
  protocol    = "HTTP"
  target_type = "instance"
  vpc_id      = var.vpc_id

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
  key_name        = data.aws_key_pair.existing_key.key_name
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

# Route 53 DNS Record to point to ALB
resource "aws_route53_record" "deepseek_dns" {
  zone_id = var.hosted_zone_id
  name    = "deepseek.fozdigitalz.com"
  type    = "A"

  alias {
    name                   = aws_lb.deepseek_lb.dns_name
    zone_id                = aws_lb.deepseek_lb.zone_id
    evaluate_target_health = false
  }
}

#AWS Web Application Firewall
resource "aws_wafv2_web_acl" "deepseek_waf" {
  name        = "deepseek-waf"
  description = "WAF for ALB protecting backend"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  # AWS Managed Rule: SQL Injection Protection
  rule {
    name     = "AWS-SQLInjection-Protection"
    priority = 1

    action {
      block {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "SQLInjectionProtection"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed Rule: XSS Protection
  rule {
    name     = "AWS-XSS-Protection"
    priority = 2

    action {
      block {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesXSSRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "XSSProtection"
      sampled_requests_enabled   = true
    }
  }

  # Rate Limiting Rule (Limits requests from a single IP)
  rule {
    name     = "RateLimit"
    priority = 3

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 200  # Max requests allowed per 5 minutes
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimit"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed Rule: Bot Protection (Blocks known bad bots)
  rule {
    name     = "AWS-Bot-Control"
    priority = 4

    action {
      block {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesBotControlRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "BotProtection"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "deepseek-waf"
    sampled_requests_enabled   = true
  }
}


#WAF Attachement to ALB
resource "aws_wafv2_web_acl_association" "deepseek_waf_alb" {
  resource_arn = aws_lb.deepseek_lb.arn
  web_acl_arn  = aws_wafv2_web_acl.deepseek_waf.arn
  depends_on = [aws_lb.deepseek_lb,
  aws_wafv2_web_acl.deepseek_waf
  ]
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
