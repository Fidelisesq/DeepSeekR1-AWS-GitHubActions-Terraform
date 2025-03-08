# Provider configuration
provider "aws" {
  region = "us-east-1"
}

# Fetch existing VPC
data "aws_vpc" "main_vpc" {
  id = var.vpc_id
}

# Security Groups
## Security Group for EC2 (Only ALB can access it)
resource "aws_security_group" "deepseek_ec2_sg" {
  name        = "deepseek_ec2_sg"
  description = "Security group for EC2 instance"
  vpc_id      = data.aws_vpc.main_vpc.id

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

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

## Security Group for ALB (Allows direct access)
resource "aws_security_group" "alb_sg" {
  name        = "deepseek_alb_sg"
  description = "Security group for ALB"
  vpc_id      = data.aws_vpc.main_vpc.id

  # Allow HTTPS from anywhere
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
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

## Security Group for VPC Endpoints
resource "aws_security_group" "endpoint_sg" {
  name        = "vpc-endpoint-sg"
  description = "Security group for VPC Endpoints"
  vpc_id      = data.aws_vpc.main_vpc.id

  # Allow traffic from EC2 to VPC Endpoints
  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.deepseek_ec2_sg.id]
  }

  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.deepseek_ec2_sg.id]
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Load Balancer
resource "aws_lb" "deepseek_lb" {
  name               = "deepseek-alb"
  internal           = false   # Public ALB
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = var.public_subnet_ids  # ALB must be in public subnets
}

## Listener for ALB (HTTPS) forwards traffic to OpenWebUI
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

# Target Groups
resource "aws_lb_target_group" "deepseek_tg" {
  name     = "deepseek-target-group"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = data.aws_vpc.main_vpc.id

  health_check {
    path                = "/"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
}


# IAM Role for SSM
resource "aws_iam_role" "ssm_role" {
  name = "EC2SSMRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

# Attach AmazonSSMManagedInstanceCore policy
resource "aws_iam_role_policy_attachment" "ssm_policy" {
  role       = aws_iam_role.ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# IAM Instance Profile
resource "aws_iam_instance_profile" "ssm_instance_profile" {
  name = "EC2SSMInstanceProfile"
  role = aws_iam_role.ssm_role.name
}

# EC2 Instance
resource "aws_instance" "deepseek_ec2" {
  ami                  = var.ami_id
  instance_type        = var.instance_type
  subnet_id            = var.private_subnet_ids[0]
  security_groups      = [aws_security_group.deepseek_ec2_sg.id]
  iam_instance_profile = aws_iam_instance_profile.ssm_instance_profile.name

  root_block_device {
    volume_size           = 48
    volume_type           = "gp3"
    delete_on_termination = true
  }

  tags = {
    Name = "DeepSeekModelInstance"
  }
}

# Attach EC2 Instance to Target Group
resource "aws_lb_target_group_attachment" "deepseek_tg_attachment" {
  target_group_arn = aws_lb_target_group.deepseek_tg.arn
  target_id        = aws_instance.deepseek_ec2.id
  port             = 8080
}

# VPC Endpoints for SSM
resource "aws_vpc_endpoint" "ssm" {
  vpc_id            = data.aws_vpc.main_vpc.id
  service_name      = "com.amazonaws.us-east-1.ssm"
  vpc_endpoint_type = "Interface"
  subnet_ids        = var.private_subnet_ids
  security_group_ids = [aws_security_group.endpoint_sg.id]
  private_dns_enabled = true
}


# VPC Endpoint for EC2 Messages (Used by SSM)
resource "aws_vpc_endpoint" "ec2_messages" {
  vpc_id            = data.aws_vpc.main_vpc.id
  service_name      = "com.amazonaws.us-east-1.ec2messages"
  vpc_endpoint_type = "Interface"
  subnet_ids        = var.private_subnet_ids
  security_group_ids = [aws_security_group.endpoint_sg.id]
  private_dns_enabled = true
}

# VPC Endpoint for SSM Messages (Used by SSM)
resource "aws_vpc_endpoint" "ssm_messages" {
  vpc_id            = data.aws_vpc.main_vpc.id
  service_name      = "com.amazonaws.us-east-1.ssmmessages"
  vpc_endpoint_type = "Interface"
  subnet_ids        = var.private_subnet_ids
  security_group_ids = [aws_security_group.endpoint_sg.id]
  private_dns_enabled = true
}


# Route 53 DNS Record
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

  # Rate Limiting Rule
  rule {
    name     = "RateLimitRule"
    priority = 1

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 150
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimit"
      sampled_requests_enabled   = true
    }
  }

# Amazon IP Reputation List (Blocks known bad IPs, reconnaissance, DDoS)
  rule {
    name     = "AmazonIPReputationRule"
    priority = 2

    override_action { 
      none {} 
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesAmazonIpReputationList"

        # OPTIONAL: Override specific rules inside the group
        rule_action_override {
          action_to_use {
            block {}
          }
          name = "AWSManagedIPReputationList"
        }

        rule_action_override {
          action_to_use {
            block {}
          }
          name = "AWSManagedReconnaissanceList"
        }

        rule_action_override {
          action_to_use {
            count {}
          }
          name = "AWSManagedIPDDoSList"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AmazonIPReputationRule"
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
