# Deploying DeepSeek Model R1 on AWS via Terraform & GitHub Actions - Update
![Architecture Diagram](https://github.com/Fidelisesq/DeepSeekR1-AWS-GitHubActions-Terraform/blob/main/Images/architecture%20diagram.png)

Hey there! In this project documentation, I’m going to walk you through how I deployed the **DeepSeek Model R1** on AWS using **Terraform** and **GitHub Actions**. If you’ve ever tried deploying a machine learning model, you know it can get pretty complicated—especially when you’re juggling multiple AWS services. To make things easier, I decided to automate the whole process using Terraform for infrastructure as code and GitHub Actions for CI/CD. Spoiler alert: it worked like a charm!

This project involved setting up an EC2 instance, an Application Load Balancer (ALB), security groups, IAM roles, and even a custom domain using Route 53. The best part? Everything was automated, so I didn’t have to manually configure resources every time I made a change. Whether you’re a seasoned DevOps pro or just getting started with cloud deployments, I hope this walkthrough gives you some useful insights (and maybe saves you a few headaches along the way).


In this update, I’ve **migrated my EC2 instance to a private subnet** for improved security while still ensuring seamless access for application configuration and management. Here’s what changed:  

✅ **Private Subnet Deployment** – The EC2 instance now runs in a private subnet instead of a public one.  
✅ **Internet Access via NAT Gateway** – The instance can pull updates and dependencies while remaining inaccessible from the public internet.  
✅ **AWS Systems Manager (SSM) for Secure Access** – Instead of SSH, I’m using SSM to manage and interact with the instance securely.  
✅ **AWS WAF for Backend Protection** – Added AWS Web Application Firewall (WAF) to safeguard against malicious traffic and attacks.

This approach **enhances security** while maintaining full operational control over the deployment. Next steps? Further optimizing performance and security! 

---

## Table of Contents
1. **Introduction**
2. **Project Overview**
3. **Terraform Configuration**
   - Provider Configuration
   - Security Groups
   - Load Balancer (ALB)
   - EC2 Instance
   - IAM Roles and Instance Profile
   - Route 53 DNS Record
   - Terraform Backend (S3)
   - AWS WAF Configuration
4. **GitHub Actions Workflow**
   - Workflow Triggers
   - Setup Job
   - Apply Job
   - Post-Apply Job
   - Destroy Job
5. **Challenges Faced**
6. **Lessons Learned**
7. **Future Improvements**
8. **Conclusion**

---

## 1. Introduction

Deploying machine learning models in production can be a complex task, especially when it involves multiple AWS services. To streamline this process, I used **Terraform** to define the infrastructure as code and **GitHub Actions** to automate the deployment pipeline. This approach ensures consistency, scalability, and repeatability.

---

## 2. Project Overview

The goal of this project was to deploy the **DeepSeek Model R1** on AWS, making it accessible via a web interface (OpenWebUI) and an API (Ollama). The infrastructure includes:

- **EC2 Instance**: Hosts the DeepSeek model in a Docker container and associated services in a private subnet.
- **AWS Systems Manager (SSM)**: Provides secure connection to EC2 in private subnet via VPC Endpoints.
- **Application Load Balancer (ALB)**: Distributes traffic to the EC2 instance and handles SSL termination.
- **Security Groups**: Control inbound and outbound traffic to the ALB and EC2 instance.
- **IAM Roles**: Provide the necessary permissions for the EC2 instance to allow AWS Systems Manager Access
- **Route 53**: Manages DNS records for the ALB. I just employed a cetificate I already have in us-east-1 and a ready public hosted zone in same region.
- **Terraform Backend**: Stores the Terraform state file in an S3 bucket for team collaboration.
- **AWF**: Protects the backend against bad requests

---

## 3. Terraform Configuration & Data 

The Terraform configuration is the backbone of this project. It defines all the AWS resources required for the deployment. Below is a breakdown of the key components:

### AWS Provider & VPC Configuration

The first step in the Terraform configuration is to define the AWS provider and specify the region:

```hcl
provider "aws" {
  region = "us-east-1"
}

# Fetch existing VPC
data "aws_vpc" "main_vpc" {
  id = var.vpc_id
}
```

### Security Groups

I created 3 security groups: one for the ALB and one for the EC2 instance and the last for the VPC endpoints. The ALB security group allows HTTPS traffic (port 443). The EC2 security group restricts traffic to only allow communication from the ALB on ports 8080 (OpenWebUI) and the security group of the VPC endpoints.

```hcl
## Security Group for EC2 (Only ALB can access it)
resource "aws_security_group" "deepseek_ec2_sg" {
  name        = "deepseek_ec2_sg"
  description = "Security group for EC2 instance"
  vpc_id      = data.aws_vpc.main_vpc.id

  # Allow traffic from ALB 
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
```

### Load Balancer (ALB) & Listener

The ALB is configured to listen on ports 443 (HTTPS) and forwards traffic to the target group that has the EC2.

```hcl
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
```

### EC2, IAM & VPC Endpoints

The EC2 instance is configured with a gp3 EBS volume (48GB) and an IAM role for necessary permissions. The instance is placed in a public subnet and associated with the EC2 security group. Note: `An instance with GPU support like p3.2xlarge, g4dn.xlarge etc would do better here to handle bigger model and process responses faster` but I didn't get one approved by AWS at the time of project execution. So, I used `c4.4xlarge`.

```hcl
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
```


### Route 53 DNS Record

A Route 53 DNS record is created to map the ALB’s DNS name to a custom domain. Like I mentioned above, I used an already existing certificate to enable SSL and I also employed an existing hosted zone in us-east-1.

```hcl
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
```

### AWS WAF Configuration

```hcl
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

# AWS Managed Known Bad Inputs Rule Set
  rule {
    name     = "KnownBadInputsRule"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "KnownBadInputsRule"
      sampled_requests_enabled   = true
    }
  }

# AWS Managed Common Rule Set
rule {
  name     = "CommonRuleSet"
  priority = 4

  override_action {
    none {}  # Ensures AWS WAF applies its built-in block actions
  }

  statement {
    managed_rule_group_statement {
      vendor_name = "AWS"
      name        = "AWSManagedRulesCommonRuleSet"

      # Override specific rules that are set to "Count" by default, so they actually block bad traffic.
      rule_action_override {
        action_to_use {
          block {}
        }
        name = "CrossSiteScripting_URIPATH_RC_COUNT"
      }

      rule_action_override {
        action_to_use {
          block {}
        }
        name = "CrossSiteScripting_BODY_RC_COUNT"
      }

      rule_action_override {
        action_to_use {
          block {}
        }
        name = "CrossSiteScripting_QUERYARGUMENTS_RC_COUNT"
      }

      rule_action_override {
        action_to_use {
          block {}
        }
        name = "CrossSiteScripting_COOKIE_RC_COUNT"
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "CommonRuleSet"
    sampled_requests_enabled   = true
  }
}

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "deepseek-waf"
    sampled_requests_enabled   = true
  }
}

#WAF Attachment to ALB
resource "aws_wafv2_web_acl_association" "deepseek_waf_alb" {
  resource_arn = aws_lb.deepseek_lb.arn
  web_acl_arn  = aws_wafv2_web_acl.deepseek_waf.arn
  depends_on = [aws_lb.deepseek_lb,
  aws_wafv2_web_acl.deepseek_waf
  ]
}
```

### Terraform Backend (S3)

The Terraform state file is stored in an S3 bucket to enable team collaboration and state management.

```hcl
terraform {
  backend "s3" {
    bucket         = "foz-terraform-state-bucket"
    key            = "infra.tfstate"
    region         = "us-east-1"
    encrypt        = true
  }
}
```

### Variables Configuration

The `variables.tf` file defines all the input variables required for the Terraform configuration. These variables make the configuration reusable and customizable.

```hcl
variable "vpc_id" {
  description = "The VPC ID where resources will be deployed"
  type        = string
}

variable "public_subnet_ids" {
  description = "List of public subnet IDs for ALB"
  type        = list(string)
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs for EC2 instances"
  type        = list(string)
}

variable "ami_id" {
  description = "AMI ID for the EC2 instance"
  type        = string
}

variable "instance_type" {
  description = "Instance type for the EC2 instance"
  type        = string
}

variable "certificate_arn" {
  description = "ARN of the SSL certificate for HTTPS"
  type        = string
}

variable "hosted_zone_id" {
  description = "Route 53 hosted zone ID for the domain"
  type        = string
}
```

### Terraform.tfvars

The `terraform.tfvars` file is used to assign values to the variables defined in `variables.tf`. This file is typically not committed to version control (e.g., Git) for security reasons, as it may contain sensitive information like AWS credentials. I added `terraform.tfvars` to `.gitignore` so it won't be tracked. I provided the variables and secrets in github using `environment variables` and `secrets`. Also, the values below are made up and not real.

```hcl
vpc_id = "vpc-012345678910"
private_subnet_ids = ["subnet-0012345678910", "subnet-0012345678910", "subnet-0012345678910"]
instance_type = "c4.4xlarge" # bigger for production but t2.2xlarge test
ami_id = "ami-04b4f1a9cf54c11d0"
certificate_arn   = "arn:aws:acm:us-east-1:012345678910:certificate/697cf89b-9931-435f-a5f0-c8f012345678910c"
hosted_zone_id    = "Z012345678960X9UZZVPUYYW0H"
public_subnet_ids = ["subnet-0012345678910","subnet-012345678910"]

```

### Output Configuration

The output.tf file defines the outputs that Terraform will display after applying the configuration. I used these outputs for retrieving information like the EC2 instance’s public IP or the ALB’s DNS name that are needed for my `Github Action workflow` to configure my EC2 instances.
```hcl
output "ec2_public_ip" {
  description = "Public IP of the EC2 instance"
  value       = aws_instance.deepseek_ec2.public_ip
}

output "lb_url" {
  description = "DNS name of the ALB"
  value       = aws_lb.deepseek_lb.dns_name
}

output "deepseek_ec2_sg_id" {
  value = aws_security_group.deepseek_ec2_sg.id
}

output "deepseek_ec2_id" {
  value = aws_instance.deepseek_ec2.id
}

```
---

## 4. GitHub Actions Workflow

The GitHub Actions workflow automates the deployment process. It consists of four main jobs: **setup**, **apply**, **post-apply**, and **destroy**. My workflow will be triggered by pushing to the main branch or manually through the GitHub UI using workflow dispatch with an input to choose the action (apply/destroy).

### Workflow Triggers

The workflow is triggered on a push to the `main` branch or manually via the `workflow_dispatch` event. The manual trigger allows you to choose between **apply** (to create resources) and **destroy** (to tear down resources).

```yaml
on:
  push:
    branches:
      - main
  workflow_dispatch:
    inputs:
      action:
        description: "Choose action (apply/destroy)"
        required: true
        default: "apply"
        type: choice
        options:
          - apply
          - destroy
```

### Setup Job

The **setup** job initializes the environment by checking out the code, setting up Terraform, and configuring AWS credentials.

```yaml
name: Deploying DeepSeek Model R1 on AWS via Terraform & GitHub Actions

on:
  push:
    branches:
      - main
  workflow_dispatch:
    inputs:
      action:
        description: "Choose action (apply/destroy)"
        required: true
        default: "apply"
        type: choice
        options:
          - apply
          - destroy

jobs:
  setup:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Terraform
        uses: hashicorp/setup-terraform@v3

      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ${{ secrets.AWS_DEFAULT_REGION }}
```

### Apply Job

The **apply** job runs Terraform to create the infrastructure. It generates a `terraform.tfvars` file using GitHub Secrets, initializes Terraform, and applies the configuration. This is where my `Github Actions Runner` SSH into my EC2 to install docker, pulls the images and deploy `Ollama` and `OpenWebUI`using Docker.

```yaml
  apply:
    runs-on: ubuntu-latest
    outputs:
      ec2_instance_id: ${{ steps.get_ec2_id.outputs.ec2_id }}
    needs: setup
    if: |
      (github.event_name == 'workflow_dispatch' && github.event.inputs.action == 'apply') ||
      (github.event_name == 'push' && !contains(github.event.head_commit.message, 'destroy'))
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Terraform
        uses: hashicorp/setup-terraform@v3

      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ${{ secrets.AWS_DEFAULT_REGION }}

      - name: Create terraform.tfvars
        run: |
          cat <<EOF > terraform.tfvars
          ami_id = "${{ secrets.AMI_ID }}"
          certificate_arn = "${{ secrets.CERTIFICATE_ARN }}"
          vpc_id = "${{ secrets.VPC_ID }}"
          hosted_zone_id = "${{ secrets.HOSTED_ZONE_ID }}"
          instance_type = "${{ secrets.INSTANCE_TYPE }}"
          aws_access_key_id = "${{ secrets.AWS_ACCESS_KEY_ID }}"
          aws_secret_access_key = "${{ secrets.AWS_SECRET_ACCESS_KEY }}"
          aws_region = "${{ secrets.AWS_DEFAULT_REGION }}"
          public_subnet_ids = ${{ secrets.PUBLIC_SUBNET_IDS }}
          private_subnet_ids = ${{ secrets.PRIVATE_SUBNET_IDS }}
          EOF

      - name: Mask AWS Account ID in Logs
        run: echo "::add-mask::${{ secrets.AWS_ACCOUNT_ID }}"

      - name: Terraform Init & Apply
        run: |
          terraform init \
            -backend-config="bucket=${{ secrets.TERRAFORM_STATE_BUCKET }}" \
            -backend-config="key=infra.tfstate" \
            -backend-config="region=${{ secrets.AWS_DEFAULT_REGION }}"
          terraform apply -auto-approve -var-file=terraform.tfvars

      - name: Retrieve EC2 Instance ID
        id: get_ec2_id
        run: |
          echo "Retrieving EC2 Instance ID..."
          EC2_ID=$(terraform output -raw deepseek_ec2_id)
          echo "EC2_INSTANCE_ID=$EC2_ID" >> $GITHUB_ENV
          echo "::set-output name=ec2_id::$EC2_ID"
        

      - name: Verify EC2 Instance ID
        run: |
          echo "EC2_INSTANCE_ID=${{ env.EC2_INSTANCE_ID }}"
          if [ -z "${{ env.EC2_INSTANCE_ID }}" ]; then
            echo "EC2 instance ID is empty or invalid."
            exit 1
          fi
          
      - name: Wait for EC2
        run: sleep 60    
```

### Post-Apply Job

The **post-apply** job configures the EC2 instance after Terraform provisions it. It verifies the instance's connection via AWS SSM, checks if the SSM agent is running, and installs Docker along with necessary dependencies. After rebooting the instance, it deploys the **DeepSeek Model R1** inside an **Ollama** container and sets up **Open WebUI** for interaction. Finally, it confirms that the WebUI is accessible via `https://deepseek.fozdigitalz.com`. This ensures a fully automated deployment of the model and web interface on AWS.

```yaml
  post_apply:
    runs-on: ubuntu-latest
    needs: apply
    if: success()
    env:
      EC2_INSTANCE_ID: ${{ needs.apply.outputs.ec2_instance_id }}
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Terraform
        uses: hashicorp/setup-terraform@v3

      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ${{ secrets.AWS_DEFAULT_REGION }}


      - name: Create terraform.tfvars
        run: |
          cat <<EOF > terraform.tfvars
          ami_id = "${{ secrets.AMI_ID }}"
          certificate_arn = "${{ secrets.CERTIFICATE_ARN }}"
          vpc_id = "${{ secrets.VPC_ID }}"
          hosted_zone_id = "${{ secrets.HOSTED_ZONE_ID }}"
          instance_type = "${{ secrets.INSTANCE_TYPE }}"
          aws_access_key_id = "${{ secrets.AWS_ACCESS_KEY_ID }}"
          aws_secret_access_key = "${{ secrets.AWS_SECRET_ACCESS_KEY }}"
          aws_region = "${{ secrets.AWS_DEFAULT_REGION }}"
          public_subnet_ids = ${{ secrets.PUBLIC_SUBNET_IDS }}
          private_subnet_ids = ${{ secrets.PRIVATE_SUBNET_IDS }}
          EOF

      - name: Verify SSM Connection
        run: |
          echo "Verifying SSM Connection..."
          aws ssm describe-instance-information --region ${{ secrets.AWS_DEFAULT_REGION }} \
            --query "InstanceInformationList[?InstanceId=='${{ env.EC2_INSTANCE_ID }}']" \
            --output json

      - name: Check SSM Agent Status
        run: |
          aws ssm send-command \
            --document-name "AWS-RunShellScript" \
            --instance-ids "${{ env.EC2_INSTANCE_ID }}" \
            --parameters '{"commands":["sudo systemctl status amazon-ssm-agent"]}' \
            --region ${{ secrets.AWS_DEFAULT_REGION }}
          
      - name: Install Docker via SSM
        run: |
          aws ssm send-command \
            --document-name "AWS-RunShellScript" \
            --targets "[{\"Key\":\"InstanceIds\",\"Values\":[\"${{ env.EC2_INSTANCE_ID }}\"]}]" \
            --parameters commands='[
              "sudo apt-get update",
              "sudo apt-get install -y docker.io docker-compose",
              "sudo systemctl enable docker",
              "sudo systemctl start docker",
              "sudo usermod -aG docker ubuntu",
              "sudo sed -i s/^ENABLED=1/ENABLED=0/ /etc/apt/apt.conf.d/20auto-upgrades",
              "sleep 10",
              "sudo reboot"
            ]' \
            --region ${{ secrets.AWS_DEFAULT_REGION }}
          
      - name: Wait for EC2 instance to reboot ..."
        run: sleep 50

      - name: Run DeepSeek Model and WebUI via SSM
        run: |
          aws ssm send-command \
            --document-name "AWS-RunShellScript" \
            --targets "[{\"Key\":\"InstanceIds\",\"Values\":[\"${{ env.EC2_INSTANCE_ID }}\"]}]" \
            --parameters commands='[
              "docker run -d -v ollama:/root/.ollama -p 11434:11434 --name ollama ollama/ollama",
              "sleep 20",
              "docker exec ollama ollama pull deepseek-r1:8b",
              "sleep 15",
              "docker exec -d ollama ollama serve",
              "sleep 15",
              "docker run -d -p 8080:8080 --add-host=host.docker.internal:host-gateway -v open-webui:/app/backend/data --name open-webui --restart always ghcr.io/open-webui/open-webui:main",
              "sleep 15"
            ]' \
            --region ${{ secrets.AWS_DEFAULT_REGION }}
      
          echo "Waiting for WebUI to start..."
          sleep 30              

      - name: Confirm WebUI is Running
        run: |
          aws ssm send-command \
            --document-name "AWS-RunShellScript" \
            --targets '[{"Key":"instanceIds","Values":["${{ env.EC2_INSTANCE_ID }}"]}]' \
            --parameters '{"commands":["curl -I https://deepseek.fozdigitalz.com"]}' \
            --region ${{ secrets.AWS_DEFAULT_REGION }}

```
### Destroy Job

The **destroy** job tears down the infrastructure when triggered manually or via a commit message containing "destroy".

```yaml
  destroy:
    runs-on: ubuntu-latest
    needs: setup
    if: |
      (github.event_name == 'workflow_dispatch' && github.event.inputs.action == 'destroy') ||
      (github.event_name == 'push' && contains(github.event.head_commit.message, 'destroy'))
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Terraform
        uses: hashicorp/setup-terraform@v3

      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ${{ secrets.AWS_DEFAULT_REGION }}
      
      - name: Create terraform.tfvars
        run: |
          cat <<EOF > terraform.tfvars
          ami_id = "${{ secrets.AMI_ID }}"
          certificate_arn = "${{ secrets.CERTIFICATE_ARN }}"
          vpc_id = "${{ secrets.VPC_ID }}"
          hosted_zone_id = "${{ secrets.HOSTED_ZONE_ID }}"
          instance_type = "${{ secrets.INSTANCE_TYPE }}"
          aws_access_key_id = "${{ secrets.AWS_ACCESS_KEY_ID }}"
          aws_secret_access_key = "${{ secrets.AWS_SECRET_ACCESS_KEY }}"
          aws_region = "${{ secrets.AWS_DEFAULT_REGION }}"
          public_subnet_ids = ${{ secrets.PUBLIC_SUBNET_IDS }}
          private_subnet_ids = ${{ secrets.PRIVATE_SUBNET_IDS }}
          EOF
  
      - name: Mask AWS Account ID in Logs
        run: echo "::add-mask::${{ secrets.AWS_ACCOUNT_ID }}"

      - name: Terraform Destroy
        run: |
          terraform init -reconfigure \
            -backend-config="bucket=${{ secrets.TERRAFORM_STATE_BUCKET }}" \
            -backend-config="key=infra.tfstate" \
            -backend-config="region=${{ secrets.AWS_DEFAULT_REGION }}"
          terraform destroy -auto-approve -var-file=terraform.tfvars
```
`Completed workflow run`
![completed_workflow_run](https://github.com/Fidelisesq/DeepSeekR1-AWS-GitHubActions-Terraform/blob/main/Images/Completed_workflow_run2.png)

---
## **5. The Application in Action (Result)**

After successfully deploying the DeepSeek Model R1 on AWS, I was able to access the OpenWebUI and interact with the model. Below are some screenshots demonstrating the setup and functionality:

### **1. OpenWebUI Interface**
The OpenWebUI provides a user-friendly interface for interacting with the DeepSeek Model R1. Here’s a screenshot of the dashboard:

![OpenWebUI Dashboard](https://github.com/Fidelisesq/DeepSeekR1-AWS-GitHubActions-Terraform/blob/main/Images/interface-getting%20started.png)

*The OpenWebUI dashboard, accessible via the custom domain `deepseek.fozdigitalz.com`.*

![OpenWebUI Welcome Page](https://github.com/Fidelisesq/DeepSeekR1-AWS-GitHubActions-Terraform/blob/main/Images/openwebui-welcome-page.png)
`OpenWebUI Welcome Page`

### **2. Model Interaction**
I tested the model by asking it a few questions. Here’s an example of the model’s response:

![Model Response-11](https://github.com/Fidelisesq/DeepSeekR1-AWS-GitHubActions-Terraform/blob/main/Images/model-response-1.png)
`Sample model response 11` *The DeepSeek Model R1 generating a response to a sample query.*

![Sample model response-12](https://github.com/Fidelisesq/DeepSeekR1-AWS-GitHubActions-Terraform/blob/main/Images/model-response11.png)
`Sample model response 12`

![Sample model response 21](https://github.com/Fidelisesq/DeepSeekR1-AWS-GitHubActions-Terraform/blob/main/Images/model-response-2.png)
`Sample model response 21`

![Sample model response 22](https://github.com/Fidelisesq/DeepSeekR1-AWS-GitHubActions-Terraform/blob/main/Images/model-response-22.png)
`Sample model response 22`

### **3. Infrastructure Clean Up**
I can destroy my infrastructure when I trigger my workflow in different ways. My workflow will be triggered by pushing to the main branch or manually through the GitHub UI using workflow dispatch with an input to choose the action (apply/destroy).
- By manually triggering the workflow from the GitHub UI and selecting the `destroy` action.
- By pushing to the `main` branch with a commit message that contains the word `destroy.`
- By running the command `gh workflow run "workflow name" --field action=destroy` locally but you must have the Github CLI installed for this to work.

![terraform destroy](https://github.com/Fidelisesq/DeepSeekR1-AWS-GitHubActions-Terraform/blob/main/Images/Terraform%20destroy.png)
`Infrastructure cleanup using terraform`

## **6. Challenges Faced & Lesson Learned**

Learning from the challenges in my first deployment, modifying the setup was easier—I moved the EC2 instance to a private subnet, switched from SSH to AWS SSM for secure access, and integrated AWS WAF for better protection. However, I still researched best practices for implementing AWS-managed WAF rules to enhance security effectively.

---


## 7. Future Improvements

While the deployment process is now functional, there are opportunities I may consider to enhance scalability, security, and cost-efficiency.

In my first deployment, I considered improvements like moving EC2 to a private subnet, using SSM instead of SSH, and adding WAF, which I have now implemented. Additionally, I’m exploring **CloudWatch for monitoring, auto-scaling for better resource management, and GPU instances for enhanced performance**, though AWS approval for GPU is still pending. These refinements aim to make the deployment more secure, scalable, and cost-efficient.

---

## 8. Conclusion

This deployment has evolved significantly from the initial setup, incorporating **better security, automation, and scalability** based on lessons learned. Moving EC2 to a private subnet, using **AWS SSM** instead of SSH, and integrating **AWS WAF** has strengthened security, while **CloudWatch and auto-scaling** are now key considerations for future improvements. As I continue refining the architecture, I’m also exploring **GPU-powered instances** for better performance once AWS approval is granted. These enhancements ensure a more **resilient, efficient, and secure** deployment of the DeepSeek Model R1 on AWS.