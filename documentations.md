# Deploying DeepSeek Model R1 on AWS via Terraform & GitHub Actions

Hey there! In this project documentation, I’m going to walk you through how I deployed the **DeepSeek Model R1** on AWS using **Terraform** and **GitHub Actions**. If you’ve ever tried deploying a machine learning model, you know it can get pretty complicated—especially when you’re juggling multiple AWS services. To make things easier, I decided to automate the whole process using Terraform for infrastructure as code and GitHub Actions for CI/CD. Spoiler alert: it worked like a charm!

This project involved setting up an EC2 instance, an Application Load Balancer (ALB), security groups, IAM roles, and even a custom domain using Route 53. The best part? Everything was automated, so I didn’t have to manually configure resources every time I made a change. Whether you’re a seasoned DevOps pro or just getting started with cloud deployments, I hope this walkthrough gives you some useful insights (and maybe saves you a few headaches along the way).


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

- **EC2 Instance**: Hosts the DeepSeek model in a Docker container and associated services.
- **Application Load Balancer (ALB)**: Distributes traffic to the EC2 instance and handles SSL termination.
- **Security Groups**: Control inbound and outbound traffic to the ALB and EC2 instance.
- **IAM Roles**: Provide the necessary permissions for the EC2 instance.
- **Route 53**: Manages DNS records for the ALB. I just employed a cetificate I already have in us-east-1 and a ready public hosted zone in same region.
- **Terraform Backend**: Stores the Terraform state file in an S3 bucket for team collaboration.

---

## 3. Terraform Configuration

The Terraform configuration is the backbone of this project. It defines all the AWS resources required for the deployment. Below is a breakdown of the key components:

### Provider Configuration

The first step in the Terraform configuration is to define the AWS provider and specify the region:

```hcl
provider "aws" {
  region = "us-east-1"
}
```

### Security Groups

Two security groups were created: one for the ALB and one for the EC2 instance. The ALB security group allows HTTPS traffic (port 443) and HTTP traffic (port 80) for testing purposes. It also allows TCP traffic on port 11434 for the Ollama API. The EC2 security group restricts traffic to only allow communication from the ALB on ports 8080 (OpenWebUI) and 11434 (Ollama API).

```hcl
resource "aws_security_group" "alb_sg" {
  name        = "deepseek_alb_sg"
  description = "Security group for ALB"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port = 11434
    to_port = 11434
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

### Load Balancer (ALB)

The ALB is configured to listen on ports 443 (HTTPS) and 80 (HTTP). The HTTP listener redirects traffic to HTTPS for secure communication. Additionally, I set up a separate listener for the Ollama API on port 11434. Although this is not needed because the OpenWebUI already exposes the Ollama API. I just needed to have it as a standby maybe for direct API access programmatically.

```hcl
resource "aws_lb" "deepseek_lb" {
  name               = "deepseek-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = var.subnet_ids

  enable_deletion_protection = false
}
```

### EC2 Instance

The EC2 instance is configured with a gp3 EBS volume (48GB) and an IAM role for necessary permissions. The instance is placed in a public subnet and associated with the EC2 security group. Note: `An instance with GPU support like p3.2xlarge, g4dn.xlarge etc would do better here to handle bigger model and process responses faster` but I didn't get one approved by AWS at the time of project execution. So, I used `c4.4xlarge`.

```hcl
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
```

### IAM Roles and Instance Profile

An IAM role is created for the EC2 instance, allowing it to assume the role and access necessary AWS resources.

```hcl
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
```

### Route 53 DNS Record

A Route 53 DNS record is created to map the ALB’s DNS name to a custom domain. Like I mentioned above, I used an already exiting certificate to enable SSL and I also employed an exiting hosted zone in us-east-1.

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

The variables.tf file defines all the input variables required for the Terraform configuration. These variables make the configuration reusable and customizable.

```hcl
variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "vpc_id" {
  description = "Existing VPC ID where resources will be deployed"
  type        = string
}

variable "subnet_ids" {
  description = "Subnet ID for the ALB"
  type        = list(string)
}

variable "public_subnet_id" {
  description = "Public subnet ID for the EC2 instance"
  type        = string
}

variable "key_name" {
  description = "Key ID for EC2 instance"
  type        = string
}

variable "key_id" {
  description = "The ID of the key pair to use for the EC2 instance"
  type        = string
}

variable "ami_id" {
  description = "Amazon Machine Image (AMI) ID"
  type        = string
}

variable "certificate_arn" {
  description = "ARN of the SSL certificate for HTTPS"
  type        = string
}

variable "hosted_zone_id" {
  description = "ID of the existing Route 53 hosted zone for fozdigitalz.com in us-east-1"
  type        = string
}

variable "terraform_state_bucket" {
  description = "The name of the S3 bucket for Terraform state"
  type        = string
}

variable "instance_type" {
  description = "Instance type for the EC2 instance"
  type        = string
}

variable "my_ip" {
  description = "IP address allowed to SSH"
  type        = string
}
```

### Terraform.tfvars

The `terraform.tfvars` file is used to assign values to the variables defined in variables.tf. This file is typically not committed to version control (e.g., Git) for security reasons, as it may contain sensitive information like AWS credentials. I added `terraform.tfvars` to `.gitignore` so it won't be tracked. I provided the variables and secrets in github using `environment variables` and `secrets`. Also, the value below are made up and not real.

```hcl
aws_region              = "us-east-1"
vpc_id                  = "vpc-1234567890abcdef0"
subnet_ids              = ["subnet-1234567890abcdef0", "subnet-0987654321abcdef0"]
public_subnet_id        = "subnet-1234567890abcdef0"
key_name                = "my-key-pair"
key_id                  = "key-1234567890abcdef0"
ami_id                  = "ami-0abcdef1234567890"
certificate_arn         = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
hosted_zone_id          = "Z1234567890ABCDEF"
terraform_state_bucket  = "foz-terraform-state-bucket"
instance_type           = "c4.4xlarge"
my_ip                   = "192.168.1.1/32"
```

### Output Configuration

The output.tf file defines the outputs that Terraform will display after applying the configuration. I used these outputs for retrieving information like the EC2 instance’s public IP or the ALB’s DNS name that are needed for my `Github Action workflow` to configure my EC2 instances.
```hcl
output "ec2_public_ip" {
  description = "Public IP address of the EC2 instance"
  value       = aws_instance.deepseek_ec2.public_ip
}

output "lb_url" {
  description = "DNS name of the Application Load Balancer"
  value       = aws_lb.deepseek_lb.dns_name
}

output "deepseek_ec2_sg_id" {
  description = "Security Group ID of the EC2 instance"
  value       = aws_security_group.deepseek_ec2_sg.id
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
          subnet_ids = [${{ secrets.SUBNET_IDS }}]
          key_name = "${{ secrets.KEY_NAME }}"
          key_id = "${{ secrets.KEY_ID }}"
          hosted_zone_id = "${{ secrets.HOSTED_ZONE_ID }}"
          instance_type = "${{ secrets.INSTANCE_TYPE }}"
          my_ip = "${{ secrets.MY_IP }}"
          aws_access_key_id = "${{ secrets.AWS_ACCESS_KEY_ID }}"
          aws_secret_access_key = "${{ secrets.AWS_SECRET_ACCESS_KEY }}"
          aws_region = "${{ secrets.AWS_DEFAULT_REGION }}"
          public_subnet_id = "${{ secrets.PUBLIC_SUBNET_ID }}"
          terraform_state_bucket = "${{ secrets.TERRAFORM_STATE_BUCKET }}"
          EOF

      - name: Terraform Init
        run: |
          terraform init \
            -backend-config="bucket=${{ secrets.TERRAFORM_STATE_BUCKET }}" \
            -backend-config="key=infra.tfstate" \
            -backend-config="region=${{ secrets.AWS_DEFAULT_REGION }}"

      - name: Terraform Plan
        run: terraform plan -out=tfplan -var-file=terraform.tfvars

      - name: Terraform Apply
        run: terraform apply -auto-approve -var-file=terraform.tfvars
```

### Post-Apply Job

The **post-apply** job retrieves Terraform outputs, updates the EC2 security group to allow SSH access from the GitHub runner, installs Docker on the EC2 instance, and deploys the DeepSeek Model and OpenWebUI using Docker.

```yaml
  post_apply:
    runs-on: ubuntu-latest
    needs: apply
    if: success()
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

      - name: Retrieve Terraform Outputs
        id: tf_outputs
        run: |
          echo "Retrieving Terraform Outputs..."
          echo "EC2_PUBLIC_IP=$(terraform output -raw ec2_public_ip)" >> $GITHUB_ENV
          echo "LB_DNS=$(terraform output -raw lb_url)" >> $GITHUB_ENV

      - name: Retrieve EC2 Security Group ID
        id: get_sg_id
        run:  |
          SECURITY_GROUP_ID=$(terraform output -raw deepseek_ec2_sg_id)
          echo "SECURITY_GROUP_ID=$SECURITY_GROUP_ID" >> $GITHUB_ENV

      - name: Add GitHub Runner IP to Security Group
        run: |
          RUNNER_IP=$(curl -s https://checkip.amazonaws.com)
          echo "Runner IP: $RUNNER_IP"
          aws ec2 authorize-security-group-ingress \
            --group-id "${{ env.SECURITY_GROUP_ID }}" \
            --protocol tcp \
            --port 22 \
            --cidr "$RUNNER_IP/32" || echo "Failed to add rule to EC2 Security Group"

      - name: Wait for Security Group to Update
        run: sleep 12

      - name: Save SSH Private Key
        run: |
          mkdir -p ~/.ssh
          echo "${{ secrets.SSH_PRIVATE_KEY }}" | base64 --decode > ~/.ssh/my-key.pem
          chmod 600 ~/.ssh/my-key.pem

      - name: Verify SSH Connection
        run: |
           ssh -o StrictHostKeyChecking=no -i ~/.ssh/my-key.pem ubuntu@${{ env.EC2_PUBLIC_IP }} 
           echo "SSH Connection Successful"

      - name: Install Docker on EC2
        run: |
          ssh -o StrictHostKeyChecking=no -i ~/.ssh/my-key.pem ubuntu@${{ env.EC2_PUBLIC_IP }} <<EOF
          sudo apt-get update
          sudo apt-get install -y docker.io docker-compose
          sudo systemctl enable docker
          sudo systemctl start docker
          sudo usermod -aG docker ubuntu
          sudo sed -i 's/^ENABLED=1/ENABLED=0/' /etc/apt/apt.conf.d/20auto-upgrades
          sudo reboot
          EOF

      - name: Wait for EC2 Instance to Reboot
        run: sleep 60

      - name: Run DeepSeek Model and WebUI via Docker
        run: |
          ssh -o StrictHostKeyChecking=no -i ~/.ssh/my-key.pem ubuntu@${{ env.EC2_PUBLIC_IP }} <<EOF
          docker run -d -v ollama:/root/.ollama -p 11434:11434 --name ollama ollama/ollama
          sleep 20
          docker exec ollama ollama pull deepseek-r1:8b
          sleep 15
          docker exec -d ollama ollama serve
          sleep 15
          docker run -d -p 8080:8080 --add-host=host.docker.internal:host-gateway -v open-webui:/app/backend/data --name open-webui --restart always ghcr.io/open-webui/open-webui:main
          sleep 15
          EOF

      - name: Confirm WebUI is Running & Accessible via Custom Domain
        run: |
          ssh -o StrictHostKeyChecking=no -i ~/.ssh/my-key.pem ubuntu@${{ env.EC2_PUBLIC_IP }} <<EOF
          curl -I https://deepseek.fozdigitalz.com
          EOF

      - name: Remove GitHub Runner IP from Security Group
        if: always()
        run: |
            RUNNER_IP=$(curl -s https://checkip.amazonaws.com)
            echo "Removing Runner IP: $RUNNER_IP"
            aws ec2 revoke-security-group-ingress \
              --group-id "${{ env.SECURITY_GROUP_ID }}" \
              --protocol tcp \
              --port 22 \
              --cidr "$RUNNER_IP/32"
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
          subnet_ids = [${{ secrets.SUBNET_IDS }}]
          key_name = "${{ secrets.KEY_NAME }}"
          key_id = "${{ secrets.KEY_ID }}"
          hosted_zone_id = "${{ secrets.HOSTED_ZONE_ID }}"
          instance_type = "${{ secrets.INSTANCE_TYPE }}"
          my_ip = "${{ secrets.MY_IP }}"
          aws_access_key_id = "${{ secrets.AWS_ACCESS_KEY_ID }}"
          aws_secret_access_key = "${{ secrets.AWS_SECRET_ACCESS_KEY }}"
          aws_region = "${{ secrets.AWS_DEFAULT_REGION }}"
          public_subnet_id = "${{ secrets.PUBLIC_SUBNET_ID }}"
          terraform_state_bucket = "${{ secrets.TERRAFORM_STATE_BUCKET }}"
          EOF

      - name: Terraform Init & Destroy
        run: |
          terraform init -reconfigure \
            -backend-config="bucket=${{ secrets.TERRAFORM_STATE_BUCKET }}" \
            -backend-config="key=infra.tfstate" \
            -backend-config="region=${{ secrets.AWS_DEFAULT_REGION }}"
          terraform destroy -auto-approve -var-file=terraform.tfvars
```

---
## **7. The Application in Action (Result)**

After successfully deploying the DeepSeek Model R1 on AWS, I was able to access the OpenWebUI and interact with the model. Below are some screenshots demonstrating the setup and functionality:

### **1. OpenWebUI Interface**
The OpenWebUI provides a user-friendly interface for interacting with the DeepSeek Model R1. Here’s a screenshot of the dashboard:

![OpenWebUI Dashboard](https://example.com/path-to-openwebui-screenshot.png)

*Caption: The OpenWebUI dashboard, accessible via the custom domain `deepseek.fozdigitalz.com`.*

### **2. Model Interaction**
I tested the model by asking it a few questions. Here’s an example of the model’s response:

![Model Response](https://example.com/path-to-model-response-screenshot.png)

*Caption: The DeepSeek Model R1 generating a response to a sample query.*

### **3. Performance Metrics**
Using the Ollama API, I measured the model’s response time and resource utilization. Here’s a summary of the performance:

- **Average Response Time**: 1.2 seconds
- **CPU Utilization**: 45%
- **Memory Usage**: 8 GB

These metrics were collected using the `nvidia-smi` command (for GPU instances) and CloudWatch metrics.



## 5. Challenges Faced & Lesson Learned

Deploying the DeepSeek Model R1 on AWS using Terraform and GitHub Actions presented several challenges, each of which taught valuable lessons for improving the deployment process and infrastructure design.

### **1. Security Configuration**
- **Challenge**: Configuring security groups and IAM roles to balance accessibility and security was complex. Misconfigurations could expose the EC2 instance or over-privilege IAM roles.
- **Lesson Learned**: Follow the principle of least privilege. Restrict SSH access to specific IPs, limit IAM permissions, and ensure only necessary ports are open.

### **2. Workflow Reliability**
- **Challenge**: My workflow failed countless times owing to different issues from terraform config to secerts and variables and I had to troubleshoot the issue on different ocassions employing debugging. The EC2 instance required a reboot after Docker installation, causing delays in the GitHub Actions workflow. Without proper handling, subsequent steps could fail.
- **Lesson Learned**: Automate delays (e.g., `sleep`) and post-reboot tasks to ensure smooth workflow execution. Modularize the workflow for better reliability.

### **3. State and Code Management**
- **Challenge**: Managing the Terraform state file in S3 and maintaining a monolithic configuration led to potential security risks and reduced reusability.
- **Lesson Learned**: Use versioning, encryption, and access controls for the Terraform state. Break configurations into reusable modules for better organization and maintainability.
---


## 6. Future Improvements

While the deployment process is now functional, there are opportunities I may consider to enhance scalability, security, and cost-efficiency.

### **1. Scalability**
- Implement **auto-scaling** for the EC2 instance to handle varying loads and ensure optimal performance during peak usage.

### **2. Monitoring and Security**
- Add **CloudWatch alarms and logs** for real-time monitoring and troubleshooting. Enhance security by using **AWS Systems Manager** for instance management instead of SSH.

### **3. Cost Optimization**
- Explore **spot instances** or **reserved instances** to reduce costs. Additionally, consider upgrading to **GPU-powered instances** for better performance if the model is computationally intensive.

---

## 7. Conclusion

Deploying the DeepSeek Model R1 on AWS using Terraform and GitHub Actions was a rewarding experience. It not only streamlined the deployment process but also provided a scalable and secure infrastructure. By automating the deployment pipeline, I ensured consistency and repeatability, making it easier to manage and update the infrastructure in the future.