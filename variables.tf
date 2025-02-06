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
/*
variable "private_subnet_id" {
  description = "Private subnet ID for the EC2 instance"
  type        = string
}
*/

variable "public_subnet_id" {
  description = "Public subnet ID for the EC2 instance"
  type        = string
}

variable "key_name" {  # Updated from key_name to key_id
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

