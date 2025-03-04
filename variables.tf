variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "vpc_id" {
  description = "The VPC ID where resources will be deployed"
  type        = string
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs where ALB and EC2 will be deployed"
  type        = list(string)
}

variable "ami_id" {
  description = "AMI ID for the EC2 instance"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "P4d" # Change based on GPU needs
}

variable "key_id" {
  description = "AWS Key Pair ID for SSH access"
  type        = string
}

variable "certificate_arn" {
  description = "ACM certificate ARN for SSL/TLS"
  type        = string
}

variable "hosted_zone_id" {
  description = "Route 53 hosted zone ID for DNS records"
  type        = string
}

variable "my_ip" {
  description = "Your IP for SSH access (change before deployment)"
  type        = string
}

/*
variable "cloudfront_global_ip_list" {
  description = "List of CloudFront Global IP ranges."
  type        = list(string)
}

variable "cloudfront_regional_edge_ip_list" {
  description = "List of CloudFront Regional Edge IP ranges."
  type        = list(string)
}
*/
