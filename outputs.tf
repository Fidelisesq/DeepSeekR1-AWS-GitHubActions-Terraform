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

