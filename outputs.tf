/*
output "ec2_public_ip" {
  description = "Public IP of the EC2 instance"
  value       = aws_instance.deepseek_ec2.public_ip
}
*/

output "ec2_public_ip" {
  description = "Public IP of the EC2 instance"
  value       = aws_instance.deepseek_ec2.public_ip
}

output "lb_url" {
  description = "DNS name of the ALB"
  value       = aws_lb.deepseek_lb.dns_name
}
