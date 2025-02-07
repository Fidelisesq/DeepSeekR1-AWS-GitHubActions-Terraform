# **Deploying DeepSeek Model R1 on AWS EC2 Using Terraform & GitHub Actions**

## Introduction
This project automates the deployment of the DeepSeek Model R1 on an AWS EC2 instance using Terraform and GitHub Actions. The goal is to streamline model hosting with infrastructure as code, ensure security best practices, and enable seamless updates using CI/CD workflows.

## Project Objectives
- Host the DeepSeek Model R1 on AWS with a public endpoint.
- Use Terraform to provision AWS resources efficiently.
- Implement GitHub Actions for automated deployment.
- Secure access using IAM roles, Security Groups, and encryption.
- Leverage an S3 bucket for model storage and state management.
- Deploy a load balancer to manage external traffic.
- Use a custom domain (`www.deepseek-fozdigitalz.com`) to access the model interactively via web browswer.

---

## Step-by-Step Implementation

### 1. **Setting Up AWS Resources with Terraform**
- Created an S3 bucket for storing Terraform state.
- Provisioned an EC2 instance with GPU support for model inference.
- Configured IAM roles and policies for secure access.
- Defined Security Groups to restrict access based on least privilege principles.
- Set up an Application Load Balancer (ALB) for external traffic management.
- Enabled encryption:
  - S3 encryption for secure model storage.
  - SSL/TLS encryption for secure communication.

### 2. **Automating Deployment with GitHub Actions**
The GitHub Actions workflow includes:

#### **Setup & Deployment Workflow**
1. **Setup Job:**
   - Configures AWS credentials.
   - Installs Terraform and required dependencies.

2. **Apply Terraform Job:**
   - Initializes Terraform and applies changes to provision resources.
   - Generates a `terraform.tfvars` file dynamically.
   - Stores Terraform state in an S3 bucket.

3. **Post-Apply Configuration:**
   - Adds GitHub Runner's IP to the security group for SSH access.
   - Connects to the EC2 instance and installs Docker, NVIDIA drivers, and other dependencies.
   - Downloads and runs the DeepSeek Model R1 container.
   - Verifies that the model is accessible via `www.deepseek-fozdigitalz.com`.

4. **Destroy Job (Optional):**
   - Removes all AWS resources when no longer needed.
   
### 3. **Verifying Deployment**
- Checked that the EC2 instance was correctly configured with GPU support.
- Ensured that the DeepSeek Model R1 was running inside a Docker container.
- Confirmed that traffic was properly routed via the Application Load Balancer.
- Validated SSL/TLS encryption on the custom domain.

---

## Challenges Faced
1. **Terraform State Management Issues**  
   - Initially, storing state locally caused inconsistencies. Solution: Used an S3 backend to manage state centrally.

2. **SSH Access to EC2**  
   - Security groups were too restrictive. Solution: Temporarily added GitHub Runner’s IP dynamically.

3. **Model Loading Time**  
   - The DeepSeek Model R1 took longer than expected to initialize. Solution: Used `sleep` commands but plan to implement Docker health checks.

4. **Docker Permissions**  
   - The container required elevated permissions to access GPU resources. Solution: Ensured correct NVIDIA drivers were installed.

5. **Sensitive Credentials in Terraform**  
   - Initially stored AWS credentials in `terraform.tfvars`. Solution: Plan to switch to GitHub OIDC authentication.

---

## Future Modifications & Improvements
- **Use OIDC for AWS Authentication:** Avoid storing long-lived AWS credentials.
- **Refactor Docker Health Checks:** Implement robust readiness probes instead of static sleep delays.
- **Optimize Security Group Handling:** Use session-based security group rules instead of dynamically adding/removing IPs.
- **Improve Error Handling:** Add better rollback mechanisms in case of failures.

---

## Conclusion
This project successfully automated the deployment of the DeepSeek Model R1 on AWS, leveraging Terraform and GitHub Actions for efficiency and scalability. While the implementation met the initial objectives, future optimizations will further enhance security, automation, and reliability.

🚀 **Next Steps:** Implement suggested improvements and document further learnings!


