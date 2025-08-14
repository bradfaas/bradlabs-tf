variable "lab_id" {
  type = string
}

variable "user_id" {
  type = string
}

variable "region" {
  type = string
}

variable "vpc_cidr" {
  type    = string
  default = "172.16.73.0/24"
}

# Domain config
variable "domain_name" {
  type    = string
  default = "lab.local"
}

variable "domain_netbios_name" {
  type    = string
  default = "LAB"
}

variable "domain_admin_password" {
  type      = string
  sensitive = true
}

# Optional override for Windows local/Domain Administrator password.
# If null, module reuses domain_admin_password.
variable "windows_admin_password" {
  type      = string
  default   = null
  sensitive = true
}

# Password for Ubuntu 'ubuntu' user to log in via xrdp
variable "linux_user_password" {
  type      = string
  sensitive = true
}

# App catalog location (S3 bucket for installers)
variable "s3_app_bucket" {
  type = string
}

# Each app = { s3_key = "path/installer.msi|exe|deb|rpm", args = "/qn" } — max 3
variable "windows_apps" {
  type    = list(object({ s3_key = string, args = string }))
  default = []
  validation {
    condition     = length(var.windows_apps) <= 3
    error_message = "windows_apps maximum is 3."
  }
}

variable "linux_apps" {
  type    = list(object({ s3_key = string, args = string }))
  default = []
  validation {
    condition     = length(var.linux_apps) <= 3
    error_message = "linux_apps maximum is 3."
  }
}

variable "instance_types" {
  type = object({
    dc            = string
    win_desktop   = string
    linux_desktop = string
  })
  default = {
    dc            = "t3.medium"
    win_desktop   = "t3.large"
    linux_desktop = "t3.large"
  }
}

# VPC endpoints
variable "create_interface_endpoints" {
  type    = bool
  default = true
}

variable "create_s3_gateway_endpoint" {
  type    = bool
  default = true
}

# NAT egress (keeps instances private but allows outbound internet)
variable "enable_nat" {
  type    = bool
  default = true
}

# Expose RDP via a public NLB (instances stay private)
variable "enable_nlb_rdp" {
  type    = bool
  default = true
}

# Source CIDR allowed to RDP/xRDP to instances (NLB preserves client source IP)
variable "admin_cidr" {
  type    = string
  default = "0.0.0.0/0" # For POC; set to your /32 for safety
}

variable "tags" {
  type    = map(string)
  default = {}
}
