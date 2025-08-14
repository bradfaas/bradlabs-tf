terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.0" }
  }
  backend "s3" {
    # Provided via -backend-config at init time (see buildspec.yml)
    # bucket       = ""
    # key          = ""
    # region       = ""
  }
}

provider "aws" { region = var.region }

module "lab" {
  source     = "./modules/lab"
  lab_id     = var.lab_id
  user_id    = var.user_id
  region     = var.region

  s3_app_bucket         = var.s3_app_bucket

  enable_nat            = var.enable_nat

  domain_admin_password = var.domain_admin_password
  windows_admin_password = var.windows_admin_password
  create_domain_user = var.create_domain_user
  domain_user_password = var.domain_user_password

  linux_user_password    = var.linux_user_password

  windows_apps = var.windows_apps
  linux_apps   = var.linux_apps

  tags = var.tags
}
