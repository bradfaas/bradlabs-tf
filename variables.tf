variable "region"                { type = string }
variable "lab_id"                { type = string }
variable "user_id"               { type = string }
variable "s3_app_bucket"         { type = string }
variable "domain_admin_password" {
  type      = string
  sensitive = true
}

variable "windows_admin_password" {
  type      = string
  default   = null
  sensitive = true
}

variable "linux_user_password" {
  type      = string
  sensitive = true
}

variable "enable_nat" {
  type    = bool
  default = true
}

variable "windows_apps" {
  type = list(object({ s3_key = string, args = string }))
  default = []
}
variable "linux_apps" {
  type = list(object({ s3_key = string, args = string }))
  default = []
}
variable "tags" {
  type    = map(string)
  default = {}
}

