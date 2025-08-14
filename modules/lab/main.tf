terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.0" }
  }
}

locals {
  win_apps = slice(
    concat(var.windows_apps, [for _ in range(3 - length(var.windows_apps)) : { s3_key = "", args = "" }]),
    0, 3
  )

  lin_apps = slice(
    concat(var.linux_apps,  [for _ in range(3 - length(var.linux_apps))  : { s3_key = "", args = "" }]),
    0, 3
  )

  base_tags = merge(var.tags, {
    labId  = var.lab_id
    userId = var.user_id
  })

  win_admin_pw = coalesce(var.windows_admin_password, var.domain_admin_password)

  # Split /24 into /28s for small public/private subnets
  public_subnet_cidr  = cidrsubnet(var.vpc_cidr, 4, 0) # e.g., .0/28
  private_subnet_cidr = cidrsubnet(var.vpc_cidr, 4, 1) # e.g., .16/28
}

# ------------------------
# Networking
# ------------------------
resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = merge(local.base_tags, { Name = "lab-${var.lab_id}" })
}

data "aws_availability_zones" "available" {}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = local.public_subnet_cidr
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false
  tags = merge(local.base_tags, { Name = "lab-${var.lab_id}-public" })
}

resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = local.private_subnet_cidr
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false
  tags = merge(local.base_tags, { Name = "lab-${var.lab_id}-private" })
}

# IGW + NAT (egress)
resource "aws_internet_gateway" "this" {
  count = var.enable_nat ? 1 : 0
  vpc_id = aws_vpc.this.id
  tags   = merge(local.base_tags, { Name = "lab-${var.lab_id}-igw" })
}

resource "aws_eip" "nat" {
  count  = var.enable_nat ? 1 : 0
  domain = "vpc"
  tags   = merge(local.base_tags, { Name = "lab-${var.lab_id}-nat-eip" })
}

resource "aws_nat_gateway" "this" {
  count         = var.enable_nat ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public.id
  tags          = merge(local.base_tags, { Name = "lab-${var.lab_id}-nat" })
  depends_on    = [aws_internet_gateway.this]
}

# Route tables
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.base_tags, { Name = "lab-${var.lab_id}-rt-public" })
}

resource "aws_route" "public_default" {
  count                  = var.enable_nat ? 1 : 0
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this[0].id
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.base_tags, { Name = "lab-${var.lab_id}-rt-private" })
}

resource "aws_route" "private_default" {
  count                  = var.enable_nat ? 1 : 0
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this[0].id
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

# Security group for instances
resource "aws_security_group" "instances" {
  name        = "lab-${var.lab_id}-instances"
  description = "Instances intra-traffic & egress; allow RDP from admin CIDR"
  vpc_id      = aws_vpc.this.id

  # intra-SG
  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    self      = true
  }

  # RDP/xRDP from your admin IP (NLB preserves client IP)
  ingress {
    description = "RDP/xRDP"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.base_tags
}

# SG for Interface Endpoints (allow HTTPS from instances)
resource "aws_security_group" "endpoints" {
  name        = "lab-${var.lab_id}-endpoints"
  description = "Allow HTTPS from lab instances to endpoints"
  vpc_id      = aws_vpc.this.id

  ingress {
    description     = "HTTPS from instances"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.instances.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.base_tags
}

# VPC Endpoints
resource "aws_vpc_endpoint" "s3" {
  count             = var.create_s3_gateway_endpoint ? 1 : 0
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
  tags              = local.base_tags
}

resource "aws_vpc_endpoint" "ssm" {
  count               = var.create_interface_endpoints ? 1 : 0
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.region}.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private.id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
  tags                = local.base_tags
}

resource "aws_vpc_endpoint" "ssmmessages" {
  count               = var.create_interface_endpoints ? 1 : 0
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.region}.ssmmessages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private.id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
  tags                = local.base_tags
}

resource "aws_vpc_endpoint" "ec2messages" {
  count               = var.create_interface_endpoints ? 1 : 0
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.region}.ec2messages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private.id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
  tags                = local.base_tags
}

# ------------------------
# AMIs
# ------------------------
data "aws_ssm_parameter" "win2022" {
  name = "/aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base"
}

data "aws_ami" "ubuntu2204" {
  most_recent = true
  owners      = ["099720109477"] # Canonical
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

# ------------------------
# IAM for instances (SSM + S3 read)
# ------------------------
data "aws_iam_policy_document" "assume_ec2" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "instance" {
  name               = "lab-${var.lab_id}-instance-role"
  assume_role_policy = data.aws_iam_policy_document.assume_ec2.json
  tags               = local.base_tags
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "s3_read" {
  statement {
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [
      "arn:aws:s3:::${var.s3_app_bucket}",
      "arn:aws:s3:::${var.s3_app_bucket}/*"
    ]
  }
}

resource "aws_iam_policy" "s3_read" {
  name   = "lab-${var.lab_id}-s3-read"
  policy = data.aws_iam_policy_document.s3_read.json
}

resource "aws_iam_role_policy_attachment" "s3_read" {
  role       = aws_iam_role.instance.name
  policy_arn = aws_iam_policy.s3_read.arn
}

resource "aws_iam_instance_profile" "instance" {
  name = "lab-${var.lab_id}-profile"
  role = aws_iam_role.instance.name
}

# ------------------------
# EC2 Instances (private subnet)
# ------------------------
resource "aws_instance" "dc" {
  ami                    = data.aws_ssm_parameter.win2022.value
  instance_type          = var.instance_types.dc
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.instances.id]
  iam_instance_profile   = aws_iam_instance_profile.instance.name
  monitoring             = false
  get_password_data      = false

  tags = merge(local.base_tags, { Name = "lab-${var.lab_id}-dc", role = "dc" })
}

resource "aws_instance" "win" {
  ami                    = data.aws_ssm_parameter.win2022.value
  instance_type          = var.instance_types.win_desktop
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.instances.id]
  iam_instance_profile   = aws_iam_instance_profile.instance.name
  monitoring             = false
  get_password_data      = false

  tags = merge(local.base_tags, { Name = "lab-${var.lab_id}-win", role = "win-desktop" })
}

resource "aws_instance" "linux" {
  ami                    = data.aws_ami.ubuntu2204.id
  instance_type          = var.instance_types.linux_desktop
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.instances.id]
  iam_instance_profile   = aws_iam_instance_profile.instance.name
  monitoring             = false

  tags = merge(local.base_tags, { Name = "lab-${var.lab_id}-linux", role = "linux-desktop" })
}

# ------------------------
# SSM Documents
# ------------------------

# Promote DC (set admin pw, enable RDP, then promote)
resource "aws_ssm_document" "setup_dc" {
  name          = "Lab-${var.lab_id}-SetupDC"
  document_type = "Command"
  content = jsonencode({
    schemaVersion = "2.2"
    description   = "Set admin password, enable RDP, and promote to DC for ${var.domain_name}"
    parameters    = {
      AdminPassword = { type = "String" }
    }
    mainSteps = [
      {
        action = "aws:runPowerShellScript"
        name   = "PrepAndPromote"
        inputs = {
          runCommand = [
            "net user Administrator '{{ AdminPassword }}'",
            "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 0",
            "Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'",
            "$sec = ConvertTo-SecureString '{{ AdminPassword }}' -AsPlainText -Force",
            "Install-WindowsFeature AD-Domain-Services",
            "Import-Module ADDSDeployment",
            "Install-ADDSForest -DomainName '${var.domain_name}' -SafeModeAdministratorPassword $sec -Force"
          ]
        }
      }
    ]
  })
  tags = local.base_tags
}

# Join Windows desktop to domain (also set admin pw & enable RDP)
resource "aws_ssm_document" "join_domain_win" {
  name          = "Lab-${var.lab_id}-JoinDomainWin"
  document_type = "Command"
  content = jsonencode({
    schemaVersion = "2.2"
    description   = "Enable RDP and join Windows to ${var.domain_name}"
    parameters    = {
      DcIp          = { type = "String" }
      AdminPassword = { type = "String" }
    }
    mainSteps = [
      {
        action = "aws:runPowerShellScript"
        name   = "EnableRDPAndJoin"
        inputs = {
          runCommand = [
            "$p = Get-WmiObject Win32_ComputerSystem",
            "if ($p.PartOfDomain -eq $true) { Write-Host 'Already joined'; exit 0 }",
            "net user Administrator '{{ AdminPassword }}'",
            "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 0",
            "Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'",
            "$adapters = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'}",
            "$adapters | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses @('{{ DcIp }}') }",
            "while (-not (Test-Connection -Quiet -Count 1 '{{ DcIp }}')) { Start-Sleep -Seconds 15 }",
            "$sec = ConvertTo-SecureString '{{ AdminPassword }}' -AsPlainText -Force",
            "$cred = New-Object System.Management.Automation.PSCredential('${var.domain_netbios_name}\\Administrator',$sec)",
            "Add-Computer -DomainName '${var.domain_name}' -Credential $cred -Force -ErrorAction Stop",
            "Restart-Computer -Force"
          ]
        }
      }
    ]
  })
  tags = local.base_tags
}

# Install apps on Windows
resource "aws_ssm_document" "install_apps_win" {
  name          = "Lab-${var.lab_id}-InstallAppsWin"
  document_type = "Command"
  content = jsonencode({
    schemaVersion = "2.2"
    description   = "Install up to 3 Windows apps from S3"
    parameters    = {
      Bucket  = { type = "String" }
      App1Key = { type = "String", default = "" }
      App1Arg = { type = "String", default = "" }
      App2Key = { type = "String", default = "" }
      App2Arg = { type = "String", default = "" }
      App3Key = { type = "String", default = "" }
      App3Arg = { type = "String", default = "" }
    }
    mainSteps = [
      { action = "aws:runPowerShellScript", name = "PrepDir", inputs = { runCommand = ["New-Item -ItemType Directory -Force -Path C:\\Temp\\app-installs | Out-Null"] } },
      { action = "aws:downloadContent", name = "Get1", inputs = { sourceType = "S3", sourceInfo = jsonencode({ path = "s3://{{ Bucket }}/{{ App1Key }}" }), destinationPath = "C:\\Temp\\app-installs" } },
      { action = "aws:downloadContent", name = "Get2", inputs = { sourceType = "S3", sourceInfo = jsonencode({ path = "s3://{{ Bucket }}/{{ App2Key }}" }), destinationPath = "C:\\Temp\\app-installs" } },
      { action = "aws:downloadContent", name = "Get3", inputs = { sourceType = "S3", sourceInfo = jsonencode({ path = "s3://{{ Bucket }}/{{ App3Key }}" }), destinationPath = "C:\\Temp\\app-installs" } },
      {
        action = "aws:runPowerShellScript",
        name   = "Install",
        inputs = {
          runCommand = [
            "$items = Get-ChildItem 'C:\\Temp\\app-installs' | Where-Object { -not $_.PSIsContainer }",
            "$argsMap = @{",
            "  (Split-Path -Leaf '{{ App1Key }}') = '{{ App1Arg }}'",
            "  (Split-Path -Leaf '{{ App2Key }}') = '{{ App2Arg }}'",
            "  (Split-Path -Leaf '{{ App3Key }}') = '{{ App3Arg }}'",
            "}",
            "foreach ($f in $items) {",
            "  $ext = [IO.Path]::GetExtension($f.FullName).ToLower()",
            "  $a = $argsMap[$f.Name]",
            "  if ($ext -eq '.msi') { Start-Process 'msiexec.exe' -ArgumentList @('/i', $f.FullName, '/qn', $a) -Wait -NoNewWindow }",
            "  elseif ($ext -eq '.exe') { Start-Process $f.FullName -ArgumentList $a -Wait -NoNewWindow }",
            "  else { Write-Host 'Skipping unsupported: ' + $f.FullName }",
            "}"
          ]
        }
      }
    ]
  })
  tags = local.base_tags
}

# Install apps on Linux
resource "aws_ssm_document" "install_apps_linux" {
  name          = "Lab-${var.lab_id}-InstallAppsLinux"
  document_type = "Command"
  content = jsonencode({
    schemaVersion = "2.2"
    description   = "Install up to 3 Linux apps from S3"
    parameters    = {
      Bucket  = { type = "String" }
      App1Key = { type = "String", default = "" }
      App1Arg = { type = "String", default = "" }
      App2Key = { type = "String", default = "" }
      App2Arg = { type = "String", default = "" }
      App3Key = { type = "String", default = "" }
      App3Arg = { type = "String", default = "" }
    }
    mainSteps = [
      { action = "aws:runShellScript", name = "PrepDir", inputs = { runCommand = ["set -e", "mkdir -p /var/tmp/app-installs"] } },
      { action = "aws:downloadContent", name = "Get1", inputs = { sourceType = "S3", sourceInfo = jsonencode({ path = "s3://{{ Bucket }}/{{ App1Key }}" }), destinationPath = "/var/tmp/app-installs" } },
      { action = "aws:downloadContent", name = "Get2", inputs = { sourceType = "S3", sourceInfo = jsonencode({ path = "s3://{{ Bucket }}/{{ App2Key }}" }), destinationPath = "/var/tmp/app-installs" } },
      { action = "aws:downloadContent", name = "Get3", inputs = { sourceType = "S3", sourceInfo = jsonencode({ path = "s3://{{ Bucket }}/{{ App3Key }}" }), destinationPath = "/var/tmp/app-installs" } },
      {
        action = "aws:runShellScript",
        name   = "Install",
        inputs = {
          runCommand = [
            "set -e",
            "cd /var/tmp/app-installs || exit 0",
            "for f in *; do",
            "  case \"$f\" in",
            "    *.deb) dpkg -i \"$f\" || true ;;",
            "    *.rpm) rpm -i --nodeps \"$f\" || true ;;",
            "    *.run|*.sh) chmod +x \"$f\" && ./\"$f\" {{ App1Arg }} {{ App2Arg }} {{ App3Arg }} || true ;;",
            "    *) echo \"Skipping $f\" ;;",
            "  esac",
            "done"
          ]
        }
      }
    ]
  })
  tags = local.base_tags
}

# Install XFCE + xrdp on Ubuntu and set password
resource "aws_ssm_document" "linux_gui_xrdp" {
  name          = "Lab-${var.lab_id}-LinuxGuiXrdp"
  document_type = "Command"
  content = jsonencode({
    schemaVersion = "2.2"
    description   = "Install XFCE desktop + xrdp and set ubuntu password"
    parameters    = {
      UserPassword = { type = "String" }
    }
    mainSteps = [
      {
        action = "aws:runShellScript"
        name   = "InstallGUI"
        inputs = {
          runCommand = [
            "set -e",
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get update",
            "apt-get install -y xfce4 xorg dbus-x11 x11-xserver-utils",
            "apt-get install -y xrdp",
            "systemctl enable xrdp",
            "systemctl restart xrdp",
            "echo \"ubuntu:{{ UserPassword }}\" | chpasswd",
            "su - ubuntu -c 'echo xfce4-session > ~/.xsession'"
          ]
        }
      }
    ]
  })
  tags = local.base_tags
}

# ------------------------
# Associations
# ------------------------
resource "aws_ssm_association" "setup_dc" {
  name = aws_ssm_document.setup_dc.name
  targets {
    key    = "InstanceIds"
    values = [aws_instance.dc.id]
  }
  parameters = {
    AdminPassword = local.win_admin_pw
  }
  compliance_severity = "HIGH"
}

resource "aws_ssm_association" "join_win" {
  name = aws_ssm_document.join_domain_win.name
  targets {
    key    = "InstanceIds"
    values = [aws_instance.win.id]
  }
  parameters = {
    DcIp          = aws_instance.dc.private_ip
    AdminPassword = local.win_admin_pw
  }
  compliance_severity = "HIGH"
}

resource "aws_ssm_association" "install_win" {
  name = aws_ssm_document.install_apps_win.name
  targets {
    key    = "InstanceIds"
    values = [aws_instance.win.id]
  }
  parameters = {
    Bucket = var.s3_app_bucket
    App1Key = local.win_apps[0].s3_key
    App1Arg = local.win_apps[0].args
    App2Key = local.win_apps[1].s3_key
    App2Arg = local.win_apps[1].args
    App3Key = local.win_apps[2].s3_key
    App3Arg = local.win_apps[2].args
  }
}

resource "aws_ssm_association" "install_linux" {
  name = aws_ssm_document.install_apps_linux.name
  targets {
    key    = "InstanceIds"
    values = [aws_instance.linux.id]
  }
  parameters = {
    Bucket = var.s3_app_bucket
    App1Key = local.lin_apps[0].s3_key
    App1Arg = local.lin_apps[0].args
    App2Key = local.lin_apps[1].s3_key
    App2Arg = local.lin_apps[1].args
    App3Key = local.lin_apps[2].s3_key
    App3Arg = local.lin_apps[2].args
  }
}

resource "aws_ssm_association" "linux_gui_xrdp" {
  name = aws_ssm_document.linux_gui_xrdp.name
  targets {
    key    = "InstanceIds"
    values = [aws_instance.linux.id]
  }
  parameters = {
    UserPassword = var.linux_user_password
  }
  compliance_severity = "MEDIUM"
}

# ------------------------
# Public NLB for RDP/xRDP (instances remain private)
# ------------------------
resource "aws_eip" "nlb" {
  count  = var.enable_nlb_rdp ? 1 : 0
  domain = "vpc"
  tags   = merge(local.base_tags, { Name = "lab-${var.lab_id}-nlb-eip" })
}

resource "aws_lb" "rdp" {
  count               = var.enable_nlb_rdp ? 1 : 0
  name                = "lab-${var.lab_id}-rdp"
  load_balancer_type  = "network"
  internal            = false
  enable_deletion_protection = false

  subnet_mapping {
    subnet_id     = aws_subnet.public.id
    allocation_id = aws_eip.nlb[0].id
  }

  tags = local.base_tags
}

resource "aws_lb_target_group" "win_rdp" {
  count    = var.enable_nlb_rdp ? 1 : 0
  name     = "lab-${var.lab_id}-win-rdp"
  port     = 3389
  protocol = "TCP"
  vpc_id   = aws_vpc.this.id
  health_check { protocol = "TCP" }
  tags = local.base_tags
}

resource "aws_lb_target_group" "linux_rdp" {
  count    = var.enable_nlb_rdp ? 1 : 0
  name     = "lab-${var.lab_id}-linux-rdp"
  port     = 3389
  protocol = "TCP"
  vpc_id   = aws_vpc.this.id
  health_check { protocol = "TCP" }
  tags = local.base_tags
}

# --- DC RDP target group (TCP/3389) ---
resource "aws_lb_target_group" "dc_rdp" {
  count    = var.enable_nlb_rdp ? 1 : 0
  name     = "lab-${var.lab_id}-dc-rdp"
  port     = 3389
  protocol = "TCP"
  vpc_id   = aws_vpc.this.id
  health_check { protocol = "TCP" }  # simple TCP health check
  tags = local.base_tags
}

resource "aws_lb_target_group_attachment" "win_attach" {
  count            = var.enable_nlb_rdp ? 1 : 0
  target_group_arn = aws_lb_target_group.win_rdp[0].arn
  target_id        = aws_instance.win.id
  port             = 3389
}

resource "aws_lb_target_group_attachment" "linux_attach" {
  count            = var.enable_nlb_rdp ? 1 : 0
  target_group_arn = aws_lb_target_group.linux_rdp[0].arn
  target_id        = aws_instance.linux.id
  port             = 3389
}

# Attach DC instance to the DC RDP TG
resource "aws_lb_target_group_attachment" "dc_attach" {
  count            = var.enable_nlb_rdp ? 1 : 0
  target_group_arn = aws_lb_target_group.dc_rdp[0].arn
  target_id        = aws_instance.dc.id
  port             = 3389
}

resource "aws_lb_listener" "win_listener" {
  count             = var.enable_nlb_rdp ? 1 : 0
  load_balancer_arn = aws_lb.rdp[0].arn
  port              = 3389
  protocol          = "TCP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.win_rdp[0].arn
  }
}

resource "aws_lb_listener" "linux_listener" {
  count             = var.enable_nlb_rdp ? 1 : 0
  load_balancer_arn = aws_lb.rdp[0].arn
  port              = 3390
  protocol          = "TCP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.linux_rdp[0].arn
  }
}

# Listener on 3391 that forwards to the DC
resource "aws_lb_listener" "dc_listener" {
  count             = var.enable_nlb_rdp ? 1 : 0
  load_balancer_arn = aws_lb.rdp[0].arn
  port              = 3391
  protocol          = "TCP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.dc_rdp[0].arn
  }
}
