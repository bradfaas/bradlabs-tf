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
}


# ------------------------
# Networking (private-only)
# ------------------------
resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = merge(local.base_tags, { Name = "lab-${var.lab_id}" })
}

data "aws_availability_zones" "available" {}

# ---------- Subnets: 1x public (/28) + 1x private (/28) ----------
# Split the /24 into /28s; index 0 = public, index 1 = private
locals {
  public_subnet_cidr  = cidrsubnet(var.vpc_cidr, 4, 0) # e.g., 172.16.73.0/28
  private_subnet_cidr = cidrsubnet(var.vpc_cidr, 4, 1) # e.g., 172.16.73.16/28
}

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

# ---------- IGW + NAT (behind a flag) ----------
resource "aws_internet_gateway" "this" {
  count = var.enable_nat ? 1 : 0
  vpc_id = aws_vpc.this.id
  tags   = merge(local.base_tags, { Name = "lab-${var.lab_id}-igw" })
}

resource "aws_eip" "nat" {
  count = var.enable_nat ? 1 : 0
  domain = "vpc"
  tags   = merge(local.base_tags, { Name = "lab-${var.lab_id}-nat-eip" })
}

resource "aws_nat_gateway" "this" {
  count         = var.enable_nat ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public.id
  tags          = merge(local.base_tags, { Name = "lab-${var.lab_id}-nat" })
  depends_on    = [aws_internet_gateway.this] # ensure IGW exists first
}

# ---------- Route tables ----------
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

# SG for instances: allow intra-SG all traffic (AD chatter), no inbound from outside
resource "aws_security_group" "instances" {
  name        = "lab-${var.lab_id}-instances"
  description = "Instances intra-traffic & egress"
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "intra-sg"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = local.base_tags
}

# SG for interface endpoints (allow 443 from instances)
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

# VPC endpoints
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
# EC2 Instances
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
# Secrets as SSM Parameter (SecureString)
# ------------------------
resource "aws_ssm_parameter" "domain_admin_pw" {
  name   = "/labs/${var.lab_id}/domainAdminPassword"
  type   = "SecureString"
  value  = var.domain_admin_password
  tags   = local.base_tags
}

# ------------------------
# SSM Documents
# ------------------------

# 1) Promote DC (new forest)
resource "aws_ssm_document" "setup_dc" {
  name          = "Lab-${var.lab_id}-SetupDC"
  document_type = "Command"
  content = jsonencode({
    schemaVersion = "2.2"
    description   = "Promote server to DC for ${var.domain_name}"
    parameters    = {
      AdminPassword = { type = "String" }
    }
    mainSteps = [
      {
        action = "aws:runPowerShellScript"
        name   = "InstallADDS"
        inputs = {
          runCommand = [
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

# 2) Join Windows desktop to domain
resource "aws_ssm_document" "join_domain_win" {
  name          = "Lab-${var.lab_id}-JoinDomainWin"
  document_type = "Command"
  content = jsonencode({
    schemaVersion = "2.2"
    description   = "Join Windows to ${var.domain_name}"
    parameters    = {
      DcIp          = { type = "String" }
      AdminPassword = { type = "String" }
    }
    mainSteps = [
      {
        action = "aws:runPowerShellScript"
        name   = "Join"
        inputs = {
          runCommand = [
            "$p = Get-WmiObject Win32_ComputerSystem",
            "if ($p.PartOfDomain -eq $true) { Write-Host 'Already joined'; exit 0 }",
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

# 3) Install apps on Windows
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


# 4) Install apps on Linux
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
      { action = "aws:runShellScript", name = "PrepDir", inputs = { runCommand = ["mkdir -p /var/tmp/app-installs"] } },
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
    AdminPassword = var.domain_admin_password
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
    AdminPassword = var.domain_admin_password
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

