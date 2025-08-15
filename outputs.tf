output "lab_endpoints" {
  value = {
    dc_ip    = module.lab.dc_private_ip
    win_ip   = module.lab.win_private_ip
    linux_ip = module.lab.linux_private_ip
  }
}

output "instance_ids" { value = module.lab.instance_ids }
output "doc_names"    { value = module.lab.doc_names }

output "vpc_id"       { value = module.lab.vpc_id }
output "subnet_id"    { value = module.lab.subnet_id }

output "nlb_public_ip"  { value = module.lab.nlb_public_ip }
output "nlb_dns_name"   { value = module.lab.nlb_dns_name }

output "rdp_endpoints" { value = module.lab.rdp_endpoints }


