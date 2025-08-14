output "vpc_id"           { value = aws_vpc.this.id }
output "subnet_id"        { value = aws_subnet.private.id }
output "dc_private_ip"    { value = aws_instance.dc.private_ip }
output "win_private_ip"   { value = aws_instance.win.private_ip }
output "linux_private_ip" { value = aws_instance.linux.private_ip }
output "instance_ids" {
  value = {
    dc    = aws_instance.dc.id
    win   = aws_instance.win.id
    linux = aws_instance.linux.id
  }
}
