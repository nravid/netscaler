$credential = Get-Credential

$uri = "http://192.168.137.25/nitro/v2/config/managed_device"
$nmasdevices = Invoke-RestMethod -uri $uri -Credential $credential | select managed_device -ExpandProperty managed_device | select type, ip_address, instance_state, ha_master_state | Where-Object {($_.type -eq "nsvpx") -and ($_.instance_state -eq "Up") -and ($_.ha_master_state -eq "Primary")}
