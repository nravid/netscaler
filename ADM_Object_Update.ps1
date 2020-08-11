
function Get-TimeStamp {
    return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
}

$logfile = '\\naspmhome\technology\Ravid_Nate\Private\Appsense\new_adm_log.txt'
$admip="192.77.88.227"


"$(Get-TimeStamp) *** START Location Add" | Out-File -FilePath $logfile -Append -Encoding ascii

$admcred = Get-Credential

$admgetipblockuri = "https://ctxadm.foo.com/nitro/v1/config/ip_block?onerror=continue"

$locationpath = '\\naspmhome\technology\Ravid_Nate\Private\Appsense\internal_location_adm_input2.txt'
$subnetdata = Import-Csv -Path $locationpath




ForEach ($subnet in $subnetdata) {

$subnetname = $subnet.locreg + "_" + $subnet.start_ip

$admipblock2 = @{"ip_block" = 
    @{
     "name" = $subnetname
     "start_ip" = $subnet.start_ip 
     "end_ip" = $subnet.end_ip
     "country" = $subnet.loccnt 
     "region" = $subnet.locreg
     "city" = $subnet.loccity
      }} | ConvertTo-Json
$admipjson2 = 'object=' + $admipblock2

"$(Get-TimeStamp) *** ADD Location $subnetname"  | Out-File -FilePath $logfile -Append -Encoding ascii

$result =  Invoke-RestMethod -Uri $admgetipblockuri -Credential $admcred -Body $admipjson2 -Method Post -ContentType 'application/json'

} # Subnet Loop

"$(Get-TimeStamp) *** End Location Add" | Out-File -FilePath $logfile -Append -Encoding ascii
