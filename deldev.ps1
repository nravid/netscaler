
$datactr = "trm"

$Nsip = 'nt0pnsint01.aqrcapital.com'
$Credential = Get-Credential
Connect-NetScaler -Hostname $Nsip -Credential $Credential



$datactr = "grn"

$Nsip = 'ng0pnsint01.aqrcapital.com'
$SecurePassword = ConvertTo-SecureString 'HH!qDpk)8S4L' -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential ("nsroot", $SecurePassword)
Connect-NetScaler -Hostname $Nsip -Credential $Credential


$devlist = import-csv -Path H:\NS-Migration\deldev.csv

ForEach ($vip in $devlist){

    $lbvsname = $vip.name + "_vip_" + $datactr
    $lbvsname80 = $vip.name + "_vip_80_" + $datactr
    $lbvsname443 = $vip.name + "_vip_443_" + $datactr
    $gslbvsname = $vip.name + "_gslb_vip_" + $datactr
    $gslbsvcnametrm = $vip.name + "_gslb_svc_trm"
    $gslbsvcnamegrn = $vip.name + "_gslb_svc_grn"
    $gslbsvcpaytrm = @{ name = $gslbsvcnametrm }
    $gslbsvcpaygrn = @{ name = $gslbsvcnamegrn }

    Write-Host $lbvsname, $gslbvsname, $gslbsvcname, $vip.grnip, $vip.trmip

Remove-NSLBVirtualServer -Name $lbvsname -ErrorAction SilentlyContinue -Confirm -Force
Remove-NSLBVirtualServer -Name $lbvsname80 -ErrorAction SilentlyContinue -Confirm -Force
Remove-NSLBVirtualServer -Name $lbvsname443 -ErrorAction SilentlyContinue -Confirm -Force
Invoke-Nitro -Method DELETE -Type gslbvserver -Resource $gslbvsname -OnErrorAction CONTINUE -Confirm -Force
Invoke-Nitro -Method DELETE -Type gslbservice -Resource $gslbsvcnametrm -Payload $gslbsvcpaytrm -OnErrorAction CONTINUE -Confirm -Force
Invoke-Nitro -Method DELETE -Type gslbservice -Resource $gslbsvcnamegrn -Payload $gslbsvcpaygrn -OnErrorAction CONTINUE -Confirm -Force
Remove-NSLBServer -Name $vip.grnip -ErrorAction SilentlyContinue -Confirm -Force
Remove-NSLBServer -Name $vip.trmip -ErrorAction SilentlyContinue -Confirm -Force

}


