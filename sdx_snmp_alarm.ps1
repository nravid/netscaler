
$AllProtocols = [System.Net.SecurityProtocolType]'Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

$credential = Get-Credential
$snmpalrms = Get-Content "\\foo.bar\users\ravidn\Documents\GitHub\natescripts\sdx_snmp_names.txt"


function sdxsnmp {
     [CmdletBinding()]
    Param(
         [Parameter(Mandatory=$true)]
         [string]$nsipaddr,
         [Parameter(Mandatory=$true)]
         [string]$snmpalarm
         )

    $uri = "https://"+$nsipaddr+"/nitro/v2/config/snmp_alarm_config/" + $snmpalarm

    $snmpapayld = @{ }
    $snmpapayld = @{
                   name = $snmpalarm
                   severity = "Critical"
                   enable = $true
                   }#snmpapayld
    TRY {
        Invoke-RestMethod -Method PUT -Uri $uri -Credential $credential -Body $snmpapayld
        }#TRY SNMPAlarm
    CATCH {}#CATCH SNMPAlarm

}#function sdxsnmp


$nmasdevices = Invoke-RestMethod -uri "https://nt0pctxmas01.foo.bar/nitro/v2/config/managed_device" -Credential $credential | select managed_device -ExpandProperty managed_device | select type, ip_address | Where-Object {($_.type -eq "nssdx")}


ForEach ($nsip in $nmasdevices) {
    TRY {
        $fqdn = Resolve-DnsName $nsip.ip_address
        ForEach ($snmpa in $snmpalrms){
                $report = sdxsnmp $fqdn.namehost $snmpa
        }#ForEach SNMPAlrms
    }#TRY DNS Resolve
    CATCH {
          Write-Host "Failed " $fqdn
    }#CATCH DNS Resolve
} #ForEach nsip




