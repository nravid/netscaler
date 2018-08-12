----

$AllProtocols = [System.Net.SecurityProtocolType]'Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols


*** TRM INT - OLD

$Nsip = 'nt0pnsint01.foobar.com'
$Credential = Get-Credential
Connect-NetScaler -Hostname $Nsip -Credential $Credential


*** GRN INT - OLD
$Nsip = 'ng0pnsint01.foobar.com'
$SecurePassword = ConvertTo-SecureString 'HH!qDpk)8S4L' -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential ("nsroot", $SecurePassword)
Connect-NetScaler -Hostname $Nsip -Credential $Credential


*** TRM QA1 INT
$Nsip = 'nt0qnsinty01.foobar.com'
$Credential = Get-Credential
Connect-NetScaler -Hostname $Nsip -Credential $CredentialS

*** GRN QA1 INT
$Nsip = 'ng0qnsinty01.foobar.com'
$Credential = Get-Credential
Connect-NetScaler -Hostname $Nsip -Credential $Credential -HTTPS


Get-NSConfig -State saved | Select-String -Pattern "\.qa1.int" | out-file -Width 250 H:\NS-Migration\QA1-TRM.txt -Append

Regex: ^.+.*domainName 
Remove Duplicates: ^(.*?)$\s+?^(?=.*^\1$)



Get-NSConfig -State saved | Select-String -Pattern "\.qa1.int.foobar.com" |  Measure-Object


$Servers = Get-NSLBServiceGroup | Where-Object {$_.servicegroupname -like '*.dev*'} | select-object servicegroupname | Get-NSLBServiceGroupMemberBinding -ErrorAction SilentlyContinue | Select-Object servername -Unique 

$Servers.servername | Get-NSLBServer | ForEach-Object {"add server $($_.name) $($_.domain)"}


Get-NSLBServiceGroup | Where-Object {$_.servicegroupname -like '*.dev*'} | select-object servicegroupname | Get-NSLBServiceGroupMonitorBinding -ErrorAction SilentlyContinue

$nate = Get-NSLBServiceGroup | Where-Object {$_.servicegroupname -like '*.dev*'} | select-object servicegroupname
$nate.servicegroupname | Get-NSLBServiceGroupMonitorBinding | Select-Object -Unique monitor_name


$nate = invoke-nitro -Method GET -Type gslbvserver | select gslbvserver -ExpandProperty gslbvserver | select name | where name -Like '*stg.abc*' | sort -Property name 
[System.Collections.ArrayList]$nate2 = @()


foreach ($temp in $nate) {
$pos = $temp.name.indexof("_gslb")
$left = $temp.name.substring(0, $pos)
Write-Host $left 
$nate2.Add($left)
}

Out-File H:\NS-Migration\qa1-test.txt -Append

$RestURI = "http://"+$Nsip+"/nitro/v1/config/gslbvserver/remoteprintipgs.foobar.com_gslb_vip_trm?attrs=name,servicetype"
Invoke-RestMethod -Uri $RestURI -Credential $credential
 

$nateget = Invoke-Nitro -Method GET -Type gslbvserver -Resource remoteprintipgs.foobar.com_gslb_vip_trm | Select-Object gslbvserver
$nateget.gslbvserver


Get-NSLBvirtualserver | Where-Object {$_.name -like '*.dev*' -and $_.curstate -eq "DOWN"} | Select-Object name,ipv46,statechangetimesec,comment | Export-Csv -NoTypeInformation H:\NS-Migration\DEV-DOWN.csv -Append



$ipaddresses = import-csv H:\NS-Migration\DEV-DOWN.csv | select-object $ColumnHeader

Write-Host "Started Pinging.."
foreach( $ip in $ipaddresses) {
    if (test-connection $ip.("ipv46") -count 1 -quiet -ErrorAction SilentlyContinue) {
        write-host $ip.("ipv46") "Ping succeeded." -foreground green

    } else {
         write-host $ip.("ipv46") "Ping failed." -foreground red
    }
    
}


Write-Host "Pinging Completed."


Invoke-Nitro -Method GET -Type appfwlearningdata -Arguments profilename:sso.abc.com_waf_prf,starturl

Get-NSIPResource | Select-Object -Unique ipaddress | Export-Csv -NoTypeInformation H:\NS-Migration\TRM-IPADDR.csv



Get-IBResourceRecord -Credential $Credential -GridServer ibxgridmaster.foobar.com -SearchText itseclog.foobar.com -Type CName

