
$vpxlist = ("10.30.44.21",
            "10.30.44.22",
            "10.30.172.21",
            "10.30.176.21",
            "10.30.180.21",
            "10.31.44.21",
            "10.31.44.22",
            "10.31.48.21",
            "10.31.48.22",
            "10.31.160.21",
            "10.31.160.22",
            "10.31.164.21",
            "10.31.164.22",
            "10.64.56.21",
            "10.64.56.22"
            )

----



$AllProtocols = [System.Net.SecurityProtocolType]'Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

*** ASH INT

$Nsip = 'va0pnsinty02.foo.bar'
$Credential = Get-Credential
Connect-NetScaler -Hostname $Nsip -Credential $Credential -Https

*** GRN STG

$Nsip = 'ng0snsinty01.foo.bar'
$Credential = Get-Credential
Connect-NetScaler -Hostname $Nsip -Credential $Credential -Https

*** TRM EXT

$Nsip = 'nt0pnsext01.foo.bar'
$Credential = Get-Credential
Connect-NetScaler -Hostname $Nsip -Credential $Credential -HTTPS

*** GRN EXT

$Nsip = 'ng0pnsext01.foo.bar'
$Credential = Get-Credential
Connect-NetScaler -Hostname $Nsip -Credential $Credential -HTTPS



*** TRM INT

$Nsip = 'nt0pnsint01.foo.bar'
$Credential = Get-Credential
$trmsess = Connect-NetScaler -Hostname $Nsip -Credential $Credential


*** GRN INT
$Nsip = 'ng0pnsint01.foo.bar'
$SecurePassword = ConvertTo-SecureString 'HH!qDpk)8S4L' -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential ("nsroot", $SecurePassword)
Connect-NetScaler -Hostname $Nsip -Credential $Credential


*** TRM PRD INT
$Nsip = 'nt0pnsinty01.foo.bar'
$Credential = Get-Credential
Connect-NetScaler -Hostname $Nsip -Credential $Credential -HTTPS

*** GRN DEV INT
$Nsip = 'ng0dnsinty01.foo.bar'
$Credential = Get-Credential
Connect-NetScaler -Hostname $Nsip -Credential $Credential -HTTPS

*** GRN STG INT
$Nsip = 'ng0snsinty01.foo.bar'
$Credential = Get-Credential
Connect-NetScaler -Hostname $Nsip -Credential $Credential -HTTPS

*** GRN QA INT
$Nsip = 'ng0qnsinty01.foo.bar'
$Credential = Get-Credential
Connect-NetScaler -Hostname $Nsip -Credential $Credential -HTTPS

*** TRM DMZ3 EXT
$Nsip = 'nt0pnsexty02.foo.bar'
$Credential = Get-Credential
Connect-NetScaler -Hostname $Nsip -Credential $Credential -HTTPS
----
$SecurePassword = ConvertTo-SecureString "yaABAW0&DJzX" -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential ("nsroot", $SecurePassword)



Get-NSLBMonitor | Where-Object {$_.type -eq 'HTTP'}

Get-NSLBVirtualServer | Where-Object {$_.name -like '*.dev*' -and $_.curstate -eq 'DOWN' } | select-object name,ipv46 | Export-Csv -Path H:\NS-Migration\deldev.csv -Append -NoTypeInformation

Get-NSLBVirtualServer | select-object name | Export-Csv -Path H:\NS-Migration\devipnumber.csv -Append -NoTypeInformation -Force

 | export-csv -path H:\NS-Migration\lbvip-ssl.csv


Get-NSConfig -State saved | Select-String -Pattern "\.dev.int" | out-file -Width 250 H:\NS-Migration\QA1-TRM.txt


$Servers = Get-NSLBServiceGroup | Where-Object {$_.servicegroupname -like '*.dev*'} | select-object servicegroupname | Get-NSLBServiceGroupMemberBinding -ErrorAction SilentlyContinue | Select-Object servername -Unique 

$Servers.servername | Get-NSLBServer | ForEach-Object {"add server $($_.name) $($_.domain)"}


Get-NSLBServiceGroup | Where-Object {$_.servicegroupname -like '*.dev*'} | select-object servicegroupname | Get-NSLBServiceGroupMonitorBinding -ErrorAction SilentlyContinue

$nate = Get-NSLBServiceGroup | Where-Object {$_.servicegroupname -like '*.dev*'} | select-object servicegroupname
$nate.servicegroupname | Get-NSLBServiceGroupMonitorBinding | Select-Object -Unique monitor_name


$RestURI = "http://"+$Nsip+"/nitro/v1/config/gslbvserver/remoteprintipgs.foo.bar_gslb_vip_trm?attrs=name,servicetype"
Invoke-RestMethod -Uri $RestURI -Credential $credential
 

$nateget = Invoke-Nitro -Method GET -Type gslbvserver -Resource remoteprintipgs.foo.bar_gslb_vip_trm | Select-Object gslbvserver
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


Invoke-Nitro -Method GET -Type appfwlearningdata -Arguments profilename:sso.aqr.com_waf_prf,securitycheck:starturl


Get-NSIPResource | Select-Object -Unique ipaddress | Export-Csv -NoTypeInformation H:\NS-Migration\TRM-IPADDR.csv



Get-IBResourceRecord -Credential $Credential -GridServer ibxgridmaster.foo.bar -SearchText itseclog.foo.bar -Type CName

$BigTRMsession = Connect-NetScaler -Credential $credential -Hostname "nt0pnsint.foo.bar" -Https -PassThru
$BigGRNsession = Connect-NetScaler -Credential $credential -Hostname "ng0pnsint.foo.bar" -Https -PassThru

$nate = $null
$nateout = $null
$netscalers=@("nt0pnsint.foo.bar","ng0pnsint.foo.bar")
foreach ($ns in $netscalers) {
        Connect-NetScaler -Credential $credential -Hostname $ns -PassThru
        $nate=Invoke-Nitro -Method GET -Stat -Type lbvserver
        $nateout+=$nate.lbvserver | ? {$_.state -eq "UP" -and $_.tothits -ne "0"} | select name,tothits
        Disconnect-NetScaler
}


$nate = $null
$nateout = $null
$netscalers=@("nt0pnsint.foo.bar","ng0pnsint.foo.bar")
foreach ($ns in $netscalers) {
        Connect-NetScaler -Credential $credential -Hostname $ns -PassThru
        $nate=Invoke-Nitro -Method GET -Stat -Type lbvserver
        $nateout+=$nate.lbvserver | ? {$_.name -match "aqrweb"} | select name,tothits
        Disconnect-NetScaler
}


