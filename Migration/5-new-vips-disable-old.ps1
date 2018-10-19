
<#
Ask for environment ("DEV", "QA1", "STG", "PRD")
For each DC (TRM, GRN), scan through new VPX LB vServers and extract the list of vServers for that environment
Sort uniquely and disable old VPX VIPs
#>


function Get-TimeStamp {
    
    return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
    
}

$AllProtocols = [System.Net.SecurityProtocolType]'Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols


$env = $null
$envinit = $null
$credential = $null
$dclist = $null
$dclist = @("trm","grn")

$newservers = New-Object System.Collections.ArrayList
$unqservers = New-Object System.Collections.ArrayList

$env = Read-Host -Prompt "Environment?"
$envinit = ($env.Substring(0,1))
$credential = Get-Credential

$logfile = $null
$logfile = "H:\NS-Migration\" + $env + "-vipDisable.txt"

"$(Get-TimeStamp) *** START *** Script new-vips-disable-old.ps1 for Environment: " + $env | Out-File -filepath $logfile -Append -Encoding ascii

ForEach ($dc in $dclist) {
    $dcinit = $null
    $dcinit = ($dc.Substring(0,1))

    $OLDNsip = $null
    $OLDNsip = 'n' + $dcinit + '0pnsint01.aqrcapital.com'
    $NEWNsip = $null
    $NEWNsip = 'n' + $dcinit + '0' + $envinit + 'nsinty01.aqrcapital.com'

    "$(Get-TimeStamp) CONNECT to " + $NEWNsip | Out-File -filepath $logfile -Append -Encoding ascii

    Connect-NetScaler -Hostname $NEWNsip -Credential $Credential -HTTPS

    "$(Get-TimeStamp) GET List of vServers from " + $NEWNsip | Out-File -filepath $logfile -Append -Encoding ascii
    $servers = $null
    TRY {
        $servers = Invoke-Nitro -Method GET -Type lbvserver | select lbvserver -ExpandProperty lbvserver | select name
        }#TRY GET Bindings
    CATCH {
          "$(Get-TimeStamp) FAILED GET List of vServers from " + $NEWNsip + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
    }#CATCH GET Bindings
    
    "$(Get-TimeStamp) DISCONNECT from " + $NEWNsip | Out-File -filepath $logfile -Append -Encoding ascii
    Disconnect-NetScaler

    "$(Get-TimeStamp) CONNECT to " + $OLDNsip | Out-File -filepath $logfile -Append -Encoding ascii

    Connect-NetScaler -Hostname $OLDNsip -Credential $Credential

    ForEach ($vip in $servers) {
        TRY {
            "$(Get-TimeStamp) DISABLE " + $vip.name + " from " + $OLDNsip | Out-File -filepath $logfile -Append -Encoding ascii
            $oldvippayld = @{ }
            $oldvippayld = @{
                             name = $vip.name
                             }#oldvippayld
            Invoke-Nitro -Method POST -Type lbvserver -Action disable -Payload $oldvippayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
            }#TRY SubString
        CATCH {
              "$(Get-TimeStamp) FAILED DISABLE VIP " + $vip.name + " from " + $OLDNsip + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
        }#CATCH SubString


    }#ForEach VIP
    Save-NSConfig
    Disconnect-NetScaler
}#ForEach DC



"$(Get-TimeStamp) *** END *** Script new-vips-disable-old.ps1 for Environment: " + $env | Out-File -filepath $logfile -Append -Encoding ascii
