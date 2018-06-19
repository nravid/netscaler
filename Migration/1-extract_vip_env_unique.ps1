
<#
Ask for environment ("DEV", "QA1", "STG", "PRD")
For each DC (TRM, GRN), scan through GSLB vServers and extract those with domain binding for that environment
Sort uniquely and export CSV file
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
$envcompare = '*.' + $env + '.int.aqr*'
$credential = Get-Credential

$outputfile = $null
$outputfile = "H:\NS-Migration\" + $env + "-VIP.csv"
$logfile = $null
$logfile = "H:\NS-Migration\" + $env + "-gslbextract.txt"

"$(Get-TimeStamp) *** START *** Script extract_vip_env_unique.ps1 for Environment: " + $env | Out-File -filepath $logfile -Append -Encoding ascii
"$(Get-TimeStamp) Environment Compare: " + $envcompare | Out-File -filepath $logfile -Append -Encoding ascii

ForEach ($dc in $dclist) {
    $dcinit = $null
    $dcinit = ($dc.Substring(0,1))

    $OLDNsip = $null
    $OLDNsip = 'n' + $dcinit + '0pnsint01.aqrcapital.com'

    "$(Get-TimeStamp) CONNECT to " + $OLDNsip | Out-File -filepath $logfile -Append -Encoding ascii

    Connect-NetScaler -Hostname $OLDNsip -Credential $Credential

    "$(Get-TimeStamp) GET GSLB DomainName Bindings from " + $OLDNsip | Out-File -filepath $logfile -Append -Encoding ascii
    $servers = $null
    TRY {
        $servers = Invoke-Nitro -Method GET -Type gslbvserver_domain_binding?bulkbindings=yes | select gslbvserver_domain_binding -ExpandProperty gslbvserver_domain_binding | select name, domainname | where domainname -Like $envcompare
        }#TRY GET Bindings
    CATCH {
          "$(Get-TimeStamp) FAILED GET GSLB DomainName Bindings from " + $OLDNsip + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
    }#CATCH GET Bindings
    

    ForEach ($vip in $servers) {
        $pos = $null
        $left = $null
        $pos = $vip.name.indexof("_gslb")
        TRY {
            $left = $vip.name.substring(0, $pos)
            [void]$newservers.Add($left)
            "$(Get-TimeStamp) CONVERT " + $vip.name + "to: " + $left | Out-File -filepath $logfile -Append -Encoding ascii
            }#TRY SubString
        CATCH {
              "$(Get-TimeStamp) FAILED VIP Conversion for VIP Name " + $vip.name + " and DomainName " + $vip.domainname + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
        }#CATCH SubString


    }#ForEach VIP

}#ForEach DC

"$(Get-TimeStamp) Writing to File " + $outputfile | Out-File -filepath $logfile -Append -Encoding ascii
TRY {
    $newservers | select @{Label='Name';Expression={$_}} | Sort-Object -Property Name -Unique | Export-Csv -NoTypeInformation -Path $outputfile -Append
    }#TRY Export File
CATCH {
      "$(Get-TimeStamp) FAILED Writing file " + $outputfile + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
}#CATCH Export File


"$(Get-TimeStamp) *** END *** Script extract_vip_env_unique.ps1 for Environment: " + $env | Out-File -filepath $logfile -Append -Encoding ascii
