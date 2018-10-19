<#
Read CSV file and for each DC, and each VIP, change the SERVER record for the GSLB Service IP.
Delete tho GSLB DomainName Binding from the OLD VPX
#>

function Get-TimeStamp {
    
    return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
    
}

$env = $null
$envinit = $null
$credential = $null
$dclist = $null
$gslbdclist = $null
$dclist = @("trm","grn")
$gslbdclist = @("trm","grn")

$env = Read-Host -Prompt "Environment?"
$envinit = ($env.Substring(0,1))
$inputfile = $null
$logfile = $null
$inputfile = "H:\NS-Migration\" + $env + "-VIP.csv"
$logfile = "H:\NS-Migration\" + $env + "-chgsrv-output.txt"
$Credential = Get-Credential
$envlist = import-csv -Path $inputfile

$trmpref = $null
$grnpref = $null

$env = $null
$envinit = $null
$env = Read-Host -Prompt "Environment?"
$envinit = ($env.Substring(0,1))

$grnpref = "10.30."

switch ($env) {
"prd" {
      $trmpref = "10.64." ; break
      }# PRD Switch
default {
      $trmpref = "10.31." ; break
      }#default switch
}#switch env

"$(Get-TimeStamp) *** START *** Script change_sev_ip_disable_gslb_svc.ps1 for Environment: " + $env | Out-File -filepath $logfile -Append -Encoding ascii

ForEach ($dc in $dclist) {
    $dcinit = $null
    $dcinit = ($dc.Substring(0,1))

    $NEWNsip = $null
    $NEWNsip = 'n' + $dcinit + '0' + $envinit + 'nsinty01.aqrcapital.com'
    $OLDNsip = $null
    $OLDNsip = 'n' + $dcinit + '0pnsint01.aqrcapital.com'

    "$(Get-TimeStamp) CONNECT: " + $NEWNsip | Out-File -filepath $logfile -Append -Encoding ascii
    Connect-NetScaler -Hostname $NewNsip -Credential $Credential -HTTPS

    ForEach ($vip in $envlist){
        ForEach ($gslbdc in $gslbdclist) {
            $gslbsrvname = $null
            $gslbsrvnewip = $null
            $hashtbl = $null
            $payld = $null

            $gslbsrvname = $vip.name + '_gslb_srv_' + $gslbdc
            IF ($gslbdc -eq "TRM") {
                $gslbsrvnewip = $trmpref + $vip.trmip
            }#IF GSLBDC
            ELSE {
                $gslbsrvnewip = $grnpref + $vip.grnip
            }#ELSE GSLBDC
<#
#Update Server Entry
            $hashtbl = @{ }
            $hashtbl.Set_Item("name",$gslbsrvname) 
            $hashtbl.Set_Item("ipaddress",$gslbsrvnewip) 
            $payld = $hashtbl
           "$(Get-TimeStamp) Update Server " + $gslbsrvname + " " + $gslbsrvnewip | Out-File -filepath $logfile -Append -Encoding ascii
            try {
#                Set-NSLBServer -Name $gslbsrvname -IPAddress $gslbsrvnewip -Force -Confirm -ErrorAction Continue
                Invoke-Nitro -Method PUT -Type server -Resource $gslbsrvname -OnErrorAction CONTINUE -Confirm -Force -Payload $payld
            }#TRY Invoke-Nitro
            catch {
                  "$(Get-TimeStamp) FAILED: Change Server IP "  + $gslbsrvname + " " + $gslbsrvnewip + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
            }#CATCH Invoke-Nitro

#Set PublicIP to *
            $gslbsvcname = $null
            $gslbsvcname = $vip.name + '_gslb_svc_' + $gslbdc
            $gslbsvcpayld = @{ }
            $gslbsvcpayld = @{
                             servicename = $gslbsvcname
                             publicip = "*"
                             state = "ENABLED"
                             }#gslbvippayld
           "$(Get-TimeStamp) Set Public IP " + $gslbsvcname | Out-File -filepath $logfile -Append -Encoding ascii

                try {
                   Invoke-Nitro -Method PUT -Type gslbservice -Payload $gslbsvcpayld -OnErrorAction CONTINUE -Confirm -Force
                }#TRY Invoke Nitro Delete
                catch {
                  "$(Get-TimeStamp) FAILED: Set Public IP "  + $gslbsvcname + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
                }#CATCH Invoke Nitro Delete

#Remove TCP-ECV monitor binding
#            $gslbmontype = $null
#            $gslbmontype = "gslbservice_lbmonitor_binding/" + $gslbsvcname + "?args=monitor_name:tcp-ecv"
#
#           "$(Get-TimeStamp) Remove Monitor Binding " + $gslbsvcname | Out-File -filepath $logfile -Append -Encoding ascii
#
#                try {
#                   Invoke-Nitro -Method DELETE -Type $gslbmontype -OnErrorAction CONTINUE -Confirm -Force
#                }#TRY Invoke Nitro Delete
#                catch {
#                  "$(Get-TimeStamp) FAILED: Remove Monitor Binding "  + $gslbsvcname + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
#                }#CATCH Invoke Nitro Delete
#
#
#        }#ForEach GSLBDC
#    }#ForEach VIP
#>
#Remove DomainName Binding
    "$(Get-TimeStamp) CONNECT: " + $OLDNsip | Out-File -filepath $logfile -Append -Encoding ascii
    Connect-NetScaler -Hostname $OLDNsip -Credential $Credential

    ForEach ($vip in $envlist){
        ForEach ($gslbdc in $gslbdclist) {
            $gslbvipname = $null
            $gslbvipname = $vip.name + "_gslb_vip_" + $gslbdc

            $pos = $null
            $left = $null
            $pos = $vip.name.indexof(".aqrcap")
            $left = $vip.name.substring(0, $pos)
            $gslbdomname = $left + ".int.aqrcapital.com"


            $gslbdomtype = "gslbvserver_domain_binding/" + $gslbvipname + "?args=" + $gslbdomname
<#            $gslbvippayld = @{ }
            $gslbvippayld = @{
                             name = $gslbvipname
                             }#gslbvippayld
#>
           "$(Get-TimeStamp) Remove DomainName Binding " + $gslbvipname + " " + $gslbdomname | Out-File -filepath $logfile -Append -Encoding ascii

                try {
                   Invoke-Nitro -Method DELETE -Type $gslbdomtype -OnErrorAction CONTINUE -Confirm -Force
                }#TRY Invoke Nitro Delete
                catch {
                  "$(Get-TimeStamp) FAILED: Remove DomainName Binding "  + $gslbvipname + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
                }#CATCH Invoke Nitro Delete


        }#ForEach GSLBDC
    }#ForEach VIP
    Save-NSConfig
    Disconnect-NetScaler
}#ForEach DC

$savedc = @("t","g")

ForEach ($save in $savedc) {
        $SAVENsip = $null
        $SAVENsip = 'n' + $save + '0' + $envinit + 'nsinty01.aqrcapital.com'

        "$(Get-TimeStamp) Save Config " + $SAVENsip | Out-File -filepath $outputfile -Append -Encoding ascii
        try {
            Connect-NetScaler -Hostname $SAVENsip -Credential $Credential -HTTPS
            Save-NSConfig
            Disconnect-NetScaler
        } #Try SaveConfig
        catch {
              "$(Get-TimeStamp) FAILED Save Config  " + $SAVENsip + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
        } #Catch SaveConfig
}#ForEach SaveDC



"$(Get-TimeStamp) *** END *** Script change_sev_ip_disable_gslb_svc.ps1 for Environment: " + $env | Out-File -filepath $logfile -Append -Encoding ascii
