<#
Read list of FQDN from csv
    connect to old NS (TRM, GRN)
    read GSLB SVC info (OLD VIP)
    connect to new NS (TRM, GRN)
        create GSLB vServer
        bind domainname to GSLB vServer
        For each DC:
            create SERVER entry for OLD VIP and IP
            create GSLB Service
            Bind TCP-ECV monitor to GSLB Service
            Bind GSLB Service to GSLB vServer
#>

function Get-TimeStamp {
    
    return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
    
}

$env = $null
$envinit = $null
$env = Read-Host -Prompt "Environment?"
$envinit = ($env.Substring(0,1))

$Credential = $null
$envlist = $null
$dclistold = $null
$dclistnew = $null
$dclistrpt = $null

$inputfile = $null
$outputfile = $null
$inputfile = "H:\NS-Migration\" + $env + "-VIP.csv"
$outputfile = "H:\NS-Migration\" + $env + "-gslboutput.txt"
$Credential = Get-Credential
$envlist = import-csv -Path $inputfile
$dclistold = @("trm","grn")
$dclistnew = @("trm","grn")
$dclistrpt = @("trm","grn")

"$(Get-TimeStamp) *** START *** Script create_gslb_old.ps1 for Environment: " + $env | Out-File -filepath $outputfile -Append -Encoding ascii

ForEach ($fqdn in $envlist) {

 ForEach ($dc in $dclistold) {

    $OLDNsip = $null
    $oldgslb = $null
    $oldgslbsvcname = $null
    $oldgslbsvcpayld = $null

    $dcinit = $null
    $dcinit = ($dc.Substring(0,1))
    $OLDNsip = 'n' + $dcinit + '0pnsint01.aqrcapital.com'
    
    $oldgslbsvcname = $fqdn.name + "_gslb_svc_" + $dc

    Connect-NetScaler -Hostname $OLDNsip -Credential $Credential
    "$(Get-TimeStamp) GET Old GSLB Service " + $oldgslbsvcname + " from " + $OLDNsip | Out-File -filepath $outputfile -Append -Encoding ascii
    TRY {
        $oldgslb = Invoke-Nitro -Method GET -Type gslbservice -Resource $oldgslbsvcname -OnErrorAction CONTINUE -Confirm -Force
        $oldgslbsvcpayld = $oldgslb.gslbservice
    }#TRY Get Old GSLB Service
    CATCH {
              "$(Get-TimeStamp) FAILED Getting Old GSLB vServer  " + $gslbvipname + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
    }#Catch Get Old GSLB Service

    $trmip = $oldgslbsvcpayld.ipaddress -replace "10.30", "10.31"
    $grnip = $oldgslbsvcpayld.ipaddress -replace "10.31", "10.30"

    Disconnect-NetScaler

        $NEWNsip = $null
        $NEWNsip = 'n' + $dcinit + '0' + $envinit + 'nsinty01.aqrcapital.com'
        $gslbdomname = $null
        $gslbvipname = $null
        $gslbvippayld = $null
        $gslbdompayld = $null
        $gslbdomname = $null
        $gslbvipname = $fqdn.name + "_gslb_vip_" + $dc 
        $gslbdomname = $fqdn.name -replace ".aqrcapital.com", ".int.aqrcapital.com"

        $gslbviphashtbl = @{ }
        $gslbviphashtbl.Set_Item("name",$gslbvipname)
        $gslbviphashtbl.Set_Item("servicetype",$oldgslbsvcpayld.servicetype)
        $gslbviphashtbl.Set_Item("edr","ENABLED")
        $gslbviphashtbl.Set_Item("comment",$oldgslbsvcpayld.comment)
        $gslbvippayld = $gslbviphashtbl

        $gslbdomhashtbl = @{ }
        $gslbdomhashtbl.Set_Item("name",$gslbvipname)
        $gslbdomhashtbl.Set_Item("domainname",$gslbdomname)
        $gslbdompayld = $gslbdomhashtbl

        "$(Get-TimeStamp) Connect to " + $NEWNsip | Out-File -filepath $outputfile -Append -Encoding ascii
        Connect-NetScaler -Hostname $NEWNsip -Credential $Credential -HTTPS

        "$(Get-TimeStamp) Create GSLB vServer  " + $gslbvipname | Out-File -filepath $outputfile -Append -Encoding ascii
        try {
            Invoke-Nitro -Method POST -Type gslbvserver -Resource $gslbvipname -OnErrorAction CONTINUE -Confirm -Force -Payload $gslbvippayld
        } #Try GSLB vServer
        catch {
              "$(Get-TimeStamp) FAILED Creating GSLB vServer  " + $gslbvipname + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
        } #Catch GSLB vServer

        "$(Get-TimeStamp) Bind GSLB DomainName  " + $gslbdomname | Out-File -filepath $outputfile -Append -Encoding ascii
        try {
            Invoke-Nitro -Method PUT -Type gslbvserver_domain_binding -Resource $gslbvipname -OnErrorAction CONTINUE -Confirm -Force -Payload $gslbdompayld
        } #Try GSLB DomainName
        catch {
              "$(Get-TimeStamp) FAILED Binding GSLB DomainName  " + $gslbdomname + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
        } #Catch GSLB DomainName

      "$(Get-TimeStamp) Disconnect from " + $NEWNsip | Out-File -filepath $outputfile -Append -Encoding ascii
      Disconnect-NetScaler
    } #ForEach DC

    ForEach ($dcnew in $dclistnew) {

        $dcnewinit = $null
        $dcnewinit = ($dcnew.Substring(0,1))
        $NEWNsip = $null
        $NEWNsip = 'n' + $dcnewinit + '0' + $envinit + 'nsinty01.aqrcapital.com'
        "$(Get-TimeStamp) Connect to " + $NEWNsip | Out-File -filepath $outputfile -Append -Encoding ascii
        Connect-NetScaler -Hostname $NEWNsip -Credential $Credential -HTTPS


        ForEach ($dcrpt in $dclistrpt) {

            $gslbsrvname = $null
            $newgslbsvcname = $null
            $srvpayld = $null
            $gslbpayld = $null
            $gslbmonpayld = $null
            $gslbsvcpayld = $null
            $gslbsvcvipname = $null

            $gslbsrvname = $fqdn.name + "_gslb_srv_" + $dcrpt
            $newgslbsvcname = $fqdn.name + "_gslb_svc_" + $dcrpt
            $gslbsvcvipname = $fqdn.name + "_gslb_vip_" + $dcnew

            $srvhashtbl = @{ }
            $srvhashtbl.Set_Item("name",$gslbsrvname) 
            IF ($dcrpt -eq "grn") {
                $srvhashtbl.Set_Item("ipaddress",$grnip)
                } ELSE { 
                $srvhashtbl.Set_Item("ipaddress",$trmip)
            } # IF dcrpt
            $srvpayld = $srvhashtbl

            $vipsite = $null
            $gslbsite = $null

            $vipsite = $newgslbsvcname.Substring($newgslbsvcname.Length-3)
            IF ($vipsite -eq 'trm') {
                $gslbsite = "Trumbull"
            }#IF vipsite eq TRM
            ELSE {
                $gslbsite = "Greenwich"
            }#ELSE Vipsite eq GRN

            $gslbhashtbl = @{ }
            $gslbhashtbl.Set_Item("servicename",$newgslbsvcname) 
            $gslbhashtbl.Set_Item("servername",$gslbsrvname)
            $gslbhashtbl.Set_Item("servicetype",$oldgslbsvcpayld.servicetype)
            $gslbhashtbl.Set_Item("port",$oldgslbsvcpayld.port)
            $gslbhashtbl.Set_Item("sitename",$gslbsite)
            $gslbhashtbl.Set_Item("comment",$oldgslbsvcpayld.comment)
            $gslbpayld = $gslbhashtbl

            $gslbmonhashtbl = @{ }
            $gslbmonhashtbl.Set_Item("servicename",$newgslbsvcname) 
            $gslbmonhashtbl.Set_Item("monitor_name","tcp-ecv")
            $gslbmonhashtbl.Set_Item("monstate","ENABLED")
            $gslbmonhashtbl.Set_Item("weight","1")
            $gslbmonpayld = $gslbmonhashtbl

            $gslbsvchashtbl = @{ }
            $gslbsvchashtbl.Set_Item("name",$gslbsvcvipname) 
            $gslbsvchashtbl.Set_Item("servicename",$newgslbsvcname) 
            $gslbsvchashtbl.Set_Item("weight","1")
            $gslbsvcpayld = $gslbsvchashtbl


            "$(Get-TimeStamp) Create GSLB Server " + $gslbsrvname | Out-File -filepath $outputfile -Append -Encoding ascii
            try {
                Invoke-Nitro -Method POST -Type server -Resource $gslbsrvname -OnErrorAction CONTINUE -Confirm -Force -Payload $srvpayld
            } #Catch Server
            catch {
              "$(Get-TimeStamp) FAILED Creating GSLB Server " + $gslbsrvname + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
            } #Catch Server

            "$(Get-TimeStamp) Create GSLB Service " + $newgslbsvcname | Out-File -filepath $outputfile -Append -Encoding ascii
            try {
                Invoke-Nitro -Method POST -Type gslbservice -Resource $newgslbsvcname -OnErrorAction CONTINUE -Confirm -Force -Payload $gslbpayld
            } #Try GSLB Service
            catch {
              "$(Get-TimeStamp) FAILED Creating GSLB Service " + $newgslbsvcname + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
            } #Catch GSLB Service

            "$(Get-TimeStamp) Bind GSLB Monitor to " + $newgslbsvcname | Out-File -filepath $outputfile -Append -Encoding ascii
            try {
                Invoke-Nitro -Method PUT -Type gslbservice_lbmonitor_binding -Resource $newgslbsvcname -OnErrorAction CONTINUE -Confirm -Force -Payload $gslbmonpayld
            } #Try GSLB Monitor
            catch {
              "$(Get-TimeStamp) FAILED Binding GSLB Monitor to " + $newgslbsvcname + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
            } #Catch GSLB Monitor

            "$(Get-TimeStamp) Bind GSLB Service " + $newgslbsvcname | Out-File -filepath $outputfile -Append -Encoding ascii
            try {
                Invoke-Nitro -Method PUT -Type gslbvserver_gslbservice_binding -Resource $gslbsvcvipname -OnErrorAction CONTINUE -Confirm -Force -Payload $gslbsvcpayld
            } #Try GSLB Service Binding
            catch {
              "$(Get-TimeStamp) FAILED Binding GSLB Service " + $newgslbsvcname + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
            } #Catch GSLB Service Binding

        } #ForEach DCRPT

      "$(Get-TimeStamp) Disconnect from " + $NEWNsip | Out-File -filepath $outputfile -Append -Encoding ascii
      Disconnect-NetScaler


      } #ForEach DCNew
  } #ForEach FQDN

Connect-NetScaler -Hostname nt0snsinty01.aqrcapital.com -Credential $Credential -HTTPS
Save-NSConfig
Disconnect-NetScaler


Connect-NetScaler -Hostname ng0snsinty01.aqrcapital.com -Credential $Credential -HTTPS
Save-NSConfig
Disconnect-NetScaler
