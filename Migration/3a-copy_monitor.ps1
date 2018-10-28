<#

Ask for environment ("DEV", "QA1", "STG", "PRD")

Read list of FQDN from csv
    connect to old NS (TRM, GRN)
    for each vip type (plain, 80, 443)
        read LB VIP info
        read LB vServer bindings
        build table
    connect to new NS (TRM, GRN)
        Create new VIP
        Create PTR Record in InfoBlox
        for each Binding, create the corresponding reference
        Bind to the VIP
#>

function Get-TimeStamp {
    
    return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
    
}

$Credential = $null
$envlist = $null
$dclistold = $null
$dclistrpt = $null
$fqdn = $null
$dc = $null
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

$inputfile = $null
$logfile = $null
$inputfile = "H:\NS-Migration\" + $env + "-VIP.csv"
$logfile = "H:\NS-Migration\" + $env + "-monitoroutput.txt"
$Credential = Get-Credential
$envlist = import-csv -Path $inputfile
$dclistold = @("trm","grn")
$ibarrafile = $null
$ibarrafile = "H:\NS-Migration\" + $env + "-Ibarra.txt"

"$(Get-TimeStamp) *** START *** Script create_lbvip_old.ps1 for Environment: " + $env | Out-File -filepath $logfile -Append -Encoding ascii


ForEach ($fqdn in $envlist) {

 ForEach ($dc in $dclistold) {

    $dcinit = $null
    $OLDNsip = $null
    $NEWNsip = $null
    $newipaddr = $null
    $vipextension = $null

    $dcinit = ($dc.Substring(0,1))
    $OLDNsip = 'n' + $dcinit + '0pnsint01.foo.bar'
    $NEWNsip = 'n' + $dcinit + '0' + $envinit + 'nsinty01.foo.bar'

    IF ($dc -eq "trm") {
        $newipaddr = $trmpref + $fqdn.trmip
    }#IF IP Address
    ELSE {
        $newipaddr = $grnpref + $fqdn.grnip
    }#ELSE IP Address

    ForEach ($vipextension in ("_vip_","_vip_80_","_vip_443_")) {

        $oldvipname = $null
        $oldvserver = $null
        $newvippayld = $null
        $oldsslbind = $null
        $oldvsbindings = $null
        $newsvcbndhashtbl = $null
        $newsvcbndpayld = $null
        $oldsvg = $null
        $oldmon = $null
        $oldsvgbnd = $null
        $oldsvgmon = $null
        $newsvgname = $null
        $newsvgtype = $null
        $newsvgcomment = $null
        $newsvgusip = $null
        $newsvgcip = $null
        $newsvgciphead = $null
        $newsvcbndhashtbl = $null
        $newsvcbndpayld = $null
        $newsvgbndhashtbl = $null
        $newsvgbndpayld = $null
        $newrspbndvserver = $null
        $newrspbndbndpnt = $null
        $newrspbndpolname = $null
        $newrspbndpriority = $null
        $newrewbndvserver = $null
        $newrewbndbndpnt = $null
        $newrewbndpolname = $null
        $newrewbndpriority = $null
        $newsvgpayld = $null
        $newmonpayld = $null

        
        $oldvipname = $fqdn.name + $vipextension + $dc

        Connect-NetScaler -Hostname $OLDNsip -Credential $Credential
        "$(Get-TimeStamp) CONNECT: " + $OLDNsip | Out-File -filepath $logfile -Append -Encoding ascii
        
        "$(Get-TimeStamp) Get vServer " + $oldvipname | Out-File -filepath $logfile -Append -Encoding ascii

        try {
            $oldvserver = Invoke-Nitro -Method GET -Type lbvserver -Resource $oldvipname -OnErrorAction CONTINUE -Confirm -Force
            IF ($oldvserver -ne $null) {
                $newvippayld = @{ }
                $newvippayld = @{
                                name = $oldvserver.lbvserver.name
                                servicetype = $oldvserver.lbvserver.servicetype
                                port = $oldvserver.lbvserver.port
                                ipv46 = $newipaddr
                                clttimeout = $oldvserver.lbvserver.clttimeout
                                persistencetype = $oldvserver.lbvserver.persistencetype
                                timeout = $oldvserver.lbvserver.timeout
                                persistmask = $oldvserver.lbvserver.persistmask
                                v6persistmasklen = $oldvserver.lbvserver.v6persistmasklen
                                persistencebackup = $oldvserver.lbvserver.persistencebackup
                                backuppersistencetimeout = $oldvserver.lbvserver.backuppersistencetimeout
                                comment = $oldvserver.lbvserver.comment
                                }# newvippayld
                $ibarratext = $oldvserver.lbvserver.name + "," + $oldvserver.lbvserver.ipv46 + "," + $newipaddr
                $ibarratext | Out-File -FilePath $ibarrafile -Append
            }#IF NOT NUll
            IF ($oldvserver.lbvserver.servicetype -eq "SSL") {
                "$(Get-TimeStamp) SSL Binding for " + $oldvipname | Out-File -filepath $logfile -Append -Encoding ascii
                try {
                    $oldsslbind = Invoke-Nitro -Method GET -Type sslvserver_sslcertkey_binding -Resource $oldvipname -OnErrorAction CONTINUE -Confirm -Force 
                    }#TRY SSL Cert Binding
                catch {
                    "$(Get-TimeStamp) Error Getting SSL Binding for " + $oldvipname + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
                    }#CATCH SSL Cert Binding
            }#IF SSL
        }#TRY Get vServer
        catch {
            "$(Get-TimeStamp) FAILED: Get vServer for " + $oldvipname + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
        }#CATCH Get vServer

        "$(Get-TimeStamp) Get vServer bindings for " + $oldvipname | Out-File -filepath $logfile -Append -Encoding ascii
        try {
            $oldvsbindings = Invoke-Nitro -Method GET -Type lbvserver_binding -Resource $oldvipname -OnErrorAction CONTINUE -Confirm -Force 
        }#TRY lbvserver binding
        Catch {
              "$(Get-TimeStamp) FAILED: Get vServer bindings for " + $oldvipname + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
        }#CATCH Get VIP Binding

#Service
        IF ($oldvsbindings.lbvserver_binding.lbvserver_service_binding -ne $null) {
            $newsvcname = $null
            IF ($oldvsbindings.lbvserver_binding.lbvserver_service_binding.servicename -eq "HTTP_to_HTTPS_Redirect") {
                $newsvcname = "http_to_https_dummy_vip_donotdelete"
            }#If HTTP Redirect
            ELSE { 
                $newsvcname = $oldvsbindings.lbvserver_binding.lbvserver_service_binding.servicename
            }#ELSE HTTP redirect
        }#If Service

#ServiceGroup
        IF ($oldvsbindings.lbvserver_binding.lbvserver_servicegroup_binding -ne $null) {
            TRY {
                $oldsvg = Get-NSLBServiceGroup -Name $oldvsbindings.lbvserver_binding.lbvserver_servicegroup_binding.servicegroupname
                $newsvgname = $oldsvg.servicegroupname
                $newsvgtype = $oldsvg.servicetype
                $newsvgcomment = $oldsvg.comment
                $newsvgusip = $oldsvg.usip
                $newsvgcip = $oldsvg.cip
                $newsvgciphead = $oldsvg.cipheader
            }#TRY Get ServiceGroup
            CATCH {
                  "$(Get-TimeStamp) FAILED: Get ServiceGroup for " + $oldvsbindings.lbvserver_binding.lbvserver_servicegroup_binding.servicegroupname + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
            }#CATCH Get ServiceGroup


#ServiceGroup Monitor
            TRY {
                $oldsvgmon = Get-NSLBServiceGroupMonitorBinding -Name $oldvsbindings.lbvserver_binding.lbvserver_servicegroup_binding.servicegroupname
                IF ($oldsvgmon.monitor_name -ne $null) {
                    TRY {
                        $oldmon = Get-NSLBMonitor -Name $oldsvgmon.monitor_name
                    }#TRY Get Monitor
                    CATCH {
                          "$(Get-TimeStamp) FAILED: Get Monitor for " + $oldsvgmon.monitor_name + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
                    }#CATCH Get Monitor
                }#IF Monitor NULL
            }#TRY Get ServiceGroup Monitor
            CATCH {
                  "$(Get-TimeStamp) FAILED: Get ServiceGroup Monitor for " + $oldvsbindings.lbvserver_binding.lbvserver_servicegroup_binding.servicegroupname + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
            }#CATCH Get ServiceGroup Monitor
        }#If ServiceGroup

#Disconnect Old NetScaler
        Disconnect-NetScaler
        "$(Get-TimeStamp) DISCONNECT: " + $OLDNsip | Out-File -filepath $logfile -Append -Encoding ascii
#Connect New NetScaler
        Connect-NetScaler -Hostname $NEWNsip -Credential $Credential -HTTPS
        "$(Get-TimeStamp) CONNECT: " + $NEWNsip | Out-File -filepath $logfile -Append -Encoding ascii

        IF ($oldvserver -ne $null) {
#Create ServiceGroup Monitor
                IF ($oldsvgmon.monitor_name -ne $null) {
                    $newmonpayld = @{ }
                    $newmonpayld = @{
                                        monitorname = $oldmon.monitorname
                                        type = $oldmon.type
                                        secure = $oldmon.secure
                                        scriptname = $oldmon.scriptname
                                        respcode = $oldmon.respcode
                                        httprequest = $oldmon.httprequest
                                        send = $oldmon.send
                                        } #newmonpayld
                    "$(Get-TimeStamp) CREATE: New Monitor " + $oldmon.monitorname | Out-File -filepath $logfile -Append -Encoding ascii
                   TRY {
                        Invoke-Nitro -Method POST -Type lbmonitor -Payload $newmonpayld -OnErrorAction CONTINUE -Confirm -Force
		    	    }#TRY New Monitor
			        CATCH {
                          "$(Get-TimeStamp) FAILED: Create Monitor for " + $oldmon.monitorname + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
			        }#CATCH New Monitor

#Bind ServiceGroup Monitor
                    "$(Get-TimeStamp) BIND: Monitor to ServiceGroup " + $newsvgname + " " + $oldmon.monitorname | Out-File -filepath $logfile -Append -Encoding ascii
                    $newsvgmonpayld = @{ }
                    $newsvgmonpayld = @{
                                        servicegroupname = $newsvgname
                                        monitor_name = $oldmon.monitorname
                                        weight = "1"
                    }#newmonsvgpayld
        			TRY {
	    			    Invoke-Nitro -Method PUT -Type servicegroup_lbmonitor_binding -Payload $newsvgmonpayld -OnErrorAction CONTINUE -Confirm -Force
#	        			New-NSLBServiceGroupMonitor -Name $oldsvgmon.servicegroupname -MonitorName $oldsvgmon.monitorname -Confirm -ErrorAction Continue
		        	}#TRY Bind Monitor
			        CATCH {
                          "$(Get-TimeStamp) FAILED: Monitor Binding for " + $newsvgname + " " + $oldmon.monitorname + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
			        }#CATCH Monitor Binding
                }#IF Monitor NULL

        }# IF VIP not Null
        ELSE {
             "$(Get-TimeStamp) FAILED: Old VIP does not exist: " + $oldvipname + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
        }#ELSE VIP IS NULL
    }# ForEach VIPExtension
    
  } #ForEach DC

} #ForEach FQDN

$savedc = @("t","g")

ForEach ($save in $savedc) {
        $SAVENsip = $null
        $SAVENsip = 'n' + $save + '0' + $envinit + 'nsinty01.foo.bar'

        "$(Get-TimeStamp) Save Config " + $SAVENsip | Out-File -filepath $outputfile -Append -Encoding ascii
        try {
            Connect-NetScaler -Hostname $SAVENsip -Credential $Credential -HTTPS
            Save-NSConfig
            Disconnect-NetScaler
        } #Try SaveConfig
        catch {
              "$(Get-TimeStamp) FAILED Save Config  " + $SAVENsip + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
        } #Catch SaveConfig
}#ForEach SaveDC


"$(Get-TimeStamp) *** END *** Script create_lbvip_old.ps1 for Environment: " + $env | Out-File -filepath $logfile -Append -Encoding ascii
