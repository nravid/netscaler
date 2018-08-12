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

IF ($env -eq "prd") {
    $trmpref = "10.64."
}# IF env = prd
ELSE {
    $trmpref = "10.31."
}# ELSE env = prd

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
$outputfile = $null
$inputfile = "H:\NS-Migration\" + $env + "-VIP.csv"
$outputfile = "H:\NS-Migration\" + $env + "-VIPoutput.txt"
$Credential = Get-Credential
$envlist = import-csv -Path $inputfile
$dclistold = @("trm","grn")

"$(Get-TimeStamp) *** START *** Script create_lbvip_old.ps1 for Environment: " + $env | Out-File -filepath $outputfile -Append -Encoding ascii


ForEach ($fqdn in $envlist) {

 ForEach ($dc in $dclistold) {

    $dcinit = $null
    $OLDNsip = $null
    $NEWNsip = $null
    $newipaddr = $null
    $vipextension = $null

    $dcinit = ($dc.Substring(0,1))
    $OLDNsip = 'n' + $dcinit + '0pnsint01.foobar.com'
    $NEWNsip = 'n' + $dcinit + '0' + $envinit + 'nsinty01.foobar.com'

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
        "$(Get-TimeStamp) CONNECT: " + $OLDNsip | Out-File -filepath $outputfile -Append -Encoding ascii
        
        "$(Get-TimeStamp) Get vServer " + $oldvipname | Out-File -filepath $outputfile -Append -Encoding ascii

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
            }#IF NOT NUll
            IF ($oldvserver.lbvserver.servicetype -eq "SSL") {
                "$(Get-TimeStamp) SSL Binding for " + $oldvipname | Out-File -filepath $outputfile -Append -Encoding ascii
                try {
                    $oldsslbind = Invoke-Nitro -Method GET -Type sslvserver_sslcertkey_binding -Resource $oldvipname -OnErrorAction CONTINUE -Confirm -Force 
                    }#TRY SSL Cert Binding
                catch {
                    "$(Get-TimeStamp) Error Getting SSL Binding for " + $oldvipname + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
                    }#CATCH SSL Cert Binding
            }#IF SSL
        }#TRY Get vServer
        catch {
            "$(Get-TimeStamp) FAILED: Get vServer for " + $oldvipname + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
        }#CATCH Get vServer

        "$(Get-TimeStamp) Get vServer bindings for " + $oldvipname | Out-File -filepath $outputfile -Append -Encoding ascii
        try {
            $oldvsbindings = Invoke-Nitro -Method GET -Type lbvserver_binding -Resource $oldvipname -OnErrorAction CONTINUE -Confirm -Force 
        }#TRY lbvserver binding
        Catch {
              "$(Get-TimeStamp) FAILED: Get vServer bindings for " + $oldvipname + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
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
                  "$(Get-TimeStamp) FAILED: Get ServiceGroup for " + $oldvsbindings.lbvserver_binding.lbvserver_servicegroup_binding.servicegroupname + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
            }#CATCH Get ServiceGroup

#ServiceGroup Members
            TRY {
                $oldsvgbnd = Get-NSLBServiceGroupMemberBinding -Name $oldvsbindings.lbvserver_binding.lbvserver_servicegroup_binding.servicegroupname
                IF ($oldsvgbnd -isnot [array]) {
                    $oldsvgbnd = @($oldsvgbnd)
                }#IF not an array
            }#TRY Get ServiceGroup Members
            CATCH {
                  "$(Get-TimeStamp) FAILED: Get ServiceGroup Member for " + $oldvsbindings.lbvserver_binding.lbvserver_servicegroup_binding.servicegroupname + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
            }#CATCH Get ServiceGroup Members

#ServiceGroup Monitor
            TRY {
                $oldsvgmon = Get-NSLBServiceGroupMonitorBinding -Name $oldvsbindings.lbvserver_binding.lbvserver_servicegroup_binding.servicegroupname
                IF ($oldsvgmon.monitor_name -ne $null) {
                    TRY {
                        $oldmon = Get-NSLBMonitor -Name $oldsvgmon.monitor_name
                    }#TRY Get Monitor
                    CATCH {
                          "$(Get-TimeStamp) FAILED: Get Monitor for " + $oldsvgmon.monitor_name + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
                    }#CATCH Get Monitor
                }#IF Monitor NULL
            }#TRY Get ServiceGroup Monitor
            CATCH {
                  "$(Get-TimeStamp) FAILED: Get ServiceGroup Monitor for " + $oldvsbindings.lbvserver_binding.lbvserver_servicegroup_binding.servicegroupname + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
            }#CATCH Get ServiceGroup Monitor
        }#If ServiceGroup

#Responder Policy
        IF ($oldvsbindings.lbvserver_binding.lbvserver_responderpolicy_binding -ne $null) {
            $newrspbndvserver = $oldvsbindings.lbvserver_binding.lbvserver_responderpolicy_binding.name
            $newrspbndbndpnt = $oldvsbindings.lbvserver_binding.lbvserver_responderpolicy_binding.bindpoint
            $newrspbndpolname = $oldvsbindings.lbvserver_binding.lbvserver_responderpolicy_binding.policyname
            $newrspbndpriority = $oldvsbindings.lbvserver_binding.lbvserver_responderpolicy_binding.priority
            Try {
                $oldrspbnd = Get-NSLBVirtualServerResponderPolicyBinding -Name $oldvipnname
            }#TRY Get Responder Bindings
            Catch {
                  "$(Get-TimeStamp) FAILED: Get Responder binding for " + $oldvipname + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
            }#CATCH Get Responder Bindings
            Try {
                $oldrsppol = Get-NSResponderPolicy -Name $oldvsbindings.lbvserver_binding.lbvserver_responderpolicy_binding.policyname
            }#TRY Get Responder Policy
            Catch {
                  "$(Get-TimeStamp) FAILED: Get Responder Policy for " + $oldvsbindings.lbvserver_binding.lbvserver_responderpolicy_binding.policyname + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
            }#CATCH Get Responder Policy
            Try {
                $oldrspact = Get-NSResponderAction -Name $oldrsppol.action
            }#TRY Get Responder Policy
            Catch {
                  "$(Get-TimeStamp) FAILED: Get Responder Action for " + $oldrsppol.action + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
            }#CATCH Get Responder Policy
        }#If Responder Policy

#Rewrite Policy
        IF ($oldvsbindings.lbvserver_binding.lbvserver_rewritepolicy_binding -ne $null) {
            $newrewbndvserver = $oldvsbindings.lbvserver_binding.lbvserver_rewritepolicy_binding.name
            $newrewbndbndpnt = $oldvsbindings.lbvserver_binding.lbvserver_rewritepolicy_binding.bindpoint
            $newrewbndpolname = $oldvsbindings.lbvserver_binding.lbvserver_rewritepolicy_binding.policyname
            $newrewbndpriority = $oldvsbindings.lbvserver_binding.lbvserver_rewritepolicy_binding.priority
            Try {
                $oldrewbnd = Get-NSLBVirtualServerRewritePolicyBinding -Name $oldvipnname
            }#TRY Get Rewrite Bindings
            Catch {
                  "$(Get-TimeStamp) FAILED: Get Rewrite binding for " + $oldvipname + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
            }#CATCH Get Rewrite Bindings
            Try {
                $oldrewpol = Get-NSRewritePolicy -Name $oldvsbindings.lbvserver_binding.lbvserver_rewritepolicy_binding.policyname
            }#TRY Get Rewrite Policy
            Catch {
                  "$(Get-TimeStamp) FAILED: Get Rewrite Policy for " + $oldvsbindings.lbvserver_binding.lbvserver_rewritepolicy_binding.policyname + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
            }#CATCH Get Rewrite Policy
            Try {
                $oldrewact = Get-NSRewriteAction -Name $oldrewpol.action
            }#TRY Get Rewrite Policy
            Catch {
                  "$(Get-TimeStamp) FAILED: Get Rewrite Action for " + $oldrewpol.action + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
            }#CATCH Get Rewrite Policy
        }#If Rewrite Policy
#Disconnect Old NetScaler
        Disconnect-NetScaler
        "$(Get-TimeStamp) DISCONNECT: " + $OLDNsip | Out-File -filepath $outputfile -Append -Encoding ascii
#Connect New NetScaler
        Connect-NetScaler -Hostname $NEWNsip -Credential $Credential -HTTPS
        "$(Get-TimeStamp) CONNECT: " + $NEWNsip | Out-File -filepath $outputfile -Append -Encoding ascii

        IF ($oldvserver -ne $null) {
#Create New VIP
            "$(Get-TimeStamp) CREATE: New VIP " + $oldvserver.lbvserver.name | Out-File -filepath $outputfile -Append -Encoding ascii
            TRY {
                Invoke-Nitro -Method POST -Type lbvserver -OnErrorAction CONTINUE -Confirm -Force -Payload $newvippayld
            }#TRY Create VIP
            CATCH {
                  "$(Get-TimeStamp) FAILED: Create LB VIP for " + $oldvserver.lbvserver.name + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
            }#CATCH Create VIP
#
#Update InfoBlox with Appropriate PTR Record
            $ptrpos = $null
            $ptrhost = $null
            $ptrpos = $oldvserver.lbvserver.name.indexof(".foobar")
            $ptrhost = $oldvserver.lbvserver.name.substring(0, $ptrpos) + ".int"

            "$(Get-TimeStamp) CREATE: New PTR Record " + $oldvserver.lbvserver.name | Out-File -filepath $outputfile -Append -Encoding ascii
            TRY {
                Create-IbxRecord -Credential $Credential -RecordType PTR -ComputerName $ptrhost -Domain .foobar.com -IPv4Address $newipaddr -Force Force -Confirm -ErrorAction Continue | Out-File -filepath $outputfile -Append -Encoding ascii
            }#TRY Create IBX Record
            CATCH {
                  "$(Get-TimeStamp) FAILED: Create New PTR Record for " + $oldvserver.lbvserver.name + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
            }#CATCH Create IBX Record
#
#Set SSL Profile/Cert to VIP
		    IF ($oldvserver.lbvserver.servicetype -eq "SSL") {
                "$(Get-TimeStamp) BIND: SSL Record " + $oldvserver.lbvserver.name + " " + $oldsslbind.sslvserver_sslcertkey_binding.certkeyname | Out-File -filepath $outputfile -Append -Encoding ascii
                $newsslprfpayld = @{ }
                $newsslprfpayld = @{
                                   vservername = $oldvserver.lbvserver.name
                                   sslprofile = "abc_default_ssl_profile_frontend"
                }#newsslprfpayld
	    		TRY {
      			    Invoke-Nitro -Method PUT -Type sslvserver -Payload $newsslprfpayld -OnErrorAction CONTINUE -Confirm -Force
#	    			Set-NSLBSSLVirtualServerProfile -Name $oldvserver.lbvserver.name -SSLProfile abc_default_ssl_profile_frontend -ErrorAction CONTINUE -Confirm
		    	}#TRY SSL Set Profile
			    CATCH {
                  "$(Get-TimeStamp) FAILED: Set SSL Profile for " + $oldvserver.lbvserver.name + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
			    }#CATCH SSL Set Profile
                $newsslvippayld = @{ }
                $newsslvippayld = @{
                                   vservername = $oldvserver.lbvserver.name
                                   certkeyname = $oldsslbind.sslvserver_sslcertkey_binding.certkeyname
                }#newsslvippayld
	    		TRY {
      			    Invoke-Nitro -Method PUT -Type sslvserver_sslcertkey_binding -Payload $newsslvippayld -OnErrorAction CONTINUE -Confirm -Force
#				    Add-NSLBSSLVirtualServerCertificateBinding -Certificate $oldsslbind.sslvserver_sslcertkey_binding.certkeyname -VirtualServerName $oldvserver.lbvserver.name -ErrorAction CONTINUE -Confirm
			    }#TRY SSL Bind Certificate
	    		CATCH {
                  "$(Get-TimeStamp) FAILED: Set SSL Cert Binding for " + $oldsslbind.vservername + " " + $oldsslbind.sslvserver_sslcertkey_binding.certkeyname + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
			    }#CATCH SSL Set Profile
		    }#IF VIP is SSL
#Bind Service to VIP
            IF ($oldvsbindings.lbvserver_binding.lbvserver_service_binding -ne $null) {
                "$(Get-TimeStamp) BIND: Service Record " + $oldvserver.lbvserver.name + " " + $newsvcname | Out-File -filepath $outputfile -Append -Encoding ascii
                $newsvcvippayld = @{ }
                $newsvcvippayld = @{
                                   name = $oldvserver.lbvserver.name
                                   servicename = $newsvcname
                }#newsvcvippayld
	    		TRY {
      			    Invoke-Nitro -Method PUT -Type lbvserver_service_binding -Payload $newsvcvippayld -OnErrorAction CONTINUE -Confirm -Force
#		    		Add-NSLBVirtualServerBinding -VirtualServerName $oldvsbindings.vservername -ServiceName $newsvcname -ErrorAction CONTINUE -Confirm
			    }#TRY Service Binding
    			CATCH {
                  "$(Get-TimeStamp) FAILED: Service Binding for " + $oldvserver.lbvserver.name + " " + $newsvcname + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
		    	}#CATCH Service Binding
            }#If Bind Service

#Create New ServiceGroup
            IF ($oldvsbindings.lbvserver_binding.lbvserver_servicegroup_binding -ne $null) {
                "$(Get-TimeStamp) BIND: ServiceGroup Record " + $oldvsbindings.vservername + " " + $newsvgname | Out-File -filepath $outputfile -Append -Encoding ascii
                $newsvgpayld = @{ }
                $newsvgpayld = @{
                                servicegroupname = $oldsvg.servicegroupname
                                servicetype = $oldsvg.servicetype
                                td = $oldsvg.td
                                maxclient = $oldsvg.maxclient
                                maxreq = $oldsvg.maxreq
                                cacheable = $oldsvg.cacheable
                                cip = $oldsvg.cip
                                cipheader = $oldsvg.cipheader
                                usip = $oldsvg.usip
                                pathmonitor = $oldsvg.pathmonitor
                                pathmonitorindv = $oldsvg.pathmonitorindv
                                useproxyport = $oldsvg.useproxyport
                                healthmonitor = $oldsvg.healthmonitor
                                sc = $oldsvg.sc
                                sp = $oldsvg.sp
                                rtspsessionidremap = $oldsvg.rtspsessionidremap
                                clttimeout = $oldsvg.clttimeout
                                svrtimeout = $oldsvg.svrtimeout
                                cka = $oldsvg.cka
                                tcpb = $oldsvg.tcpb
                                cmp = $oldsvg.cmp
                                maxbandwidth = $oldsvg.maxbandwidth
                                monthreshold = $oldsvg.monthreshold
                                state = $oldsvg.state
                                downstateflush = $oldsvg.downstateflush
                                tcpprofilename = $oldsvg.tcpprofilename
                                httpprofilename = $oldsvg.httpprofilename
                                comment = $oldsvg.comment
                                appflowlog = $oldsvg.appflowlog
                                netprofile = $oldsvg.netprofile
                                autoscale = $oldsvg.autoscale
                                memberport = $oldsvg.memberport
                                monconnectionclose = $oldsvg.monconnectionclose
                                } #newsvgpayld
	    		TRY {
                        Invoke-Nitro -Method POST -Type servicegroup -Payload $newsvgpayld -OnErrorAction CONTINUE -Confirm -Force
#		    		New-NSLBServiceGroup -name $newsvgname -ServiceType $newsvgtype -comment $newsvgcomment -ClientIP $newsvgcip -ClientIPHeader $newsvgciphead -Confirm -ErrorAction Continue
			    }#TRY New Service Group
                CATCH {
                  "$(Get-TimeStamp) FAILED: ServiceGroup Create for " + $newsvgname + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
                }#CATCH New Service Group
                    
#Create New Servers
                ForEach ($svgmemcnt in $oldsvgbnd) {
                    #Create new LB Server
                    "$(Get-TimeStamp) CREATE: New SERVER Record " + $svgmemcnt.servername | Out-File -filepath $outputfile -Append -Encoding ascii
                    $newsrvpayld = @{ }
                    $newsrvpayld = @{
                                        name = $svgmemcnt.servername
                                        ipaddress = $svgmemcnt.ip
                                        } #newsrvpayld
				    TRY {
                        Invoke-Nitro -Method POST -Type server -Payload $newsrvpayld -OnErrorAction CONTINUE -Confirm -Force
#					    New-NSLBServer -confirm -name $svgmemcnt.servername -IPAddress $svgmemcnt.ip -ErrorAction Continue
    				}#TRY New LB Server
	    			CATCH {
                          "$(Get-TimeStamp) FAILED: Server Create for " + $svgmemcnt.servername + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
			    	}#CATCH New Server
#Bind ServiceGroup Member
                    "$(Get-TimeStamp) BIND: New SERVER Record " + $svgmemcnt.servicegroupname + " " + $svgmemcnt.servername | Out-File -filepath $outputfile -Append -Encoding ascii
                    $newsvgmempayld = @{ }
                    $newsvgmempayld = @{
                                        servicegroupname = $svgmemcnt.servicegroupname
                                        servername = $svgmemcnt.servername
                                        port = $svgmemcnt.port
                                        weight = $svgmemcnt.weight
                    }#newsvgmempayld
    				TRY {
                        Invoke-Nitro -Method PUT -Type servicegroup_servicegroupmember_binding -Payload $newsvgmempayld -OnErrorAction CONTINUE -Confirm -Force
#	    				New-NSLBServiceGroupMember -name $svgmemcnt.servicegroupname -ServerName $svgmemcnt.servername -Port $svgmemcnt.port -Weight $svgmemcnt.weight -Confirm -ErrorAction Continue
		    		}#TRY New ServiceGroup Member
			    	CATCH {
                      "$(Get-TimeStamp) FAILED: Service Group Member Binding for " + $svgmemcnt.servicegroupname + " " + $svgmemcnt.servername + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
    				}#CATCH New Server
                }#ForEach Member Binding

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
                    "$(Get-TimeStamp) CREATE: New Monitor " + $oldmon.monitorname | Out-File -filepath $outputfile -Append -Encoding ascii
                   TRY {
                        Invoke-Nitro -Method POST -Type lbmonitor -Payload $newmonpayld -OnErrorAction CONTINUE -Confirm -Force
		    	    }#TRY New Monitor
			        CATCH {
                          "$(Get-TimeStamp) FAILED: Create Monitor for " + $oldmon.monitorname + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
			        }#CATCH New Monitor

#Bind ServiceGroup Monitor
                    "$(Get-TimeStamp) BIND: Monitor to ServiceGroup " + $newsvgname + " " + $oldmon.monitor_name | Out-File -filepath $outputfile -Append -Encoding ascii
                    $newsvgmonpayld = @{ }
                    $newsvgmonpayld = @{
                                        servicegroupname = $newsvgname
                                        monitor_name = $oldmon.monitor_name
                                        weight = "1"
                    }#newmonsvgpayld
        			TRY {
	    			    Invoke-Nitro -Method PUT -Type servicegroup_lbmonitor_binding -Payload $newsvgmonpayld -OnErrorAction CONTINUE -Confirm -Force
#	        			New-NSLBServiceGroupMonitor -Name $oldsvgmon.servicegroupname -MonitorName $oldsvgmon.monitor_name -Confirm -ErrorAction Continue
		        	}#TRY Bind Monitor
			        CATCH {
                          "$(Get-TimeStamp) FAILED: Monitor Binding for " + $newsvgname + " " + $oldmon.monitor_name + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
			        }#CATCH Monitor Binding
                }#IF Monitor NULL

#Bind ServiceGroup SSLProfileBackend
                IF ($newsvgtype -eq "SSL") {
                    $newsvgsslpayld = @{ }
                    $newsvgsslpayld = @{
                                        servicegroupname = $newsvgname
                                        sslprofile = "abc_default_ssl_profile_backend"
                                        } #newsvgsslpayld
                    "$(Get-TimeStamp) BIND: ServiceGroup SSL Profile " + $newsvgname | Out-File -filepath $outputfile -Append -Encoding ascii
    			    TRY {
	    			    Invoke-Nitro -Method PUT -Type sslservicegroup -Payload $newsvgsslpayld -OnErrorAction CONTINUE -Confirm -Force
		    	    }#TRY SSL Profile Backend
			        CATCH {
                          "$(Get-TimeStamp) FAILED: ServiceGroup SSL Profile Binding for " + $newsvgname + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
           		    }#CATCH SSL Profile Backend
                }#IF ServiceGroup SSL
#Bind ServiceGroup to VIP
                "$(Get-TimeStamp) BIND: ServiceGroup to VIP " + $newsvgname + " " + $oldvserver.lbvserver.name | Out-File -filepath $outputfile -Append -Encoding ascii
                $newsvgvippayld = @{ }
                $newsvgvippayld = @{
                                   name = $oldvserver.lbvserver.name
                                   servicegroupname = $newsvgname
                }#newsvgvippayld
	    		TRY {
      			    Invoke-Nitro -Method PUT -Type lbvserver_servicegroup_binding -Payload $newsvgvippayld -OnErrorAction CONTINUE -Confirm -Force
#		    		Add-NSLBVirtualServerBinding -VirtualServerName $oldvserver.lbvserver.name -ServiceGroupName $newsvgname -ErrorAction CONTINUE -Confirm
    			}#TRY ServiceGroup Binding
	    		CATCH {
                      "$(Get-TimeStamp) FAILED: ServiceGroup VIP Binding for " + $newsvgname + " " + $oldvserver.lbvserver.name + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
			    }#CATCH ServiceGroup Bind

            }#IF Add New ServiceGroup

#Create Responder Action
            IF ($oldvsbindings.lbvserver_binding.lbvserver_responderpolicy_binding -ne $null) {
                "$(Get-TimeStamp) CREATE: Responder Action " + $oldrspact.name | Out-File -filepath $outputfile -Append -Encoding ascii
                IF ($oldrspact.name -ne "HTTP_to_HTTPS_Redirect") {
                    $newrspactpayld = @{ }
                    $newrspactpayld = @{
                                    name = $oldrspact.name
                                    type = $oldrspact.type
                                    target = $oldrspact.target
                                    htmlpage = $oldrspact.htmlpage
                                    bypasssafetycheck = $oldrspact.bypasssafetycheck
                                    refinesearch = $oldrspact.refinesearch
                                    comment = $oldrspact.comment
                                    responsestatuscode = $oldrspact.responsestatuscode 
                                    reasonphrase = $oldrspact.reasonphrase
                                    }#newrspactpayld
		    	    TRY {
          			    Invoke-Nitro -Method POST -Type responderaction  -Payload $newrspactpayld -OnErrorAction CONTINUE -Confirm -Force
#			    	    New-NSResponderAction -Name $oldrspact.name -Type $oldrspact.type -Target $oldrspact.target -ResponseStatusCode $oldrspact.responsestatuscode -Confirm -ErrorAction Continue
			        }#TRY Responder Action
    			    CATCH {
                          "$(Get-TimeStamp) FAILED: New Responder Action for " + $oldrspact.name + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
    	    		}#CATCH Responder Action

#Create Responder Policy
                   "$(Get-TimeStamp) CREATE: Responder Policy " + $oldrsppol.name | Out-File -filepath $outputfile -Append -Encoding ascii
                    $newrsppolpayld = @{ }
                    $newrsppolpayld = @{
                                    name = $oldrsppol.name
                                    rule = $oldrsppol.rule
                                    action = $oldrsppol.action
                                    undefaction = $oldrsppol.undefaction
                                    comment = $oldrewact.comment
                                    logaction = $oldrewpol.logaction
                                    appflowaction = $oldrsppol.appflowaction
                                    } #newrewpsppayld
	    	    	TRY {
      			    Invoke-Nitro -Method POST -Type responderpolicy  -Payload $newrsppolpayld -OnErrorAction CONTINUE -Confirm -Force
#    		    		New-NSResponderPolicy -Name $oldrsppol.name -Rule $oldrsppol.rule -Action $oldrsppol.action -Confirm -ErrorAction Continue
	    		    }#TRY Responder Policy
		    	    CATCH {
                          "$(Get-TimeStamp) FAILED: New Responder Policy for " + $oldrsppol.name + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
    			    }#CATCH Responder Policy
                }#IF Responder Policy
                    
#Bind Responder Policy
                IF ($oldrspact.name -eq "HTTP_to_HTTPS_Redirect") {
                    $oldrsppol.name = "default_http_to_https_responder_policy"
                }
                "$(Get-TimeStamp) BIND: Responder Policy " + $oldrsppol.name + " " + $oldvserver.lbvserver.name | Out-File -filepath $outputfile -Append -Encoding ascii
    			TRY {
	    			Add-NSLBVirtualServerResponderPolicyBinding -VirtualServerName $oldvserver.lbvserver.name -PolicyName $oldrsppol.name -Bindpoint REQUEST -Priority 100
		    	}#TRY Responder Binding
			    CATCH {
                      "$(Get-TimeStamp) FAILED: Responder Binding for " + $oldrsppol.name + " " + $oldvserver.lbvserver.name + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
	    		}#CATCH Responder Bind
            }#Not HTTP Redirect
#Create Rewrite Action
            IF ($oldvsbindings.lbvserver_binding.lbvserver_rewritepolicy_binding -ne $null) {
                    $newrewactpayld = @{ }
                    $newrewactpayld = @{
                                    name = $oldrewact.name
                                    type = $oldrewact.type
                                    target = $oldrewact.target
                                    stringbuilderexpr = $oldrewact.stringbuilderexpr
                                    pattern = $oldrewact.pattern
                                    search = $oldrewact.search
                                    bypasssafetycheck = $oldrewact.bypasssafetycheck
                                    refinesearch = $oldrewact.refinesearch
                                    comment = $oldrewact.comment
                                    } #newrewactpayld

                "$(Get-TimeStamp) CREATE: Rewrite Action " + $oldrewact.name | Out-File -filepath $outputfile -Append -Encoding ascii
	    		TRY {
      			    Invoke-Nitro -Method POST -Type rewriteaction -Payload $newrewactpayld -OnErrorAction CONTINUE -Confirm -Force
<#		    		New-NSRewriteAction -Name $oldrewact.name `
			    						-Type $oldrewact.type `
				    					-Target $oldrewact.target `
					    				-Expression $oldrewact.stringbuilderexpr `
						    			-Confirm -ErrorAction Continue
#>
			    }#TRY Rewrite Action
			    CATCH {
                      "$(Get-TimeStamp) FAILED: New Rewrite Action for " + $oldrewact.name + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
	    		}#CATCH Rewrite Action
#Create Rewrite Policy
                "$(Get-TimeStamp) CREATE: Rewrite Policy " + $oldrewpol.name | Out-File -filepath $outputfile -Append -Encoding ascii
                    $newrewpolpayld = @{ }
                    $newrewpolpayld = @{
                                    name = $oldrewpol.name
                                    rule = $oldrewpol.rule
                                    action = $oldrewpol.action
                                    comment = $oldrewpol.comment
                                    } #newrewpolpayld
		    	TRY {
      			    Invoke-Nitro -Method POST -Type rewritepolicy -Payload $newrewpolpayld -OnErrorAction CONTINUE -Confirm -Force
<#			    	New-NSRewritePolicy -Name $oldrewpol.name `
				    					-Rule $oldrewpol.rule `
    									-ActionName $oldrewpol.action `
	    								-LogActionName $oldrewpol.logaction `
		    							-Confirm -ErrorAction Continue
#>
			    }#TRY Rewrite Policy
    			CATCH {
                      "$(Get-TimeStamp) FAILED: New Rewrite Policy for " + $oldrewpol.name + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
	    		}#CATCH Rewrite Policy

#Bind Rewrite Policy
                "$(Get-TimeStamp) BIND: Rewrite Policy " + $oldrewpol.name + " " + $oldvserver.lbvserver.name | Out-File -filepath $outputfile -Append -Encoding ascii
    			TRY {
	    			Add-NSLBVirtualServerRewritePolicyBinding -VirtualServerName $oldvserver.lbvserver.name -PolicyName $oldrewpol.name -Bindpoint REQUEST -Priority 100
		    	}#TRY Rewrite Binding
			    CATCH {
                      "$(Get-TimeStamp) FAILED: Rewrite Binding for " + $oldrewpol.name + " " + $oldvserver.lbvserver.name + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
	    		}#CATCH Rewrite Bind
            }#IF Rewrite Policy
        }# IF VIP not Null
        ELSE {
             "$(Get-TimeStamp) FAILED: Old VIP does not exist: " + $oldvipname + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
        }#ELSE VIP IS NULL
    }# ForEach VIPExtension
    
  } #ForEach DC

} #ForEach FQDN

"$(Get-TimeStamp) *** END *** Script create_lbvip_old.ps1 for Environment: " + $env | Out-File -filepath $outputfile -Append -Encoding ascii
