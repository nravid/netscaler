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

$grnpref = "10.30."

switch ($env) {
"prd" {
      $trmpref = "10.64." ; break
      }# PRD Switch
default {
      $trmpref = "10.31." ; break
      }#default switch
}#switch env


"$(Get-TimeStamp) *** START *** Script create_gslb_old.ps1 for Environment: " + $env | Out-File -filepath $outputfile -Append -Encoding ascii
ForEach ($dc in $dclistold) {
        $OLDNsip = $null
        $dcinit = $null
        $dcinit = ($dc.Substring(0,1))
        $OLDNsip = 'n' + $dcinit + '0pnsint.foo.bar'
        $NEWNsip = $null
        $NEWNsip = 'n' + $dcinit + '0' + $envinit + 'nsinty.foo.bar'

        ForEach ($fqdn in $envlist) {
                $oldgslbvsrv = $null
                $oldgslbvsrv2 = $null
                $oldgslbvsvcbnd = $null
                $oldgslbvsvcbnd2 = $null
                $gslbdomname = $null
                $gslbdomname = $fqdn.name -replace ".foo.bar", ".int.foo.bar"

#Connect to Old NS
                Connect-NetScaler -Hostname $OLDNsip -Credential $Credential
#Identify GSLB vServer for the DomainName
                "$(Get-TimeStamp) GET GSLB Domain Binding " + $gslbdomname | Out-File -filepath $outputfile -Append -Encoding ascii
                TRY {
                    $gslbvip = Invoke-Nitro -Method GET -Type gslbdomain_gslbvserver_binding -Resource $gslbdomname -Confirm -Force -ErrorAction Continue
                    $oldgslbvdompayld = @{ }
                    $oldgslbvdompayld = $gslbvip.gslbdomain_gslbvserver_binding
                    "$(Get-TimeStamp) GET GSLB vServer " + $oldgslbvdompayld.vservername | Out-File -filepath $outputfile -Append -Encoding ascii
#Get the GSLB vServer configuration
                TRY {
                    $oldgslbvsrv = Invoke-Nitro -Method GET -Type gslbvserver -Resource $oldgslbvdompayld.vservername -Confirm -Force -ErrorAction Continue
                    $oldgslbvsrvpayld = @{ }
                    $oldgslbvsrvpayld = $oldgslbvsrv.gslbvserver
                    "$(Get-TimeStamp) GET GSLB vServer service bindings " + $oldgslbvsrvpayld.name | Out-File -filepath $outputfile -Append -Encoding ascii
#Get the GSLB service(s) bound to the vServer
                    TRY {
                        $oldgslbvsvcbnd = Invoke-Nitro -Method GET -Type gslbvserver_gslbservice_binding -Resource $oldgslbvsrvpayld.name -Confirm -Force -ErrorAction Continue
                            $oldgslbvsvcary = @($oldgslbvsvcbnd.gslbvserver_gslbservice_binding)
#Get the GSLB service configurations and create on new
                    ForEach ($oldsvc in $oldgslbvsvcary) {
                            Connect-NetScaler -Hostname $OLDNsip -Credential $Credential
                           "$(Get-TimeStamp) GET Old GSLB Service " + $oldsvc.servicename + " from " + $OLDNsip | Out-File -filepath $outputfile -Append -Encoding ascii
                            TRY {
                                $oldgslbsvc = Invoke-Nitro -Method GET -Type gslbservice -Resource $oldsvc.servicename -OnErrorAction CONTINUE -Confirm -Force
                                $oldgslbsvcpayld = @{ }
                                $oldgslbsvcpayld = $oldgslbsvc.gslbservice
                                }#TRY Get Old GSLB Service
                            CATCH {
                                  "$(Get-TimeStamp) GET Old GSLB Service " + $oldsvc.servicename + " from " + $OLDNsip + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
                                  }#Catch Get Old GSLB Service
#Disconnect from old NS
                            "$(Get-TimeStamp) Disconnect from " + $OldNsip | Out-File -filepath $outputfile -Append -Encoding ascii
                            Disconnect-NetScaler

#Connect to New NS
                            "$(Get-TimeStamp) Connect to " + $NEWNsip | Out-File -filepath $outputfile -Append -Encoding ascii
                            Connect-NetScaler -Hostname $NEWNsip -Credential $Credential -HTTPS
#Create New GSLB server
                            $gslbsrvdc = $null
                            $gslbsrvdc  = $oldsvc.servicename.substring($oldsvc.servicename.length - 3, 3)
                            $gslbsrvname = $fqdn.name + "_gslb_srv_" + $gslbsrvdc
                            $gslbsite = $null
                            $gslbsite = "gslb_site_" + $gslbsrvdc
                            IF ($gslbsrvdc -eq "grn") {
                                                $gslbsrvaddr = $grnpref + $fqdn.grnip
												}
                            ELSE {
                                                $gslbsrvaddr = $trmpref + $fqdn.trmip
                                 }#ELSE IP Address
                            "$(Get-TimeStamp) Create GSLB Server " + $gslbsrvname | Out-File -filepath $outputfile -Append -Encoding ascii
                            $gslbsrvpayld = @{ }
                            $gslbsrvpayld = @{
                                            name = $gslbsrvname
                                            ipaddress = $gslbsrvaddr
                                            }#gslbsrvpayld
                            TRY {
                                Invoke-Nitro -Method POST -Type server -Payload $gslbsrvpayld -OnErrorAction CONTINUE -Confirm -Force
                                } #TRY Add Server
                            CATCH {
                                  "$(Get-TimeStamp) FAILED Creating GSLB Server " + $gslbsrvname + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
                                  } #Catch Server

#Create New GSLB Service
                            "$(Get-TimeStamp) Create GSLB Service " + $oldgslbsvcpayld.servicename | Out-File -filepath $outputfile -Append -Encoding ascii
                            $newgslbsvcpayld = @{ }
                            $newgslbsvcpayld = @{
                                                servicename = $oldgslbsvcpayld.servicename
                                                servername = $gslbsrvname
                                                servicetype = $oldgslbsvcpayld.servicetype
                                                port = $oldgslbsvcpayld.port
                                                maxclient = $oldgslbsvcpayld.maxclient
                                                healthmonitor = $oldgslbsvcpayld.healthmonitor
                                                sitename = $gslbsite
                                                state = $oldgslbsvcpayld.state
                                                sitepersistence = $oldgslbsvcpayld.sitepersistence
                                                cookietimeout = $oldgslbsvcpayld.cookietimeout
                                                siteprefix = $oldgslbsvcpayld.siteprefix
                                                clttimeout = $oldgslbsvcpayld.clttimeout
                                                svrtimeout = $oldgslbsvcpayld.svrtimeout
                                                maxbandwidth = $oldgslbsvcpayld.maxbandwidth
                                                downstateflush = $oldgslbsvcpayld.downstateflush
                                                monthreshold = $oldgslbsvcpayld.monthreshold
                                                comment = $oldgslbsvcpayld.comment
                                                appflowlog = $oldgslbsvcpayld.appflowlog
                                                }#newgslbsvcpayld
                            TRY {
                                Invoke-Nitro -Method POST -Type gslbservice -Payload $newgslbsvcpayld -OnErrorAction CONTINUE -Confirm -Force
                                } #TRY Add GSLB Service
                            CATCH {
                                  "$(Get-TimeStamp) FAILED Creating GSLB Service " + $oldgslbsvcpayld.servicename + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
                                  } #Catch GSLB Service

#Create New GSLB vServer - State = DISABLED
                            $newgslbvsrvpayld = @{ }
                            $newgslbvsrvpayld = @{
                                                 name = $oldgslbvsrvpayld.name
                                                 servicetype = $oldgslbvsrvpayld.servicetype
                                                 iptype = $oldgslbvsrvpayld.iptype
                                                 dnsrecordtype = $oldgslbvsrvpayld.dnsrecordtype
                                                 lbmethod = $oldgslbvsrvpayld.lbmethod
                                                 backupsessiontimeout = $oldgslbvsrvpayld.backupsessiontimeout
                                                 backuplbmethod = $oldgslbvsrvpayld.backuplbmethod
                                                 netmask = $oldgslbvsrvpayld.netmask
                                                 v6netmasklen = $oldgslbvsrvpayld.v6netmasklen
                                                 tolerance = $oldgslbvsrvpayld.tolerance
                                                 persistencetype = $oldgslbvsrvpayld.persistencetype
                                                 persistenceid = $oldgslbvsrvpayld.persistenceid
                                                 persistmask = $oldgslbvsrvpayld.persistmask
                                                 v6persistmasklen = $oldgslbvsrvpayld.v6persistmasklen
                                                 timeout = $oldgslbvsrvpayld.timeout
                                                 edr = $oldgslbvsrvpayld.edr
                                                 ecs = $oldgslbvsrvpayld.ecs
                                                 ecsaddrvalidation = $oldgslbvsrvpayld.ecsaddrvalidation
                                                 mir = $oldgslbvsrvpayld.mir
                                                 disableprimaryondown = $oldgslbvsrvpayld.disableprimaryondown
                                                 dynamicweight = $oldgslbvsrvpayld.dynamicweight
                                                 state = "DISABLED"
                                                 considereffectivestate = $oldgslbvsrvpayld.considereffectivestate
                                                 comment = $oldgslbvsrvpayld.comment
                                                 somethod = $oldgslbvsrvpayld.somethod
                                                 sopersistence = $oldgslbvsrvpayld.sopersistence
                                                 sopersistencetimeout = $oldgslbvsrvpayld.sopersistencetimeout
                                                 sothreshold = $oldgslbvsrvpayld.sothreshold
                                                 sobackupaction = $oldgslbvsrvpayld.sobackupaction
                                                 appflowlog = $oldgslbvsrvpayld.appflowlog
                                                 }#newgslbvsrvpayld
                            "$(Get-TimeStamp) Create GSLB vServer  " + $oldgslbvsrvpayld.name | Out-File -filepath $outputfile -Append -Encoding ascii
                            TRY {
                                Invoke-Nitro -Method POST -Type gslbvserver -Payload $newgslbvsrvpayld -OnErrorAction CONTINUE -Confirm -Force
                            } #TRY Add GSLB vServer
                            CATCH {
                                  "$(Get-TimeStamp) FAILED Creating GSLB vServer  " + $oldgslbvsrvpayld.name + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
                                  } #Catch GSLB vServer

#Bind DomainName to GSLB vServer
                            $gslbdompayld = @{ }
                            $gslbdompayld = @{
                                             name = $oldgslbvsrvpayld.name
                                             domainname = $gslbdomname
                                             }#gslbdompayld
                            "$(Get-TimeStamp) Bind GSLB DomainName  " + $oldgslbvdompayld.name | Out-File -filepath $outputfile -Append -Encoding ascii
                            TRY {
                                Invoke-Nitro -Method PUT -Type gslbvserver_domain_binding -Payload $gslbdompayld -OnErrorAction CONTINUE -Confirm -Force
                                } #TRY Add GSLB DomainName
                            CATCH {
                                  "$(Get-TimeStamp) FAILED Binding GSLB DomainName  " + $oldgslbvdompayld.name + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
                                  } #CATCH GSLB DomainName

#Bind GSLB Service to GSLB vServer
                            $newgslbsvcbndpayld = @{ }
                            $newgslbsvcbndpayld = @{
                                             name = $oldgslbvsrvpayld.name
                                             servicename = $oldgslbsvcpayld.servicename
                                             }#newgslbsvcbndpayld
                            "$(Get-TimeStamp) Bind GSLB Service " + $oldgslbsvcpayld.servicename | Out-File -filepath $outputfile -Append -Encoding ascii
                            TRY {
                                Invoke-Nitro -Method PUT -Type gslbvserver_gslbservice_binding -Payload $newgslbsvcbndpayld -OnErrorAction CONTINUE -Confirm -Force
                                } #TRY GSLB Service Binding
                            CATCH {
                                  "$(Get-TimeStamp) FAILED Binding GSLB Service " + $oldgslbsvcpayld.servicename + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
                                  } #CATCH GSLB Service Binding

#Disconnect from New NS                                  
                            "$(Get-TimeStamp) Disconnect from " + $NEWNsip | Out-File -filepath $outputfile -Append -Encoding ascii
                            Disconnect-NetScaler

                        }#ForEach oldsvc
                    }#TRY GSLB Service Binding
					CATCH {
						  "$(Get-TimeStamp) FAILED Getting GSLB vServer service bindings  " + $oldgslbvsrvpayld.name + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
						  }#CATCH gslb service binding

#If backup vServer Configured
            IF ($oldgslbvsrv.gslbvserver.backupvserver -ne $null) {
#Connect to Old NS
                Connect-NetScaler -Hostname $OLDNsip -Credential $Credential
                "$(Get-TimeStamp) GET GSLB backup vServer " + $oldgslbvsrv.gslbvserver.backupvserver | Out-File -filepath $outputfile -Append -Encoding ascii
                TRY {
                    $oldgslbvsrv2 = Invoke-Nitro -Method GET -Type gslbvserver -Resource $oldgslbvsrv.gslbvserver.backupvserver -Confirm -Force -ErrorAction Continue
                    "$(Get-TimeStamp) GET GSLB backup vServer service bindings " + $oldgslbvsrv2.gslbvserver.name | Out-File -filepath $outputfile -Append -Encoding ascii
                    TRY {
                        $oldgslbvsvcbnd2 = Invoke-Nitro -Method GET -Type gslbvserver_gslbservice_binding -Resource $oldgslbvsrv2.gslbvserver.name -Confirm -Force -ErrorAction Continue
						$oldgslbvsvcbndary2 = @($oldgslbvsvcbnd2.gslbvserver_gslbservice_binding)
#Get the GSLB service configurations and create on new
                    ForEach ($oldsvc2 in $oldgslbvsvcbndary2) {
                           "$(Get-TimeStamp) GET Old GSLB Service " + $oldsvc2.servicename + " from " + $OLDNsip | Out-File -filepath $outputfile -Append -Encoding ascii
                            TRY {
                                $oldgslbsvc2 = Invoke-Nitro -Method GET -Type gslbservice -Resource $oldsvc2.servicename -OnErrorAction CONTINUE -Confirm -Force
                                $oldgslbsvcpayld2 = @{ }
                                $oldgslbsvcpayld2 = $oldgslbsvc2.gslbservice
                                }#TRY Get Old GSLB Service
                            CATCH {
                                  "$(Get-TimeStamp) GET Old GSLB Service " + $oldsvc2.servicename + " from " + $OLDNsip + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
                                  }#Catch Get Old GSLB Service
#Disconnect from old NS
                            "$(Get-TimeStamp) Disconnect from " + $OldNsip | Out-File -filepath $outputfile -Append -Encoding ascii
                            Disconnect-NetScaler

#Connect to New NS
                            "$(Get-TimeStamp) Connect to " + $NEWNsip | Out-File -filepath $outputfile -Append -Encoding ascii
                            Connect-NetScaler -Hostname $NEWNsip -Credential $Credential -HTTPS
#Create New GSLB server
                            $gslbsrvdc2 = $null
                            $gslbsrvdc2  = $oldsvc2.servicename.substring($oldsvc2.servicename.length - 3, 3)
                            $gslbsite2 = $null
                            $gslbsite2 = "gslb_site_" + $gslbsrvdc
                            $gslbsrvname2 = $fqdn.name + "_gslb_srv_sec_" + $gslbsrvdc2
                            IF ($gslbsrvdc2 -eq "grn") {
                                                $gslbsrvaddr2 = $grnpref + $fqdn.grnip
												}#IF DC = GRN
                            ELSE {
                                                $gslbsrvaddr2 = $trmpref + $fqdn.trmip
                                 }#ELSE IP Address
                            "$(Get-TimeStamp) Create GSLB Server " + $gslbsrvname2 | Out-File -filepath $outputfile -Append -Encoding ascii
                            $gslbsrvpayld2 = @{ }
                            $gslbsrvpayld2 = @{
                                            name = $gslbsrvname2
                                            ipaddress = $gslbsrvaddr2
                                            }#gslbsrvpayld2
                            TRY {
                                Invoke-Nitro -Method POST -Type server -Payload $gslbsrvpayld2 -OnErrorAction CONTINUE -Confirm -Force
                                } #TRY Add Server
                            CATCH {
                                  "$(Get-TimeStamp) FAILED Creating GSLB Server " + $gslbsrvname2 + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
                                  } #Catch Server

#Create New GSLB Service
                            "$(Get-TimeStamp) Create GSLB Service " + $oldgslbsvcpayld2.servicename | Out-File -filepath $outputfile -Append -Encoding ascii
                            $newgslbsvcpayld2 = @{ }
                            $newgslbsvcpayld2 = @{
                                                servicename = $oldgslbsvcpayld2.servicename
                                                servername = $gslbsrvname2
                                                servicetype = $oldgslbsvcpayld2.servicetype
                                                port = $oldgslbsvcpayld2.port
                                                maxclient = $oldgslbsvcpayld2.maxclient
                                                healthmonitor = $oldgslbsvcpayld2.healthmonitor
                                                sitename = $gslbsite2
                                                state = $oldgslbsvcpayld2.state
                                                sitepersistence = $oldgslbsvcpayld2.sitepersistence
                                                cookietimeout = $oldgslbsvcpayld2.cookietimeout
                                                siteprefix = $oldgslbsvcpayld2.siteprefix
                                                clttimeout = $oldgslbsvcpayld2.clttimeout
                                                svrtimeout = $oldgslbsvcpayld2.svrtimeout
                                                maxbandwidth = $oldgslbsvcpayld2.maxbandwidth
                                                downstateflush = $oldgslbsvcpayld2.downstateflush
                                                monthreshold = $oldgslbsvcpayld2.monthreshold
                                                comment = $oldgslbsvcpayld2.comment
                                                appflowlog = $oldgslbsvcpayld2.appflowlog
                                                }#newgslbsvcpayld2
                            TRY {
                                Invoke-Nitro -Method POST -Type gslbservice -Payload $newgslbsvcpayld2 -OnErrorAction CONTINUE -Confirm -Force
                                } #TRY Add GSLB Service
                            CATCH {
                                  "$(Get-TimeStamp) FAILED Creating GSLB Service " + $oldgslbsvcpayld2.servicename + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
                                  } #Catch GSLB Service

#Create New GSLB vServer - State = DISABLED
                            $newgslbvsrvpayld2 = @{ }
                            $newgslbvsrvpayld2 = @{
                                                 name = $oldgslbvsrv2.gslbvserver.name
                                                 servicetype = $oldgslbvsrv2.gslbvserver.servicetype
                                                 iptype = $oldgslbvsrv2.gslbvserver.iptype
                                                 dnsrecordtype = $oldgslbvsrv2.gslbvserver.dnsrecordtype
                                                 lbmethod = $oldgslbvsrv2.gslbvserver.lbmethod
                                                 backupsessiontimeout = $oldgslbvsrv2.gslbvserver.backupsessiontimeout
                                                 backuplbmethod = $oldgslbvsrv2.gslbvserver.backuplbmethod
                                                 netmask = $oldgslbvsrv2.gslbvserver.netmask
                                                 v6netmasklen = $oldgslbvsrv2.gslbvserver.v6netmasklen
                                                 tolerance = $oldgslbvsrv2.gslbvserver.tolerance
                                                 persistencetype = $oldgslbvsrv2.gslbvserver.persistencetype
                                                 persistenceid = $oldgslbvsrv2.gslbvserver.persistenceid
                                                 persistmask = $oldgslbvsrv2.gslbvserver.persistmask
                                                 v6persistmasklen = $oldgslbvsrv2.gslbvserver.v6persistmasklen
                                                 timeout = $oldgslbvsrv2.gslbvserver.timeout
                                                 edr = $oldgslbvsrv2.gslbvserver.edr
                                                 ecs = $oldgslbvsrv2.gslbvserver.ecs
                                                 ecsaddrvalidation = $oldgslbvsrv2.gslbvserver.ecsaddrvalidation
                                                 mir = $oldgslbvsrv2.gslbvserver.mir
                                                 disableprimaryondown = $oldgslbvsrv2.gslbvserver.disableprimaryondown
                                                 dynamicweight = $oldgslbvsrv2.gslbvserver.dynamicweight
                                                 state = "DISABLED"
                                                 considereffectivestate = $oldgslbvsrv2.gslbvserver.considereffectivestate
                                                 comment = $oldgslbvsrv2.gslbvserver.comment
                                                 somethod = $oldgslbvsrv2.gslbvserver.somethod
                                                 sopersistence = $oldgslbvsrv2.gslbvserver.sopersistence
                                                 sopersistencetimeout = $oldgslbvsrv2.gslbvserver.sopersistencetimeout
                                                 sothreshold = $oldgslbvsrv2.gslbvserver.sothreshold
                                                 sobackupaction = $oldgslbvsrv2.gslbvserver.sobackupaction
                                                 appflowlog = $oldgslbvsrv2.gslbvserver.appflowlog
                                                 }#newgslbvsrvpayld2
                            "$(Get-TimeStamp) Create GSLB vServer  " + $oldgslbvsrv2.gslbvserver.name | Out-File -filepath $outputfile -Append -Encoding ascii
                            TRY {
                                Invoke-Nitro -Method POST -Type gslbvserver -Payload $newgslbvsrvpayld2 -OnErrorAction CONTINUE -Confirm -Force
                            } #TRY Add GSLB vServer
                            CATCH {
                                  "$(Get-TimeStamp) FAILED Creating GSLB vServer  " + $oldgslbvsrv2.gslbvserver.name + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
                                  } #Catch GSLB vServer

#Bind GSLB Service to GSLB vServer
                            $newgslbsvcbndpayld2 = @{ }
                            $newgslbsvcbndpayld2 = @{
                                             name = $oldgslbvsrv2.gslbvserver.name
                                             servicename = $oldgslbsvcpayld2.servicename
                                             }#newgslbsvcbndpayld
                            "$(Get-TimeStamp) Bind GSLB Service " + $oldgslbsvcpayld2.servicename | Out-File -filepath $outputfile -Append -Encoding ascii
                            TRY {
                                Invoke-Nitro -Method PUT -Type gslbvserver_gslbservice_binding -Payload $newgslbsvcbndpayld2 -OnErrorAction CONTINUE -Confirm -Force
                                } #TRY GSLB Service Binding
                            CATCH {
                                  "$(Get-TimeStamp) FAILED Binding GSLB Service " + $oldgslbsvcpayld2.servicename + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
                                  } #CATCH GSLB Service Binding

#Set Backup GSLB vServer
                            $backgslbvsrvpayld = @{ }
                            $backgslbvsrvpayld = @{
                                                 name = $oldgslbvsrvpayld.name
                                                 backupvserver = $oldgslbvsrv2.gslbvserver.name
                                                 }#backgslbvsrvpayld
                            "$(Get-TimeStamp) Set Backup GSLB vServer " + $oldgslbvsrv2.gslbvserver.name + " To " + $oldgslbvsrvpayld.name | Out-File -filepath $outputfile -Append -Encoding ascii
                            TRY {
                                Invoke-Nitro -Method PUT -Type gslbvserver -Payload $backgslbvsrvpayld -OnErrorAction CONTINUE -Confirm -Force
                            } #TRY Add Backup GSLB vServer
                            CATCH {
                                  "$(Get-TimeStamp) FAILED Set Backup GSLB vServer " + $oldgslbvsrv2.gslbvserver.name + " To " + $oldgslbvsrvpayld.name + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
                                  } #Catch Backup GSLB vServer

#Disconnect from New NS                                  
                            "$(Get-TimeStamp) Disconnect from " + $NEWNsip | Out-File -filepath $outputfile -Append -Encoding ascii
                            Disconnect-NetScaler
						}#ForEach oldsvc2
                    }#TRY gslb service binding 2
                    CATCH {
                          "$(Get-TimeStamp) FAILED Getting GSLB backup vServer service bindings  " + $oldgslbvsrv2.name + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
                          }#CATCH gslb service binding 2
                    }#Try backup vServer
                CATCH {
                      "$(Get-TimeStamp) FAILED Getting GSLB backup vServer  " + $oldgslbvsrv.gslbvserver.backupvserver + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
                      }# Catch backup vserver
                }#IF backup vserver
					}# Try Getting GSLB vServer info
				CATCH {
					  "$(Get-TimeStamp) FAILED Getting GSLB vServer  " + $gslbvip.vservername + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
					  }# CATCH Getting GSLB vserver info
					}# Try gslb domain binding
				CATCH {
					  "$(Get-TimeStamp) FAILED Getting GSLB Domain Binding  " + $gslbdomname + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
					  }#CATCH GSLB Domain Binding
 
		}#ForEach FQDN
} #ForEach DC

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
              "$(Get-TimeStamp) FAILED Save Config  " + $SAVENsip + " " + $_.Exception.Message | Out-File -filepath $outputfile -Append -Encoding ascii
        } #Catch SaveConfig
}#ForEach SaveDC

"$(Get-TimeStamp) *** END *** Script create_gslb_old.ps1 for Environment: " + $env | Out-File -filepath $outputfile -Append -Encoding ascii



