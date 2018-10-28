
<#
Ask for environment ("DEV", "QA1", "STG", "PRD")
For each DC (TRM, GRN), scan through new VPX extract the list of domainnames in that environment
Sort uniquely and remove all relevant unused configuration from Big VPXs
- Get List of DomainNames
- For each domainname:
  - identify GSLB vservers

- For each Big VPX
  - for each gslb vserver
    - identify gslb services
      - for each gslb service
        - identify GSLB server
        - if local gslb service, identify corresponding VIP(s)
          - identify service group(s)/service(s)
            - identify server(s)
            - unbind from service group/service
            - if not bound anywhere else, remove server
          - if servicegroup/server not bound anywhere else, remove
        - if no more service group/serivces bound, remove the VIP
        - remove server entry (will also remove the GSLB service)

    if no more gslb services bound to gslb vserver, delete the gslb vserver
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

$gslbviplist = New-Object System.Collections.Generic.List[System.String]
$gslbvipunq = $null

$env = Read-Host -Prompt "Environment?"
$envinit = ($env.Substring(0,1))
$credential = Get-Credential

$logfile = $null
$logfile = "H:\NS-Migration\" + $env + "-remove-old-configs.txt"

"$(Get-TimeStamp) *** START *** Script remove-old-configs.ps1 for Environment: " + $env | Out-File -filepath $logfile -Append -Encoding ascii

ForEach ($dc in $dclist) {
    $domains = $null
    $dcinit = $null
    $dcinit = ($dc.Substring(0,1))

    $NEWNsip = $null
    $NEWNsip = 'n' + $dcinit + '0' + $envinit + 'nsinty01.foo.bar'

    "$(Get-TimeStamp) CONNECT to " + $NEWNsip | Out-File -filepath $logfile -Append -Encoding ascii

    Connect-NetScaler -Hostname $NEWNsip -Credential $Credential -HTTPS
#Get List of DomainNames and the GSLB services accoitaed with them
    "$(Get-TimeStamp) GET List of DomainNames from " + $NEWNsip | Out-File -filepath $logfile -Append -Encoding ascii
    TRY {
        $domains = Invoke-Nitro -Method GET -Type gslbdomain | select gslbdomain -ExpandProperty gslbdomain | select name
        }#TRY GET Domains
    CATCH {
          "$(Get-TimeStamp) FAILED GET List of Domains from " + $NEWNsip + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
    }#CATCH GET Domains

    ForEach ($fqdn in $domains) {
        $gslbvip = $null
        "$(Get-TimeStamp) GET List of GSLB vServers for " +$fqdn + " on " + $NEWNsip | Out-File -filepath $logfile -Append -Encoding ascii
        TRY {
            $gslbvip = Invoke-Nitro -Method GET -Type gslbdomain_gslbvserver_binding -Resource $fqdn.name
            }#TRY GET GSLB SVC Bindings
        CATCH {
              "$(Get-TimeStamp) FAILED GET List of GSLB Service for " +$fqdn + " on " + $NEWNsip + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
              }#CATCH GET GSLB SVC Bindings
   
        ForEach ($gslbvipcnt in $gslbvip) {
            $gslbviplist.Add($gslbvipcnt.gslbdomain_gslbvserver_binding.vservername)
        }#ForEach gslbvipcnt
    }#ForEach fqdn
    
    "$(Get-TimeStamp) DISCONNECT from " + $NEWNsip | Out-File -filepath $logfile -Append -Encoding ascii
    Disconnect-NetScaler
}#ForEach DC

$gslbvipunq = $gslbviplist | Sort-Object | Get-Unique


ForEach ($odc in $dclist) {
    $odcinit = $null
    $odcinit = ($odc.Substring(0,1))

    $OLDNsip = $null
    $OLDNsip = 'n' + $odcinit + '0pnsint01.foo.bar'

    "$(Get-TimeStamp) CONNECT to " + $OLDNsip | Out-File -filepath $logfile -Append -Encoding ascii

    Connect-NetScaler -Hostname $OLDNsip -Credential $Credential

#for each gslb vserver
    ForEach ($newgslbvip in $gslbvipunq) {
#identify gslb services
        $oldgslbsvclist = New-Object System.Collections.Generic.List[System.String]
        $oldgslbsvc = $null
        "$(Get-TimeStamp) GET List of GSLB services for " +$newgslbvip + " on " + $OLDNsip | Out-File -filepath $logfile -Append -Encoding ascii
        TRY {
            $oldgslbsvc = Invoke-Nitro -Method GET -Type gslbvserver_gslbservice_binding -Resource $newgslbvip
            ForEach ($oldgslbsvccnt in $oldgslbsvc.gslbvserver_gslbservice_binding) {
                $oldgslbsvclist.Add($oldgslbsvccnt.servicename)
            }#ForEach oldgslbsvccnt
#For each gslb service, identify GSLB server
            ForEach ($oldgslbsvcname in $oldgslbsvclist) {
                "$(Get-TimeStamp) GET GSLB server and IP for " +$oldgslbsvcname + " on " + $OLDNsip | Out-File -filepath $logfile -Append -Encoding ascii
                Write-Host $oldgslbsvcname
                TRY {
                    $gslbsvr = Invoke-Nitro -Method GET -Type gslbservice -Resource $oldgslbsvcname
#If local gslb service, identify corresponding VIP(s)
                    IF ($gslbsvr.gslbservice.gslb -eq "LOCAL") {
                        "$(Get-TimeStamp) GET LBvServer for " +$gslbsvr.gslbservice.ipaddress + " on " + $OLDNsip | Out-File -filepath $logfile -Append -Encoding ascii
                        $oldlbvserver = $null
                        TRY {
                            $oldlbvserver = Invoke-Nitro -Method GET -Type lbvserver | select lbvserver -ExpandProperty lbvserver | select name, ipv46 | Where ipv46 -Like $gslbsvr.gslbservice.ipaddress
#Identify service group
                            "$(Get-TimeStamp) GET ServiceGroup for " +$oldlbvserver.name + " on " + $OLDNsip | Out-File -filepath $logfile -Append -Encoding ascii
                            $oldsvcgrp = $null
                            TRY {
                                $oldsvcgrp = Invoke-Nitro -Method GET -Type lbvserver_servicegroup_binding -Resource $oldlbvserver.name
#Identify server(s)
                                "$(Get-TimeStamp) GET Servers for " +$oldsvcgrp_servicegroup_binding.servicegroupname + " on " + $OLDNsip | Out-File -filepath $logfile -Append -Encoding ascii
                                TRY {
                                    $oldsvr = Invoke-Nitro -Method GET -Type servicegroup_binding -Resource $oldsvcgrp.lbvserver_servicegroup_binding.servicegroupname
                                    IF ($oldsvr -isnot [array]) {
                                        $oldsvr = @($oldsvr)
                                    }#IF not an array
#Unbind from service group
                                    ForEach ($oldsvrcnt in $oldsvr) {
                                            "$(Get-TimeStamp) Unbind " + $oldsvrcnt.servicegroup_binding.servicegroup_servicegroupmember_binding.servicegroupname + " from " + $lbvserver_servicegroup_binding.servicegroupname + " on " + $OLDNsip | Out-File -filepath $logfile -Append -Encoding ascii
<#

                                            $oldsvgmempayld = @{ }
                                            $oldsvgmempayld = @{
                                                                serviceGroupName = $oldsvrcnt.servicegroup_binding.servicegroup_servicegroupmember_binding.servicegroupname
                                                                servername = $oldsvrcnt.servicegroup_binding.servicegroup_servicegroupmember_binding.servername
                                                                port = $oldsvrcnt.servicegroup_binding.servicegroup_servicegroupmember_binding.port
                                            }#oldsvgmempayld
                                            TRY {
                                                Invoke-Nitro -Method DELETE -Type servicegroup_servicegroupmember_binding -Payload $oldsvgmempayld -OnErrorAction CONTINUE -Confirm -Force

#>
                                            $svgmemberunbindURI = "http://"+$OLDNsip+"/nitro/v1/config/servicegroup_servicegroupmember_binding/"+$oldsvrcnt.servicegroup_binding.servicegroup_servicegroupmember_binding.servicegroupname+"?args=servername:"+$oldsvrcnt.servicegroup_binding.servicegroup_servicegroupmember_binding.servername+",port:"+$oldsvrcnt.servicegroup_binding.servicegroup_servicegroupmember_binding.port
                                            TRY {
                                                Invoke-RestMethod -Uri $svgmemberunbindURI -Method DELETE -Credential $credential -ErrorAction Continue
                                            }#TRY Unbind Servicegroup member
                                            CATCH {
                                                  "$(Get-TimeStamp) FAILED Unbind " + $oldsvrcnt.servicegroup_binding.servicegroup_servicegroupmember_binding.servername + " from " + $oldsvrcnt.servicegroup_binding.servicegroup_servicegroupmember_binding.servicegroupname + " on " + $OLDNsip + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
                                            }#CATCH Unbind ServiceGroup Member
#If not bound anywhere else, remove server
                                            "$(Get-TimeStamp) Is " + $oldsvrcnt.servicegroup_binding.servicegroup_servicegroupmember_binding.servername + " still bound to anything on " + $OLDNsip | Out-File -filepath $logfile -Append -Encoding ascii
                                            $oldsvrbnd = $null
                                            TRY {
                                                $oldsvrbnd = Invoke-Nitro -Method GET -Type server_binding -Resource $oldsvrcnt.servicegroup_binding.servicegroup_servicegroupmember_binding.servername -OnErrorAction CONTINUE -Confirm -Force
                                            IF (!$oldsvrbnd.server_binding.server_servicegroup_binding) {
#Not bound anywhere else, remove server
                                                "$(Get-TimeStamp) Server " + $oldsvrcnt.servicegroup_binding.servicegroup_servicegroupmember_binding.servername + " is not bound to anything on " + $OLDNsip | Out-File -filepath $logfile -Append -Encoding ascii
                                                TRY {
                                                    Invoke-Nitro -Method DELETE -Type server -Resource $oldsvrcnt.servicegroup_binding.servicegroup_servicegroupmember_binding.servername -OnErrorAction CONTINUE -Confirm -Force
                                                }#TRY Delete Server
                                                CATCH {
                                                      "$(Get-TimeStamp) FAILED DELETE " + $oldsvrcnt.servicegroup_binding.servicegroup_servicegroupmember_binding.servername + " on " + $OLDNsip + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
                                                }#CATCH Delete Server
                                            }#IF Server is bound
                                            }#TRY Server still Bound?
                                            CATCH {
                                                  "$(Get-TimeStamp) FAILED GET " + $oldsvr.servicegroup_binding.servicegroup_servicegroupmember_binding + " on " + $OLDNsip + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
                                            }#CATCH Server still bound?
                                    }#ForEach oldsvr
#If ServiceGroup has no more bindings, remove it
                                    "$(Get-TimeStamp) Does " + $oldsvrcnt.servicegroup_binding.servicegroup_servicegroupmember_binding.servicegroupname + " have any more servers bound on " + $OLDNsip | Out-File -filepath $logfile -Append -Encoding ascii
                                    $oldsvcgrptest = $null
                                    TRY {
                                        $oldsvcgrptest = Invoke-Nitro -Method GET -Type servicegroup_binding -Resource $oldsvrcnt.servicegroup_binding.servicegroup_servicegroupmember_binding.servicegroupname
                                        IF (!$oldsvcgrouptest.servicegroup_binding.servicegroup_servicegroupmember_binding) {
                                           "$(Get-TimeStamp) Service " + $oldsvrcnt.servicegroup_binding.servicegroup_servicegroupmember_binding.servicegroupname + " has no more bindings on " + $OLDNsip | Out-File -filepath $logfile -Append -Encoding ascii
                                           TRY {
                                               Invoke-Nitro -Method DELETE -Type servicegroup -Resource $oldsvrcnt.servicegroup_binding.servicegroup_servicegroupmember_binding.servicegroupname -OnErrorAction CONTINUE -Confirm -Force
                                           }#TRY Delete ServiceGroup
                                           CATCH {
                                                 "$(Get-TimeStamp) FAILED DELETE " + $oldsvrcnt.servicegroup_binding.servicegroup_servicegroupmember_binding.servicegroupname + " on " + $OLDNsip + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
                                           }#CATCH Delete ServiceGroup
                                        }#IF SvcGroup No Bindings
                                    }#TRY ServiceGroupTest
                                    CATCH {
                                          "$(Get-TimeStamp) FAILED GET " + $oldsvrcnt.servicegroup_binding.servicegroup_servicegroupmember_binding.servicegroupname + " bindings on " + $OLDNsip + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
                                    }#CATCH ServiceGroup still has bindings?

#If no more service group/serivces bound, remove the VIP
                                    "$(Get-TimeStamp) Does " + $oldlbvserver.name + " have any more bindings " + $OLDNsip | Out-File -filepath $logfile -Append -Encoding ascii
                                    $oldvipbnd = $null
                                    TRY {
                                        $oldvipbnd = Invoke-Nitro -Method GET -Type lbvserver_binding -Resource $oldlbvserver.name -OnErrorAction CONTINUE -Confirm -Force
                                    IF (!$oldvipbnd.lbvserver_servicegroup_binding -AND !$oldvipbnd.lbvserver_service_binding) {
#Not bound anywhere else, remove VIP
                                                "$(Get-TimeStamp) VIP " + $oldlbvserver.name + " has no more bindings on " + $OLDNsip | Out-File -filepath $logfile -Append -Encoding ascii
                                                TRY {
                                                    Invoke-Nitro -Method DELETE -Type lbvserver -Resource $oldlbvserver.name -OnErrorAction CONTINUE -Confirm -Force
                                                }#TRY Delete VIP
                                                CATCH {
                                                      "$(Get-TimeStamp) FAILED DELETE " + $oldlbvserver.name + " on " + $OLDNsip + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
                                                }#CATCH Delete VIP
                                            }#IF VIP has ServiceGroup or Service
                                     }#TRY VIP Bind Test
                                     CATCH {
                                           "$(Get-TimeStamp) FAILED GET Bindings for " + $oldlbvserver.name + " on " + $OLDNsip + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
                                     }#CATCH VIP Bind Test
#Remove GSLB server entry (will also remove the GSLB service)
                                     "$(Get-TimeStamp) VIP " + $gslbsvr.gslbservice.servername + " has no more bindings on " + $OLDNsip | Out-File -filepath $logfile -Append -Encoding ascii
                                     TRY {
                                         Invoke-Nitro -Method DELETE -Type server -Resource $gslbsvr.gslbservice.servername -OnErrorAction CONTINUE -Confirm -Force
                                     }#TRY Delete GSLB Server
                                     CATCH {
                                           "$(Get-TimeStamp) FAILED DELETE " + $gslbsvr.gslbservice.servername + " on " + $OLDNsip + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
                                     }#CATCH Delete GSLB Server
                                }#TRY GET GSLB Server Bindings
                                CATCH {
                                      "$(Get-TimeStamp) FAILED GET Servers for " +$oldsvcgrp.servicegroup + " on " + $OLDNsip + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
                                }#CATCH GET GSLB SVC Bindings
                            }#Get servicegroup
                            CATCH {
                                  "$(Get-TimeStamp) FAILED GET ServiceGroup for " +$oldlbvserver.name + " on " + $OLDNsip + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
                            }#CATCH GET LBVserver
                        }#Get LBVserver
                        CATCH {
                              "$(Get-TimeStamp) FAILED GET LBvServer for " +$gslbsvr.gslbservice.ipaddress + " on " + $OLDNsip + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
                        }#CATCH GET LBVserver
                    }#If gslb local
                }#TRY GET GSLB SVC Bindings
                CATCH {
                      "$(Get-TimeStamp) FAILED GET GSLB server and IP for " +$oldgslbsvcname + " on " + $NEWNsip + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
                }#CATCH GET GSLB SVC Bindings
            }#ForEach oldgslbsvccnt
        }#TRY GET GSLB SVC Bindings
        CATCH {
              "$(Get-TimeStamp) FAILED GET List of GSLB Services for " +$newgslbvip + " on " + $OLDNsip + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
        }#CATCH GET GSLB SVC Bindings
#If no more gslb services bound to GSLB VIP, delete the GSLB VIP
        "$(Get-TimeStamp) Does " + $newgslbvip + " have any more bindings " + $OLDNsip | Out-File -filepath $logfile -Append -Encoding ascii
        $oldgslbvipbnd = $null
        TRY {
            $oldgslbvipbnd = Invoke-Nitro -Method GET -Type gslbvserver_binding -Resource $newgslbvip -OnErrorAction CONTINUE -Confirm -Force
            IF (!$oldgslbvipbnd.gslbvserver_gslbservice_binding) {
#Not bound anywhere else, remove GSLB VIP
               "$(Get-TimeStamp) GSLB VIP " + $newgslbvip + " has no more bindings on " + $OLDNsip | Out-File -filepath $logfile -Append -Encoding ascii
               TRY {
                   Invoke-Nitro -Method DELETE -Type gslbvserver -Resource $newgslbvip -OnErrorAction CONTINUE -Confirm -Force
               }#TRY Delete GSLB VIP
               CATCH {
                     "$(Get-TimeStamp) FAILED DELETE " + $newgslbvip + " on " + $OLDNsip + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
               }#CATCH Delete GSLB VIP
             }#IF GSLB VIP has GSLB Service
        }#TRY GSLB VIP Bind Test
        CATCH {
              "$(Get-TimeStamp) FAILED GET GSLB Bindings for " + $newgslbvip + " on " + $OLDNsip + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
        }#CATCH GSLB VIP Bind Test
    }#ForEach newgslbvip
    Save-NSConfig
    Disconnect-NetScaler
}#ForEach DC


"$(Get-TimeStamp) *** END *** Script remove-old-configs.ps1 for Environment: " + $env | Out-File -filepath $logfile -Append -Encoding ascii
