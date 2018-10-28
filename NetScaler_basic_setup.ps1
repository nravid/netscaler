
<#
Basic initial setup for all new NetScaler VPXs
#>


function Get-TimeStamp {
    
    return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
    
}

$AllProtocols = [System.Net.SecurityProtocolType]'Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

$NEWNsip = $null
$NEWSNIP = $null
$netmask = $null
$hostname = $null
$ldappass = $null
$weblogpass = $null
$credential = $null
$logfile = $null

$NEWNsip = Read-Host -Prompt "NSIP?"
$netmask = Read-Host -Prompt "NetMask?"
$hostname = Read-Host -Prompt "Host Name?"
$sitename = Read-Host -Prompt "Site (ash, grn, trm)?"
$DMZ = ((Read-Host -Prompt "DMZ (Y/N)?") -eq "y")
$sitename = $sitename.ToLower()
$ldappass = ((Invoke-RestMethod -Uri https://pim.foo.bar/SecretServer/winauthwebservices/api/v1/secrets/1349 -Method Get -UseDefaultCredentials -ContentType "application/json").items | Where-Object {$_.fieldName -eq "Password"}).itemValue
$weblogpass = ((Invoke-RestMethod -Uri https://pim.foo.bar/SecretServer/winauthwebservices/api/v1/secrets/5152 -Method Get -UseDefaultCredentials -ContentType "application/json").items | Where-Object {$_.fieldName -eq "Password"}).itemValue
$credential = Get-Credential

$subnet = $null
$octets = $NewNsip.split('.')
$octets[3] = $null
$subnet = $octets -join '.'
$NEWSNIP = $subnet + "20"
$NEWGSLB = $subnet + "16"
$NEWADNS = $subnet + "53"

$logfile = "H:\" + $hostname + "-initial.txt"

"$(Get-TimeStamp) *** START *** Script NetScaler_basic_setup for : " + $hostname | Out-File -filepath $logfile -Append -Encoding ascii

"$(Get-TimeStamp) CONNECT to " + $NEWNsip | Out-File -filepath $logfile -Append -Encoding ascii

Connect-NetScaler -Hostname $NEWNsip -Credential $Credential

#Set HOSTNAME
"$(Get-TimeStamp) SET Hostname to " + $hostname | Out-File -filepath $logfile -Append -Encoding ascii
$hostnamepayld = @{ }
$hostnamepayld = @{
                hostname = $hostname
                }#hostnamepayld
TRY {
    Invoke-Nitro -Method PUT -Type nshostname -Payload $hostnamepayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Hostname
CATCH {
      "$(Get-TimeStamp) FAILED SET Hostname " + $hostname + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Hostname

#Add SNIP
"$(Get-TimeStamp) ADD SNIP " + $NEWSNIP | Out-File -filepath $logfile -Append -Encoding ascii
$snippayld = @{ }
$snippayld = @{
                ipaddress = $NEWSNIP
                netmask = $netmask
                type = "SNIP"
                vserver = "DISABLED"
                mgmtaccess = "ENABLED"
                gui = "SECUREONLY"
                }#snippayld
TRY {
    Invoke-Nitro -Method POST -Type nsip -Payload $snippayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY SNIP
CATCH {
      "$(Get-TimeStamp) FAILED ADD SNIP " + $NEWSNIP + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH SNIP

#Set TimeZOne
"$(Get-TimeStamp) SET Time Zone to GMT-05:00-EST-America/New_York " + $NEWSNIP | Out-File -filepath $logfile -Append -Encoding ascii
$nstzpayld = @{ }
$nstzpayld = @{
              timezone = "GMT-05:00-EST-America/New_York"
              }#snippayld
TRY {
    Invoke-Nitro -Method PUT -Type nsconfig -Payload $nstzpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY TimeZone
CATCH {
      "$(Get-TimeStamp) FAILED SET TimeZone " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH TimeZone

#Set NTP
$ntpservers = @("10.30.4.32", "10.30.60.10")
if ($DMZ){$ntpservers = @("10.65.160.123", "10.73.160.123")}

ForEach ($ntp in $ntpservers){
    "$(Get-TimeStamp) SET NTP Server " + $ntp | Out-File -filepath $logfile -Append -Encoding ascii
    $ntppayld = @{ }
    $ntppayld = @{
                 serverip = $ntp
                 minpoll = "6"
                 maxpoll = "10"
                 }#ntppayld
    TRY {
        Invoke-Nitro -Method POST -Type ntpserver -Payload $ntppayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
        }#TRY NTPServer
    CATCH {
          "$(Get-TimeStamp) FAILED SET NTP Server " + $ntp + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
          }#CATCH NTPServer
}#NTPServers

"$(Get-TimeStamp) SET NTP Sync " + $NEWSNIP | Out-File -filepath $logfile -Append -Encoding ascii
TRY {
    Invoke-Nitro -Method POST -Type ntpsync -Action ENABLE -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY NTP Sync
CATCH {
      "$(Get-TimeStamp) FAILED SET NTP Sync " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH NTP Sync

#Enable Features
"$(Get-TimeStamp) ENABLE Features" | Out-File -filepath $logfile -Append -Encoding ascii
$featpayld = @{ }
$featpayld = @{
                feature = "WL SP LB CS CMP SSL GSLB SSLVPN AAA REWRITE AppFw RESPONDER AppFlow"
                }#featpayld
TRY {
    Invoke-Nitro -Method POST -Type nsfeature -Action ENABLE -Payload $featpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Enable Feature
CATCH {
      "$(Get-TimeStamp) FAILED ENABLE Features " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Enable Feature

"$(Get-TimeStamp) DISABLE CallHome Feature" | Out-File -filepath $logfile -Append -Encoding ascii
$chfeatpayld = @{ }
$chfeatpayld = @{
                feature = "CH"
                }#chfeatpayld
TRY {
    Invoke-Nitro -Method POST -Type nsfeature -Action DISABLE -Payload $chfeatpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Disable Feature
CATCH {
      "$(Get-TimeStamp) FAILED ENABLE Features " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Disable Feature

#Enable Modes
"$(Get-TimeStamp) ENABLE Modes" | Out-File -filepath $logfile -Append -Encoding ascii
$modepayld = @{ }
$modepayld = @{
                mode = "FR L3 TCPB Edge USNIP PMTUD"
                }#modepayld
TRY {
    Invoke-Nitro -Method POST -Type nsmode -Action ENABLE -Payload $modepayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Enable Feature
CATCH {
      "$(Get-TimeStamp) FAILED ENABLE Modes " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Enable Feature

#Set HTTP Params
"$(Get-TimeStamp) SET HTTP Params" | Out-File -filepath $logfile -Append -Encoding ascii
$httpparpayld = @{ }
$httpparpayld = @{
                dropinvalreqs = "ON"
                }#httpparpayld
TRY {
    Invoke-Nitro -Method PUT -Type nshttpparam -Payload $httpparpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Set HTTP Params
CATCH {
      "$(Get-TimeStamp) FAILED HTTP Params " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH HTTP Params

#Set HTTP Profile
"$(Get-TimeStamp) SET Default HTTP Profile" | Out-File -filepath $logfile -Append -Encoding ascii
$httpprfpayld = @{ }
$httpprfpayld = @{
                name = "nshttp_default_profile"
                dropinvalreqs = "ENABLED"
                }#httpprfpayld
TRY {
    Invoke-Nitro -Method PUT -Type nshttpprofile -Payload $httpprfpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Set HTTP Profile
CATCH {
      "$(Get-TimeStamp) FAILED SET Default HTTP Profile " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH HTTP Profile

#Set TCP Params
"$(Get-TimeStamp) SET TCP Params" | Out-File -filepath $logfile -Append -Encoding ascii
$tcpparpayld = @{ }
$tcpparpayld = @{
                ws = "ENABLED"
                wsval = "8"
                sack = "ENABLED"
                nagle = "ENABLED"
                }#tcpparpayld
TRY {
    Invoke-Nitro -Method PUT -Type nstcpparam -Payload $tcpparpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Set TCP Params
CATCH {
      "$(Get-TimeStamp) FAILED TCP Params " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Set TCP Param

#Set TCP Profile
"$(Get-TimeStamp) SET Default TCP Profile" | Out-File -filepath $logfile -Append -Encoding ascii
$tcpprfpayld = @{ }
$tcpprfpayld = @{
                name = "nstcp_default_profile"
                ws = "ENABLED"
                wsval = "8"
                sack = "ENABLED"
                nagle = "ENABLED"
                }#tcpprfpayld
TRY {
    Invoke-Nitro -Method PUT -Type nstcpprofile -Payload $tcpprfpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Set TCP Profile
CATCH {
      "$(Get-TimeStamp) FAILED SET Default TCP Profile " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH TCP Profile

#Add ADNS Server
"$(Get-TimeStamp) ADD ADNS Server " + $NEWADNS | Out-File -filepath $logfile -Append -Encoding ascii
$adnssvrpayld = @{ }
$adnssvrpayld = @{
                 name = "ADNS"
                 ipaddress = $NEWADNS
                 }#adnssvrpayld
TRY {
    Invoke-Nitro -Method POST -Type server -Payload $adnssvrpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Add ADNS Server
CATCH {
      "$(Get-TimeStamp) FAILED ADD ADNS Server " + $NEWADNS + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Add ADNS Server

#Add ADNS Service
"$(Get-TimeStamp) ADD ADNS Service " + $NEWADNS | Out-File -filepath $logfile -Append -Encoding ascii
$adnssvcpayld = @{ }
$adnssvcpayld = @{
                 name = "ADNS"
                 servername = "ADNS"
                 servicetype = "ADNS"
                 port = "53"
                 }#adnssvcpayld
TRY {
    Invoke-Nitro -Method POST -Type service -Payload $adnssvcpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Add ADNS Service
CATCH {
      "$(Get-TimeStamp) FAILED ADD ADNS Service " + $NEWADNS + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
     }#CATCH Add ADNS Service

#Add GSLB Site
"$(Get-TimeStamp) ADD GSLB Site " + "gslb_site_" + $sitename + ": " + $NEWGSLB | Out-File -filepath $logfile -Append -Encoding ascii
$gslbsitepayld = @{ }
$gslbsitepayld = @{
                  sitename = "gslb_site_" + $sitename
                  sitetype = "LOCAL"
                  siteipaddress = $NEWGSLB
                  }#gslbsitepayld
TRY {
    Invoke-Nitro -Method POST -Type gslbsite -Payload $gslbsitepayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Add GSLB Site
CATCH {
      "$(Get-TimeStamp) FAILED ADD GSLB Site " + "gslb_site_" + $sitename + ": " + $NEWGSLB + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Add GSLB site

#Add DNS NameServers
"$(Get-TimeStamp) ADD DNS NameServers" | Out-File -filepath $logfile -Append -Encoding ascii
$dnsservers = @("10.255.0.1", "10.255.0.2")
if ($DMZ){$dnsservers = @("10.65.160.53", "10.73.160.53")}

ForEach ($dns in $dnsservers){
    "$(Get-TimeStamp) Add DNS NameServer " + $dns | Out-File -filepath $logfile -Append -Encoding ascii
    $dnspayld = @{ }
    $dnspayld = @{
                 ip = $dns
                 type = "UDP_TCP"
                 }#dnspayld
    TRY {
        Invoke-Nitro -Method POST -Type dnsnameserver -Payload $dnspayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
        }#TRY DNSServer
    CATCH {
          "$(Get-TimeStamp) FAILED ADD DNS NameServer " + $dns + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
          }#CATCH DNSServer
}#DNSServers

#SNMP Community
"$(Get-TimeStamp) ADD SNMP Communities" | Out-File -filepath $logfile -Append -Encoding ascii
$snmpcomms = @("public", "zenoss")

ForEach ($snmpc in $snmpcomms){
    "$(Get-TimeStamp) Add SNMP Community " + $snmpc | Out-File -filepath $logfile -Append -Encoding ascii
    $snmpcpayld = @{ }
    $snmpcpayld = @{
                 communityname = $snmpc
                 permissions = "ALL"
                 }#snmpcpayld
    TRY {
        Invoke-Nitro -Method POST -Type snmpcommunity -Payload $snmpcpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
        }#TRY SNMPCommunity
    CATCH {
          "$(Get-TimeStamp) FAILED ADD SNMP Community " + $snmpc + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
          }#CATCH SNMPCommunity
}#SNMPComms

#SNMP Managers
"$(Get-TimeStamp) ADD SNMP Managers" | Out-File -filepath $logfile -Append -Encoding ascii
$snmpmgrs = @("st0pzenrn01.foo.bar", "st0pzenrn02.foo.bar", "st0pzenrn03.foo.bar", "st0pzenrn04.foo.bar")

ForEach ($snmpm in $snmpmgrs){
    "$(Get-TimeStamp) Add SNMP Manager " + $snmpm | Out-File -filepath $logfile -Append -Encoding ascii
    $snmpmpayld = @{ }
    $snmpmpayld = @{
                 ipaddress = $snmpm
                 netmask = "255.255.255.255"
                 domainresolveretry = "5"
                 }#snmpmpayld
    TRY {
        Invoke-Nitro -Method POST -Type snmpmanager -Payload $snmpmpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
        }#TRY SNMPManager
    CATCH {
          "$(Get-TimeStamp) FAILED ADD SNMP Manager " + $snmpm + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
          }#CATCH SNMPManager
}#SNMPMgrs

#SNMP Traps
"$(Get-TimeStamp) ADD SNMP Trap Destinations" | Out-File -filepath $logfile -Append -Encoding ascii
$snmptypes = @("generic", "specific")
$snmptraps = @("10.64.5.67", "10.31.102.103")

ForEach ($snmptype in $snmptypes){
    ForEach ($snmpt in $snmptraps){
            "$(Get-TimeStamp) ADD SNMP " + $snmptype + " Trap Destination " + $snmpt | Out-File -filepath $logfile -Append -Encoding ascii
            $snmptpayld = @{ }
            $snmptpayld = @{
                           trapclass = $snmptype
                           trapdestination = $snmpt
                           communityname = "public"
                           allpartitions = "ENABLED"
                           }#snmpmpayld
            TRY {
                Invoke-Nitro -Method POST -Type snmptrap -Payload $snmptpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
                }#TRY SNMPTrap
            CATCH {
                  "$(Get-TimeStamp) FAILED SNMP " + $snmptype + " Trap Destination " + $snmpt + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
                  }#CATCH SNMPManager
    }#SNMPTraps
}#SNMPTypes

#SNMP Warning Alarms
"$(Get-TimeStamp) SET SNMP Warning Alarms" | Out-File -filepath $logfile -Append -Encoding ascii
$snmpalrms = @("CONFIG-CHANGE", "CONFIG-SAVE", "ENTITY-STATE", "GSLB-SITE-MEP-FLAP", "HA-STICKY-PRIMARY", "LOGIN-FAILURE", "SSL-CERT-EXPIRY", "HA-SYNC-FAILURE", "HA-VERSION-MISMATCH", "HA-STATE-CHANGE", "HA-BAD-SECONDARY-STATE", "HA-NO-HEARTBEATS", "HARD-DISK-DRIVE-ERRORS")

ForEach ($snmpa in $snmpalrms){
    "$(Get-TimeStamp) SET SNMP Alarm " + $snmpa + " WARNING" | Out-File -filepath $logfile -Append -Encoding ascii
    $snmpapayld = @{ }
    $snmpapayld = @{
                 trapname = $snmpa
                 severity = "WARNING"
                 state = "ENABLED"
                 }#snmpapayld
    TRY {
        Invoke-Nitro -Method PUT -Type snmpalarm -Payload $snmpapayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
        }#TRY SNMPAlarm
    CATCH {
          "$(Get-TimeStamp) FAILED SET SNMP Alarm " + $snmpa + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
          }#CATCH SNMPAlarm
}#SNMPAlrms

#SNMP CPU/MEM Alarms
"$(Get-TimeStamp) SET SNMP CPU/MEM Alarms" | Out-File -filepath $logfile -Append -Encoding ascii
$snmpcpus = @("CPU-USAGE", "MEMORY")

ForEach ($snmpcpu in $snmpcpus){
    "$(Get-TimeStamp) SET SNMP Alarm " + $snmpcpu + " Critical" | Out-File -filepath $logfile -Append -Encoding ascii
    $snmpcpupayld = @{ }
    $snmpcpupayld = @{
                 trapname = $snmpcpu
                 severity = "CRITICAL"
                 thresholdvalue = "80"
                 normalvalue = "35"
                 state = "ENABLED"
                 }#snmpcpupayld
    TRY {
        Invoke-Nitro -Method PUT -Type snmpalarm -Payload $snmpcpupayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
        }#TRY SNMPCPUAlarm
    CATCH {
          "$(Get-TimeStamp) FAILED SET SNMP Alarm " + $snmpcpu + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
          }#CATCH SNMPCPUAlarm
}#SNMPCPUAlrms

#Set SNMP Options
"$(Get-TimeStamp) SET SNMP Options" | Out-File -filepath $logfile -Append -Encoding ascii
$snmpopayld = @{ }
$snmpopayld = @{
                snmptraplogging = "ENABLED"
                }#snmpopayld
TRY {
    Invoke-Nitro -Method PUT -Type snmpoption -Payload $snmpopayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Set SNMP Options
CATCH {
      "$(Get-TimeStamp) FAILED SET SNMP Options " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH SNMP Options

#Set Audit NetProfile
"$(Get-TimeStamp) ADD Audit NetProfile" | Out-File -filepath $logfile -Append -Encoding ascii
$netprfpayld = @{ }
$netprfpayld = @{
                name = "aqr_syslog_netprf"
                srcip = $NEWSNIP
                srcippersistency = "ENABLED"
                }#netprfpayld
TRY {
    Invoke-Nitro -Method POST -Type netprofile -Payload $netprfpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Add NetProfile
CATCH {
      "$(Get-TimeStamp) FAILED ADD Audit NetProfile " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Add NetProfile

#Add Audit SysLog Action
"$(Get-TimeStamp) ADD Audit SysLog Action" | Out-File -filepath $logfile -Append -Encoding ascii
$audactpayld = @{ }
$audactpayld = @{
                name = "aqr_syslog_audact"
                serverip = "10.30.19.60"
                loglevel = "ALL"
                logfacility = "LOCAL3"
                timezone = "LOCAL_TIME"
                userdefinedauditlog = "YES"
                transport = "TCP"
                maxlogdatasizetohold = "50"
                netprofile = "aqr_syslog_netprf"
                }#audactpayld
TRY {
    Invoke-Nitro -Method POST -Type auditsyslogaction -Payload $audactpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Add Audit Action
CATCH {
      "$(Get-TimeStamp) FAILED ADD Audit Action " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Add Audit Action

#Add Audit SysLog Policy
"$(Get-TimeStamp) ADD Audit SysLog Policy" | Out-File -filepath $logfile -Append -Encoding ascii
$audpolpayld = @{ }
$audpolpayld = @{
                name = "aqr_syslog_audpol"
                rule = "true"
                action = "aqr_syslog_audact"
                }#audpolpayld
TRY {
    Invoke-Nitro -Method POST -Type auditsyslogpolicy -Payload $audpolpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Add Audit Policy
CATCH {
      "$(Get-TimeStamp) FAILED ADD Audit Policy " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Add Audit Policy

#Bind Audit SysLog Policy
"$(Get-TimeStamp) BIND Audit SysLog Policy Globally" | Out-File -filepath $logfile -Append -Encoding ascii
$audbndpayld = @{ }
$audbndpayld = @{
                policyname = "aqr_syslog_audpol"
                priority = 100
                globalbindtype = "SYSTEM_GLOBAL"
                }#audbndpayld
TRY {
    Invoke-Nitro -Method POST -Type auditsyslogglobal_auditsyslogpolicy_binding -Payload $audbndpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Bind Audit Policy
CATCH {
      "$(Get-TimeStamp) FAILED BIND Audit Policy " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Bind Audit Policy

#SSL Ciphers
"$(Get-TimeStamp) ADD SSL Ciphers" | Out-File -filepath $logfile -Append -Encoding ascii
$ciphers = @("aqr-cipher-high_frontend", "aqr-cipher-high_backend")
$ciphernames = @("TLS1.2-ECDHE-RSA-AES-256-SHA384", "TLS1.2-ECDHE-RSA-AES-128-SHA256", "TLS1.2-DHE-RSA-AES256-GCM-SHA384", "TLS1.2-DHE-RSA-AES128-GCM-SHA256", "TLS1.2-ECDHE-RSA-AES256-GCM-SHA384", "TLS1.2-AES-256-SHA256", "TLS1.2-AES-128-SHA256","TLS1.2-AES256-GCM-SHA384", "TLS1.2-AES128-GCM-SHA256", "TLS1.2-ECDHE-ECDSA-AES256-SHA384", "TLS1.2-ECDHE-ECDSA-AES128-SHA256", "TLS1.2-ECDHE-ECDSA-AES256-GCM-SHA384", "TLS1.2-ECDHE-ECDSA-AES128-GCM-SHA256", "TLS1.2-DHE-RSA-AES-256-SHA256", "TLS1.2-DHE-RSA-AES-128-SHA256", "TLS1.2-ECDHE-RSA-AES128-GCM-SHA256")

ForEach ($cipher in $ciphers){
    "$(Get-TimeStamp) ADD Cipher " + $cipher | Out-File -filepath $logfile -Append -Encoding ascii
    $cipheraddpayld = @{ }
    $cipheraddpayld = @{
                       ciphergroupname = $cipher
                       }#cipheraddpayld
    TRY {
        Invoke-Nitro -Method POST -Type sslcipher -Payload $cipheraddpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
        ForEach ($ciphername in $ciphernames){
                "$(Get-TimeStamp) Bind Cipher " + $cipher + " with " + $ciphername | Out-File -filepath $logfile -Append -Encoding ascii
                $cipherbindpayld = @{ }
                $cipherbindpayld = @{
                           ciphergroupname = $cipher
                           ciphername = $ciphername
                           }#snmpmpayld
                TRY {
                    Invoke-Nitro -type sslcipher_sslciphersuite_binding -Method PUT -Payload $cipherbindpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
                    }#Try Bind Cipher
                CATCH {
                     "$(Get-TimeStamp) FAILED Binding Cipher " + $cipher + " with CipherName " + $ciphername + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
                      }#CATCH Bind Cipher
        }#ForEach CipherNames
        }#TRY Add Cipher
    CATCH {
          "$(Get-TimeStamp) FAILED Add Cipher " + $cipher + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
          }#CATCH Add Cipher
}#ForEach SSLCiphers

#Set SSL Parameter Default Enabled
"$(Get-TimeStamp) Set SSL Parameter Default Enabled" | Out-File -filepath $logfile -Append -Encoding ascii
$sslparampayld = @{ }
$sslparampayld = @{
                  defaultprofile = "ENABLED"
                  }#sslparampayld
TRY {
    Invoke-Nitro -Method PUT -Type sslparameter -Payload $sslparampayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Set SSL Parameter
CATCH {
      "$(Get-TimeStamp) FAILED SET SSL Parameter Default Enabled " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Set SSL Parameter

#Set SSL FrontEnd ns_default Profile for HSTS
"$(Get-TimeStamp) SET SSL FrontEnd ns_default Profile" | Out-File -filepath $logfile -Append -Encoding ascii
$ssldefprffepayld = @{ }
$ssldefprffepayld = @{
                  name = "ns_default_ssl_profile_frontend"
                  hsts = "ENABLED"
                  maxage = "157680000"
                  includesubdomains = "YES"
                  }#ssldefprffepayld
TRY {
    Invoke-Nitro -Method PUT -Type sslprofile -Payload $ssldefprffepayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Set SSL FrontEnd ns+default Profile
CATCH {
      "$(Get-TimeStamp) FAILED SET SSL FrontEnd ns_default Profile " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Add SSL FrontEnd ns_default Profile

#Add SSL FrontEnd Profile
"$(Get-TimeStamp) ADD SSL FrontEnd Profile" | Out-File -filepath $logfile -Append -Encoding ascii
$sslprffepayld = @{ }
$sslprffepayld = @{
                  name = "aqr_default_ssl_profile_frontend"
                  sslprofiletype = "FrontEnd"
                  ssl3 = "DISABLED"
                  tls1 = "DISABLED"
                  tls11 = "DISABLED"
                  tls12 = "ENABLED"
                  hsts = "ENABLED"
                  maxage = "157680000"
                  includesubdomains = "YES"
                  }#sslprffepayld
TRY {
    Invoke-Nitro -Method POST -Type sslprofile -Payload $sslprffepayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Add SSL FrontEnd Profile
CATCH {
      "$(Get-TimeStamp) FAILED ADD SSL FrontEnd Profile " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Add SSL FrontEnd Profile

#Bind SSL FrontEnd ns_default Profile Cipher to aqr cipher group
"$(Get-TimeStamp) Bind SSL FrontEnd ns_default Profile to aqr high Cipher" | Out-File -filepath $logfile -Append -Encoding ascii
$sslnscipfepayld = @{ }
$sslnscipfepayld = @{
                  name = "ns_default_ssl_profile_frontend"
                  ciphername = "aqr-cipher-high_frontend"
                  cipherpriority = 1
                  }#sslnscipfepayld
TRY {
    Invoke-Nitro -Method PUT -Type sslprofile_sslcipher_binding -Payload $sslnscipfepayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Bind SSL FrontEnd ns_default Profile Cipher to aqr cipher group
CATCH {
      "$(Get-TimeStamp) FAILED Bind SSL FrontEnd ns_default Profile to aqr high Cipher " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Bind SSL FrontEnd ns_default Profile Cipher to aqr cipher group

#UnBind SSL FrontEnd Default Profile Cipher
"$(Get-TimeStamp) UnBind SSL Default FrontEnd Profile Cipher" | Out-File -filepath $logfile -Append -Encoding ascii
$sslprffeunbindURI = "http://"+$NEWNsip+"/nitro/v1/config/sslprofile_sslcipher_binding/aqr_default_ssl_profile_frontend?args=ciphername:DEFAULT"
TRY {
     Invoke-RestMethod -Uri $sslprffeunbindURI -Method DELETE -Credential $credential -ErrorAction Continue
     }#TRY Unbind FrontEnd SSL Default
CATCH {
       "$(Get-TimeStamp) FAILED Unbind DEFAULT from FrontEnd " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
       }#CATCH Unbind SSL FrontEnd Default

#Add SSL BackEnd Profile
"$(Get-TimeStamp) ADD SSL BackEnd Profile" | Out-File -filepath $logfile -Append -Encoding ascii
$sslprfbepayld = @{ }
$sslprfbepayld = @{
                  name = "aqr_default_ssl_profile_backend"
                  sslprofiletype = "BackEnd"
                  ssl3 = "DISABLED"
                  tls1 = "DISABLED"
                  tls11 = "DISABLED"
                  tls12 = "ENABLED"
                  }#sslprfbepayld
TRY {
    Invoke-Nitro -Method POST -Type sslprofile -Payload $sslprfbepayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Add SSL BackEnd Profile
CATCH {
      "$(Get-TimeStamp) FAILED ADD SSL BackEnd Profile " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Add SSL BackEnd Profile

#Bind SSL BackEnd Profile Cipher
"$(Get-TimeStamp) Bind SSL BackEnd Profile Cipher" | Out-File -filepath $logfile -Append -Encoding ascii
$sslcipbepayld = @{ }
$sslcipbepayld = @{
                  name = "aqr_default_ssl_profile_backend"
                  ciphername = "aqr-cipher-high_backend"
                  }#sslcipbepayld
TRY {
    Invoke-Nitro -Method PUT -Type sslprofile_sslcipher_binding -Payload $sslcipbepayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Add SSL BackEnd Profile
CATCH {
      "$(Get-TimeStamp) FAILED BIND SSL BackEnd Profile " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Add SSL BackEnd Profile

#UnBind SSL BackEnd Default Profile Cipher
"$(Get-TimeStamp) UnBind SSL Default BackEnd Profile Cipher" | Out-File -filepath $logfile -Append -Encoding ascii
$sslprfbeunbindURI = "http://"+$NEWNsip+"/nitro/v1/config/sslprofile_sslcipher_binding/aqr_default_ssl_profile_backend?args=ciphername:DEFAULT_BACKEND"
TRY {
     Invoke-RestMethod -Uri $sslprfbeunbindURI -Method DELETE -Credential $credential -ErrorAction Continue
     }#TRY Unbind BackEnd SSL Default
CATCH {
       "$(Get-TimeStamp) FAILED Unbind DEFAULT from BackEnd " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
       }#CATCH Unbind SSL BackEnd Default


#Add LDAP Authentication Action
"$(Get-TimeStamp) ADD LDAP Authentication Action" | Out-File -filepath $logfile -Append -Encoding ascii
$ldapactpayld = @{ }
$ldapactpayld = @{
                name = "ldap.foo.bar_authact"
                serverip = "10.31.44.104"
                serverport = "636"
                ldapbase = "dc=AQRCAPITAL,dc=com"
                ldapbinddn = "ns_ldap@foo.bar"
                ldapbinddnpassword = $ldappass
                ldaploginname = "sAMAccountName"
                groupattrname = "memberOf"
                subattributename = "cn"
                sectype = "SSL"
                ssonameattribute = "sAMAccountName"
                }#ldapactpayld
TRY {
    Invoke-Nitro -Method POST -Type authenticationldapaction -Payload $ldapactpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Add LDAP Action
CATCH {
      "$(Get-TimeStamp) FAILED ADD LDAP Action " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Add LDAP Action

#Add LDAP Authentication Policy
"$(Get-TimeStamp) ADD LDAP Authentication Policy" | Out-File -filepath $logfile -Append -Encoding ascii
$ldappolpayld = @{ }
$ldappolpayld = @{
                name = "ldap.foo.bar_authpol"
                rule = "ns_true"
                reqaction = "ldap.foo.bar_authact"
                }#ldappolpayld
TRY {
    Invoke-Nitro -Method POST -Type authenticationldappolicy -Payload $ldappolpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Add Audit Policy
CATCH {
      "$(Get-TimeStamp) FAILED ADD Audit Policy " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Add Audit Policy

#Add LDAP Authentication Action - Administration
"$(Get-TimeStamp) ADD LDAP Authentication Administration Action" | Out-File -filepath $logfile -Append -Encoding ascii
$ldapadapayld = @{ }
$ldapadapayld = @{
                name = "ldap.foo.bar_admin_authact"
                serverip = "10.31.44.104"
                serverport = "636"
                ldapbase = "dc=AQRCAPITAL,dc=com"
                ldapbinddn = "ns_ldap@foo.bar"
                ldapbinddnpassword = $ldappass
                ldaploginname = "sAMAccountName"
                groupattrname = "memberOf"
                subattributename = "cn"
                sectype = "SSL"
                ssonameattribute = "sAMAccountName"
                searchfilter = "&(|(memberof=CN=ENT_Netscaler_Admins,OU=Security,OU=AQR Groups,OU=AQR Users,DC=aqrcapital,DC=com)(memberof=CN=ENT_Netscaler_RO,OU=Security,OU=AQR Groups,OU=AQR Users,DC=aqrcapital,DC=com))"
                }#ldapadapayld
if($DMZ){
$ldapadapayld = @{
                name = "ldap.foo.bar_admin_authact"
                serverip = "10.31.44.104"
                serverport = "636"
                ldapbase = "dc=AQRCAPITAL,dc=com"
                ldapbinddn = "ns_ldap@foo.bar"
                ldapbinddnpassword = $ldappass
                ldaploginname = "sAMAccountName"
                groupattrname = "memberOf"
                subattributename = "cn"
                sectype = "SSL"
                ssonameattribute = "sAMAccountName"
                searchfilter = "&(|(memberof=CN=ENT_Netscaler_DMZ_Admins,OU=Security,OU=AQR Groups,OU=AQR Users,DC=aqrcapital,DC=com)(memberof=CN=ENT_Netscaler_DMZ_RO,OU=Security,OU=AQR Groups,OU=AQR Users,DC=aqrcapital,DC=com))"
                }#ldapadapayld
        }

TRY {
    Invoke-Nitro -Method POST -Type authenticationldapaction -Payload $ldapadapayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Add LDAP Action Administration
CATCH {
      "$(Get-TimeStamp) FAILED ADD LDAP Authentication Administration Action " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Add LDAP Action Administration

#Add LDAP Authentication Policy - Administration
"$(Get-TimeStamp) ADD LDAP Authentication Administration Policy" | Out-File -filepath $logfile -Append -Encoding ascii
$ldapadppayld = @{ }
$ldapadppayld = @{
                name = "ldap.foo.bar_admin_authpol"
                rule = "ns_true"
                reqaction = "ldap.foo.bar_admin_authact"
                }#ldapadppayld
TRY {
    Invoke-Nitro -Method POST -Type authenticationldappolicy -Payload $ldapadppayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Add LDAP Policy Administration
CATCH {
      "$(Get-TimeStamp) FAILED ADD LDAP Authentication Administration Policy " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Add LDAP Policy Adminstration

#Bind LDAP Admin Authentication Policy Globally
"$(Get-TimeStamp) BIND LDAP Authentication Administration Policy" | Out-File -filepath $logfile -Append -Encoding ascii
$ldapbndpayld = @{ }
$ldapbndpayld = @{
                policyname = "ldap.foo.bar_admin_authpol"
                priority = "100"
                }#ldapbndpayld
TRY {
    Invoke-Nitro -Method PUT -Type systemglobal_authenticationldappolicy_binding -Payload $ldapbndpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY LDAP System Global
CATCH {
      "$(Get-TimeStamp) FAILED BIND LDAP Authentication Administration Policy " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH LDAP System Global

#Add System Group ENT_Netscaler_Admins
"$(Get-TimeStamp) ADD System Group ENT_Netscaler_Admins" | Out-File -filepath $logfile -Append -Encoding ascii
$ldapgrppayld = @{ }
$ldapgrppayld = @{
                groupname = "ENT_Netscaler_Admins"
                promptstring = "%h %s"
                timeout = "600"
                }#ldapgrppayld
if($DMZ){
$ldapgrppayld = @{
                groupname = "ENT_Netscaler_DMZ_Admins"
                promptstring = "%h %s"
                timeout = "600"
                }#ldapgrppayld

        }
TRY {
    Invoke-Nitro -Method POST -Type systemgroup -Payload $ldapgrppayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Add LDAP Group
CATCH {
      "$(Get-TimeStamp) FAILED ADD System Group ENT_Netscaler_Admins " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Add LDAP Group

#Bind System Group ENT_Netscaler_Admins Policy
"$(Get-TimeStamp) BIND System Group ENT_Netscaler_Admins to SuperUser" | Out-File -filepath $logfile -Append -Encoding ascii
$ldapgrpsupayld = @{ }
$ldapgrpsupayld = @{
                groupname = "ENT_Netscaler_Admins"
                policyname = "superuser"
                priority = "100"
                }#ldapgrpsupayld
if($DMZ){
$ldapgrpsupayld = @{
                groupname = "ENT_Netscaler_DMZ_Admins"
                policyname = "superuser"
                priority = "100"
                }#ldapgrpsupayld
        }
TRY {
    Invoke-Nitro -Method PUT -Type systemgroup_systemcmdpolicy_binding -Payload $ldapgrpsupayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY BIND LDAP Group
CATCH {
      "$(Get-TimeStamp) FAILED BIND System Group ENT_Netscaler_Admins to SuperUser " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH BIND LDAP Group

#Change read-only System Command Policy
"$(Get-TimeStamp) Change read-only System Command Policy" | Out-File -filepath $logfile -Append -Encoding ascii
$cmdpolropayld = @{ }
$cmdpolropayld = @{
                policyname = "read-only"
                action = "ALLOW"
                cmdspec = "(^man.*)|(^show\s+(?!configstatus)(?!ns ns\.conf)(?!ns runningConfig)(?!gslb runningConfig)(?!audit messages)(?!techsupport).*)|(^stat.*)"
                }#cmdpolropayld
TRY {
    Invoke-Nitro -Method PUT -Type systemcmdpolicy -Payload $cmdpolropayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Change read-only cmd policy
CATCH {
      "$(Get-TimeStamp) FAILED Change read-only System Command Policy " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Change read-only cmd policy

#Add System Group ENT_Netscaler_RO
"$(Get-TimeStamp) ADD System Group ENT_Netscaler_RO" | Out-File -filepath $logfile -Append -Encoding ascii
$ldaprogrppayld = @{ }
$ldaprogrppayld = @{
                groupname = "ENT_Netscaler_RO"
                promptstring = "%h %s"
                timeout = "600"
                }#ldaprogrppayld
if($DMZ){
$ldaprogrppayld = @{
                groupname = "ENT_Netscaler_DMZ_RO"
                promptstring = "%h %s"
                timeout = "600"
                }#ldaprogrppayld

        }
TRY {
    Invoke-Nitro -Method POST -Type systemgroup -Payload $ldaprogrppayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Add LDAP RO Group
CATCH {
      "$(Get-TimeStamp) FAILED ADD System Group ENT_Netscaler_RO " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Add LDAP RO Group

#Bind System Group ENT_Netscaler_RO Policy
"$(Get-TimeStamp) BIND System Group ENT_Netscaler_RO to Read-Only" | Out-File -filepath $logfile -Append -Encoding ascii
$ldaprogrpsupayld = @{ }
$ldaprogrpsupayld = @{
                groupname = "ENT_Netscaler_RO"
                policyname = "read-only"
                priority = "100"
                }#ldaprogrpsupayld
if($DMZ){
$ldaprogrpsupayld = @{
                groupname = "ENT_Netscaler_DMZ_RO"
                policyname = "read-only"
                priority = "100"
                }#ldaprogrpsupayld
        }
TRY {
    Invoke-Nitro -Method PUT -Type systemgroup_systemcmdpolicy_binding -Payload $ldaprogrpsupayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY BIND LDAP RO Group
CATCH {
      "$(Get-TimeStamp) FAILED BIND System Group ENT_Netscaler_RO to Read-Only " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH BIND LDAP RO Group

#Add System User weblog
"$(Get-TimeStamp) ADD System User weblog" | Out-File -filepath $logfile -Append -Encoding ascii
$sysuserpayld = @{ }
$sysuserpayld = @{
                 username = "weblog"
                 password = $weblogpass
                 externalauth = "DISABLED"
                 logging = "ENABLED"
                }#sysuserpayld
TRY {
    Invoke-Nitro -Method POST -Type systemuser -Payload $sysuserpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Add weblog user
CATCH {
      "$(Get-TimeStamp) FAILED ADD System User weblog " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Add weblog user

#Bind System User weblog Policy
"$(Get-TimeStamp) BIND System User weblog to SuperUser" | Out-File -filepath $logfile -Append -Encoding ascii
$sysusersupayld = @{ }
$sysusersupayld = @{
                   username = "weblog"
                   policyname = "superuser"
                   priority = "100"
                   }#sysusersupayld
TRY {
    Invoke-Nitro -Method PUT -Type systemuser_systemcmdpolicy_binding -Payload $sysusersupayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY BIND weblog
CATCH {
      "$(Get-TimeStamp) FAILED BIND System User weblog to SuperUser " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH BIND weblog

#Copy wildcard certificates
"$(Get-TimeStamp) Copy Wildcard Certificates" | Out-File -filepath $logfile -Append -Encoding ascii
# Set up session options
$winscpsessionoption = New-WinSCPSessionOption -HostName $NEWNsip -Credential $credential -GiveUpSecurityAndAcceptAnySshHostKey

TRY {
    $winscpsession = New-WinSCPSession -SessionOption $winscpsessionoption 
    }#WinSCP Session Open
CATCH {
      "$(Get-TimeStamp) FAILED Copy Wildcard Certificates Session Open " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
}#CATCH WinSCP Session Open

TRY {
    Send-WinSCPItem -Path "\\foo.bar\shares\FS001\Citrix\Citrix\SSL\AQRCapital_Wildcard\*" -Destination "/flash/nsconfig/ssl/*" -WinSCPSession $winscpsession
}#TRY WinSCP Copy
CATCH {
      "$(Get-TimeStamp) FAILED Copy Wildcard Certificates Session Copy " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
}#CATCH WinSCP Copy


#Create SSL Certs and link them
"$(Get-TimeStamp) Create SSL Cert Wildcard" | Out-File -filepath $logfile -Append -Encoding ascii
$newsslwildpayld = @{ }
$newsslwildpayld = @{
                    certkey = "wildcard.foo.bar_exp2018"
                    cert = "wildcard.foo.bar.cer"
                    key = "wildcard.foo.bar.key"
                    expirymonitor = "ENABLED"
                    notificationperiod = "90"
                    }#newsslwildpayld
TRY {
    Invoke-Nitro -Method POST -Type sslcertkey -Payload $newsslwildpayld -OnErrorAction CONTINUE -Confirm -Force
       }#TRY SSL Wildcard
CATCH {
      "$(Get-TimeStamp) FAILED: Create SSL Cert Wildcard " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
}#CATCH SSL Wildcard


"$(Get-TimeStamp) Create SSL Cert Intermediate" | Out-File -filepath $logfile -Append -Encoding ascii
$newsslintrpayld = @{ }
$newsslintrpayld = @{
                    certkey = "foo.bar_issuing"
                    cert = "subca.foo.bar.cer"
                    expirymonitor = "ENABLED"
                    notificationperiod = "90"
                    }#newsslintrpayld
TRY {
    Invoke-Nitro -Method POST -Type sslcertkey -Payload $newsslintrpayld -OnErrorAction CONTINUE -Confirm -Force
       }#TRY SSL Intermediate
CATCH {
      "$(Get-TimeStamp) FAILED: Create SSL Cert Intermediate " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
}#CATCH SSL Intermediate


"$(Get-TimeStamp) Create SSL Cert Root" | Out-File -filepath $logfile -Append -Encoding ascii
$newsslrootpayld = @{ }
$newsslrootpayld = @{
                    certkey = "foo.bar_root"
                    cert = "root.foo.bar.cer"
                    expirymonitor = "ENABLED"
                    notificationperiod = "90"
                    }#newsslrootpayld
TRY {
    Invoke-Nitro -Method POST -Type sslcertkey -Payload $newsslrootpayld -OnErrorAction CONTINUE -Confirm -Force
       }#TRY SSL Root
CATCH {
      "$(Get-TimeStamp) FAILED: Create SSL Cert Root " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
}#CATCH SSL Root

"$(Get-TimeStamp) Link Wildcard to Intermediate" | Out-File -filepath $logfile -Append -Encoding ascii
$wildintrpayld = @{ }
$wildintrpayld = @{
                    certkey = "wildcard.foo.bar_exp2018"
                    linkcertkeyname = "foo.bar_issuing"
                    }#wildintrpayld
TRY {
    Invoke-Nitro -Method POST -Type sslcertkey -Payload $wildintrpayld -Action LINK -OnErrorAction CONTINUE -Confirm -Force
    }#TRY Link Wildcard to Intermediate
CATCH {
      "$(Get-TimeStamp) FAILED Link Wildcard to Intermediate " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
       }#CATCH Link Wildcard to Intermediate

"$(Get-TimeStamp) Link Intermediate to Root" | Out-File -filepath $logfile -Append -Encoding ascii
$intrrootpayld = @{ }
$intrrootpayld = @{
                    certkey = "foo.bar_issuing"
                    linkcertkeyname = "foo.bar_root"
                    }#intrrootpayld
TRY {
    Invoke-Nitro -Method POST -Type sslcertkey -Payload $intrrootpayld -Action LINK -OnErrorAction CONTINUE -Confirm -Force
    }#TRY Link Intermediate to Root
CATCH {
      "$(Get-TimeStamp) FAILED Link Intermediate to Root " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
       }#CATCH Link Intermediate to Root


#Bind SSL Cert to Internal Services
$svclist = @("nshttps-127.0.0.1-443","nshttps-$NEWSNIP-443","nshttps-::1l-443")

ForEach ($intsvc in $svclist) {
        "$(Get-TimeStamp) Set SSL Profile for " + $intsvc | Out-File -filepath $logfile -Append -Encoding ascii
        $newsslprfpayld = @{ }
        $newsslprfpayld = @{
                           servicename = $intsvc
                           sslprofile = "aqr_default_ssl_profile_frontend"
                           }#newsslprfpayld
           TRY {
          Invoke-Nitro -Method PUT -Type sslservice -Payload $newsslprfpayld -OnErrorAction CONTINUE -Confirm -Force
              }#TRY SSL Set Profile
           CATCH {
              "$(Get-TimeStamp) FAILED: Set SSL Profile for " + $intsvc + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
              }#CATCH SSL Set Profile

        "$(Get-TimeStamp) BIND SSL Cert to Internal Service " + $intsvc | Out-File -filepath $logfile -Append -Encoding ascii
        $intsvcsslpayld = @{ }
        $intsvcsslpayld = @{
                           servicename = $intsvc
                           certkeyname = "wildcard.foo.bar_exp2018"
                           }#intsvcsslpayld
        TRY {
            Invoke-Nitro -Method PUT -Type sslservice_sslcertkey_binding -Payload $intsvcsslpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
            }#TRY BIND LDAP Group
        CATCH {
              "$(Get-TimeStamp) FAILED BIND SSL Cert to Internal Service " + $intsvc + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
              }#CATCH BIND LDAP Group
}#ForEach intsvc

#Add HTTP-HTTPS Responder Server
"$(Get-TimeStamp) ADD LocalHost Server" | Out-File -filepath $logfile -Append -Encoding ascii
$redirsvrpayld = @{ }
$redirsvrpayld = @{
                 name = "LocalHost"
                 ipaddress = "1.2.3.4"
                 }#redirsvrpayld
TRY {
    Invoke-Nitro -Method POST -Type server -Payload $redirsvrpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Add Redir Server
CATCH {
      "$(Get-TimeStamp) FAILED ADD LocalHost Server " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Add Redir Server

#Add HTTP-HTTPS Responder Monitor
"$(Get-TimeStamp) ADD localping monitor" | Out-File -filepath $logfile -Append -Encoding ascii
$redirmonpayld = @{ }
$redirmonpayld = @{
                 monitorname = "localping"
                 type = "PING"
                 destip = "127.0.0.1"
                 }#redirmonpayld
TRY {
    Invoke-Nitro -Method POST -Type lbmonitor -Payload $redirmonpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Add Redir Monitor
CATCH {
      "$(Get-TimeStamp) FAILED ADD localping Monitor " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
     }#CATCH Add Redir Monitor

#Add HTTP-HTTPS Responder Service
"$(Get-TimeStamp) ADD http_to_https_dummy_vip_donotdelete Service" | Out-File -filepath $logfile -Append -Encoding ascii
$redirsvcpayld = @{ }
$redirsvcpayld = @{
                 name = "http_to_https_dummy_vip_donotdelete"
                 servername = "LocalHost"
                 servicetype = "HTTP"
                 port = "80"
                 }#redirsvcpayld
TRY {
    Invoke-Nitro -Method POST -Type service -Payload $redirsvcpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Add Redir Service
CATCH {
      "$(Get-TimeStamp) FAILED ADD http_to_https_dummy_vip_donotdelete Service " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
     }#CATCH Add Redir Service

#Bind HTTP-HTTPS Responder Monitor
"$(Get-TimeStamp) BIND Monitor localping to http_to_https_dummy_vip_donotdelete Service" | Out-File -filepath $logfile -Append -Encoding ascii
$redirmnbpayld = @{ }
$redirmnbpayld = @{
                 name = "http_to_https_dummy_vip_donotdelete"
                 monitor_name = "localping"
                 monstate = "ENABLED"
                 weight = "1"
                 }#redirmnbpayld
TRY {
    Invoke-Nitro -Method PUT -Type service_lbmonitor_binding -Payload $redirmnbpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Bind Redir Monitor
CATCH {
      "$(Get-TimeStamp) FAILED BIND Monitor localping to http_to_https_dummy_vip_donotdelete Service " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
     }#CATCH Add Redir Service

#Add HTTP-HTTPS Responder Action
"$(Get-TimeStamp) ADD default_http_to_https_responder_action Responder Action" | Out-File -filepath $logfile -Append -Encoding ascii
$rediractpayld = @{ }
$rediractpayld = @{
                 name = "default_http_to_https_responder_action"
                 type = "Redirect"
                 responsestatuscode = "301"
                 target = '"https://" + HTTP.REQ.HOSTNAME.HTTP_URL_SAFE + HTTP.REQ.URL.PATH_AND_QUERY.HTTP_URL_SAFE'
                 }#rediractpayld
TRY {
    Invoke-Nitro -Method POST -Type responderaction -Payload $rediractpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Add Resp action
CATCH {
      "$(Get-TimeStamp) FAILED ADD default_http_to_https_responder_action Responder Action " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
     }#CATCH Add Redir Action

#Add HTTP-HTTPS Responder Policy
"$(Get-TimeStamp) ADD default_http_to_https_responder_policy Responder Policy" | Out-File -filepath $logfile -Append -Encoding ascii
$redirpolpayld = @{ }
$redirpolpayld = @{
                 name = "default_http_to_https_responder_policy"
                 rule = "HTTP.REQ.IS_VALID"
                 action = "default_http_to_https_responder_action"
                 undefaction = "RESET"
                 }#redirpolpayld
TRY {
    Invoke-Nitro -Method POST -Type responderpolicy -Payload $redirpolpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Add Resp policy
CATCH {
      "$(Get-TimeStamp) FAILED ADD default_http_to_https_responder_policy Responder Policy " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
     }#CATCH Add Redir policy

#Set NSIP to Restrict Access
"$(Get-TimeStamp) SET NSIP to RestrictAccess" | Out-File -filepath $logfile -Append -Encoding ascii
$nsippayld = @{ }
$nsippayld = @{
                ipaddress = $NEWNsip
                restrictaccess = "ENABLED"
                gui = "SECUREONLY"
                }#nsippayld
TRY {
    Invoke-Nitro -Method PUT -Type nsip -Payload $nsippayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY NSIP
CATCH {
      "$(Get-TimeStamp) FAILED SET NSIP to RestrictAccess " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH NSIP

"$(Get-TimeStamp) *** END *** Script NetScaler_basic_setup for : " + $hostname | Out-File -filepath $logfile -Append -Encoding ascii


