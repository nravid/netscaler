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
$credential = $null
$logfile = $null

$NEWNsip = Read-Host -Prompt "NSIP?"
$NEWSNIP = Read-Host -Prompt "SNIP?"
$netmask = Read-Host -Prompt "NetMask?"
$hostname = Read-Host -Prompt "Host Name?"
$ldappass = Read-Host -Prompt "Password for LDAP Service?"
$credential = Get-Credential

$ntpservers = $null
$dnsservers = $null
$snmpcomms = $null
$snmpmgrs = $null
$snmptraps = $null
$snmpalrms = $null
$ntpservers = @("10.30.4.32", "10.30.60.10")
$dnsservers = @("10.255.0.1", "10.255.0.2")
$snmpcomms = @("public", "zenoss")
$snmpmgrs = @("10.31.18.85", "st0pzenrn01.foobar.com", "st0pzenrn02.foobar.com", "st0pzenrn04.foobar.com")
$snmptraps = @("10.31.18.85", "10.31.102.103")
$snmpalrms = @("CONFIG-CHANGE", "CONFIG-SAVE", "ENTITY-STATE", "GSLB-SITE-MEP-FLAP", "HA-STICKY-PRIMARY", "LOGIN-FAILURE", "SSL-CERT-EXPIRY", "HA-SYNC-FAILURE", "HA-VERSION-MISMATCH", "HA-STATE-CHANGE", "HA-BAD-SECONDARY-STATE", "HA-NO-HEARTBEATS", "HARD-DISK-DRIVE-ERRORS")

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

#Set NSIP to Restrict Access
"$(Get-TimeStamp) SET NSIP to RestrictAccess" | Out-File -filepath $logfile -Append -Encoding ascii
$nsippayld = @{ }
$nsippayld = @{
              ipaddress = $NEWNsip
              restrictaccess = "ENABLED"
              }#nsippayld
TRY {
    Invoke-Nitro -Method PUT -Type nsip -Payload $nsippayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY NSIP
CATCH {
      "$(Get-TimeStamp) FAILED SET NSIP to RestrictAccess " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH NSIP

#Add SNIP
"$(Get-TimeStamp) ADD SNIP " + $NEWSNIP | Out-File -filepath $logfile -Append -Encoding ascii
$snippayld = @{ }
$snippayld = @{
              ipaddress = $NEWSNIP
              netmask = $netmask
              type = "SNIP"
              vserver = "DISABLED"
              mgmtaccess = "ENABLED"
              }#snippayld

TRY {
    Invoke-Nitro -Method POST -Type nsip -Payload $snippayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY SNIP
CATCH {
      "$(Get-TimeStamp) FAILED ADD SNIP " + $NEWSNIP + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH SNIP

#Set NTP

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

#Add DNS NameServers

"$(Get-TimeStamp) ADD DNS NameServers" | Out-File -filepath $logfile -Append -Encoding ascii

ForEach ($dns in $dnsservers){
    "$(Get-TimeStamp) Add DNS NameServer " + $dns | Out-File -filepath $logfile -Append -Encoding ascii
    $dnspayld = @{ }
    $dnspayld = @{
                 ip = $dns
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

		"$(Get-TimeStamp) SET SNMP Alarm " + $snmpu + " Critical" | Out-File -filepath $logfile -Append -Encoding ascii
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
}#SNMPCPU

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
                name = "abc_syslog_netprf"
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
                name = "abc_syslog_audact"
                serverip = "10.30.19.60"
                loglevel = "ALL"
                logfacility = "LOCAL3"
                timezone = "LOCAL_TIME"
                userdefinedauditlog = "YES"
                transport = "TCP"
                maxlogdatasizetohold = "50"
                netprofile = "abc_syslog_netprf"
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
                name = "abc_syslog_audpol"
                rule = "ns_true"
                action = "abc_syslog_audact"
                }#audpolpayld

TRY {
    Invoke-Nitro -Method POST -Type auditsyslogpolicy -Payload $audpolpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Add Audit Policy
CATCH {
      "$(Get-TimeStamp) FAILED ADD Audit Policy " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Add Audit Policy

#SSL Ciphers

"$(Get-TimeStamp) ADD SSL Ciphers" | Out-File -filepath $logfile -Append -Encoding ascii
$ciphers = @("abc-cipher-high_frontend", "abc-cipher-high_backend")
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



#Add LDAP Authentication Action

"$(Get-TimeStamp) ADD LDAP Authentication Action" | Out-File -filepath $logfile -Append -Encoding ascii
$ldapactpayld = @{ }
$ldapactpayld = @{
                 name = "ldap.foobar.com_authact"
                 serverip = "10.30.44.104"
                 serverport = "636"
                 ldapbase = "dc=foobar,dc=com"
                 ldapbinddn = "ns_ldap@foobar.com"
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
				  name = "ldap.foobar.com_authpol"
				  rule = "ns_true"
                  reqaction = "ldap.foobar.com_authact"
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
                 name = "ldap.foobar.com_admin_authact"
                 serverip = "10.30.44.104"
                 serverport = "636"
                 ldapbase = "dc=foobar,dc=com"
                 ldapbinddn = "ns_ldap@foobar.com"
                 ldapbinddnpassword = $ldappass
                 ldaploginname = "sAMAccountName"
                 groupattrname = "memberOf"
                 subattributename = "cn"
                 sectype = "SSL"
                 ssonameattribute = "sAMAccountName"
                 searchfilter = "&(|(memberof=CN=ENT_Netscaler_Admins,OU=Security,OU=abc Groups,OU=abc Users,DC=foobar,DC=com)(memberof=CN=ENT_Netscaler_RO,OU=Security,OU=abc Groups,OU=abc Users,DC=foobar,DC=com))"
                 }#ldapadapayld

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
                 name = "ldap.foobar.com_admin_authpol"
                 rule = "ns_true"
                 reqaction = "ldap.foobar.com_admin_authact"
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
                 policyname = "ldap.foobar.com_admin_authpol"
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

TRY {
    Invoke-Nitro -Method PUT -Type systemgroup_systemcmdpolicy_binding -Payload $ldapgrpsupayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY BIND LDAP Group
CATCH {
      "$(Get-TimeStamp) FAILED BIND System Group ENT_Netscaler_Admins to SuperUser " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH BIND LDAP Group

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
    Send-WinSCPItem -Path "\\foobar.com\shares\FS001\Citrix\Citrix\SSL\foobar_Wildcard\*" -Destination "/flash/nsconfig/ssl/*" -WinSCPSession $winscpsession
}#TRY WinSCP Copy

CATCH {
      "$(Get-TimeStamp) FAILED Copy Wildcard Certificates Session Copy " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
}#CATCH WinSCP Copy

#Bind SSL Cert to Internal Services

"$(Get-TimeStamp) BIND SSL Cert to Internal Services" | Out-File -filepath $logfile -Append -Encoding ascii
$svclist = @("nshttps-127.0.0.1-443","nshttps-" + $NEWSNIP + "-443","nshttps-::1l-443")
ForEach ($svc in $svclist) {
		$intsvcsslpayld = @{ }
		$intsvcsslpayld = @{
						   servicename = $svc
						   certkeyname = "wildcard.foobar.com_exp2018"
						   }#intsvcsslpayld

TRY {
    "$(Get-TimeStamp) BIND SSL Cert to Internal Service " + $svc | Out-File -filepath $logfile -Append -Encoding ascii
    Invoke-Nitro -Method PUT -Type systemgroup_systemcmdpolicy_binding -Payload $intsvcsslpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY BIND LDAP Group
CATCH {
      "$(Get-TimeStamp) FAILED BIND SSL Cert to Internal Service " + $svc + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH BIND LDAP Group
}#ForEach svc


"$(Get-TimeStamp) *** END *** Script NetScaler_basic_setup for : " + $hostname | Out-File -filepath $logfile -Append -Encoding ascii
 
