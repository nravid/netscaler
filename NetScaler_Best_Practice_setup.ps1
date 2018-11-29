
<#
Best Practices setup for all new NetScaler VPXs as per CTX121149
https://support.citrix.com/article/CTX121149
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
$credential = $null
$logfile = $null

$NEWNsip = Read-Host -Prompt "NSIP?"
$netmask = Read-Host -Prompt "NetMask?"
$hostname = Read-Host -Prompt "Host Name?"
$credential = Get-Credential

$subnet = $null
$octets = $NewNsip.split('.')
$octets[3] = $null
$subnet = $octets -join '.'
$NEWSNIP = $subnet + "20"

$logfile = "C:\Temp\" + $hostname + "-initial-CTX121149.txt"

"$(Get-TimeStamp) *** START *** Script NetScaler_Best_Practice_setup for : " + $hostname | Out-File -filepath $logfile -Append -Encoding ascii

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
                mode = "FR L3 TCPB Edge USNIP PMTUD MBF"
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

#Set Cookie Version
"$(Get-TimeStamp) SET Cookie Version to v1" | Out-File -filepath $logfile -Append -Encoding ascii
$cookverpayld = @{ }
$cookverpayld = @{
                 cookieversion = "1"
                 }#cookverpayld
TRY {
    Invoke-Nitro -Method PUT -Type nsconfig -Payload $cookverpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Set Cookie Version
CATCH {
      "$(Get-TimeStamp) FAILED Cookie Version " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Cookie Version

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
                 thresholdvalue = "95"
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

#SSL Ciphers
"$(Get-TimeStamp) ADD SSL Ciphers" | Out-File -filepath $logfile -Append -Encoding ascii
$ciphers = @("ssl_cipher_high_frontend", "ssl_cipher_high_backend")
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
                  name = "ssl_default_ssl_profile_frontend"
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
"$(Get-TimeStamp) Bind SSL FrontEnd ns_default Profile to high Cipher" | Out-File -filepath $logfile -Append -Encoding ascii
$sslnscipfepayld = @{ }
$sslnscipfepayld = @{
                  name = "ns_default_ssl_profile_frontend"
                  ciphername = "ssl_cipher_high_frontend"
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
$sslprffeunbindURI = "http://"+$NEWNsip+"/nitro/v1/config/sslprofile_sslcipher_binding/ssl_default_ssl_profile_frontend?args=ciphername:DEFAULT"
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
                  name = "ssl_default_ssl_profile_backend"
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
                  name = "ssl_default_ssl_profile_backend"
                  ciphername = "ssl_cipher_high_backend"
                  }#sslcipbepayld
TRY {
    Invoke-Nitro -Method PUT -Type sslprofile_sslcipher_binding -Payload $sslcipbepayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Add SSL BackEnd Profile
CATCH {
      "$(Get-TimeStamp) FAILED BIND SSL BackEnd Profile " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Add SSL BackEnd Profile

#UnBind SSL BackEnd Default Profile Cipher
"$(Get-TimeStamp) UnBind SSL Default BackEnd Profile Cipher" | Out-File -filepath $logfile -Append -Encoding ascii
$sslprfbeunbindURI = "http://"+$NEWNsip+"/nitro/v1/config/sslprofile_sslcipher_binding/ssl_default_ssl_profile_backend?args=ciphername:DEFAULT_BACKEND"
TRY {
     Invoke-RestMethod -Uri $sslprfbeunbindURI -Method DELETE -Credential $credential -ErrorAction Continue
     }#TRY Unbind BackEnd SSL Default
CATCH {
       "$(Get-TimeStamp) FAILED Unbind DEFAULT from BackEnd " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
       }#CATCH Unbind SSL BackEnd Default

#Add HTTP-HTTPS Responder Server
"$(Get-TimeStamp) ADD localhost_srv Server" | Out-File -filepath $logfile -Append -Encoding ascii
$redirsvrpayld = @{ }
$redirsvrpayld = @{
                 name = "localhost_srv"
                 ipaddress = "1.2.3.4"
                 }#redirsvrpayld
TRY {
    Invoke-Nitro -Method POST -Type server -Payload $redirsvrpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Add Redir Server
CATCH {
      "$(Get-TimeStamp) FAILED ADD localhost_srv Server " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH Add Redir Server

#Add HTTP-HTTPS Responder Monitor
"$(Get-TimeStamp) ADD localhost_ping_mon monitor" | Out-File -filepath $logfile -Append -Encoding ascii
$redirmonpayld = @{ }
$redirmonpayld = @{
                 monitorname = "localhost_ping_mon"
                 type = "PING"
                 destip = "127.0.0.1"
                 }#redirmonpayld
TRY {
    Invoke-Nitro -Method POST -Type lbmonitor -Payload $redirmonpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Add Redir Monitor
CATCH {
      "$(Get-TimeStamp) FAILED ADD localhost_ping_mon Monitor " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
     }#CATCH Add Redir Monitor

#Add HTTP-HTTPS Responder Service
"$(Get-TimeStamp) ADD http_to_https_dummy_svc_donotdelete Service" | Out-File -filepath $logfile -Append -Encoding ascii
$redirsvcpayld = @{ }
$redirsvcpayld = @{
                 name = "http_to_https_dummy_svc_donotdelete"
                 servername = "localhost_srv"
                 servicetype = "HTTP"
                 port = "80"
                 }#redirsvcpayld
TRY {
    Invoke-Nitro -Method POST -Type service -Payload $redirsvcpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Add Redir Service
CATCH {
      "$(Get-TimeStamp) FAILED ADD http_to_https_dummy_svc_donotdelete Service " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
     }#CATCH Add Redir Service

#Bind HTTP-HTTPS Responder Monitor
"$(Get-TimeStamp) BIND Monitor localhost_ping_mon to http_to_https_dummy_svc_donotdelete Service" | Out-File -filepath $logfile -Append -Encoding ascii
$redirmnbpayld = @{ }
$redirmnbpayld = @{
                 name = "http_to_https_dummy_svc_donotdelete"
                 monitor_name = "localhost_ping_mon"
                 monstate = "ENABLED"
                 weight = "1"
                 }#redirmnbpayld
TRY {
    Invoke-Nitro -Method PUT -Type service_lbmonitor_binding -Payload $redirmnbpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Bind Redir Monitor
CATCH {
      "$(Get-TimeStamp) FAILED BIND Monitor localhost_ping_mon to http_to_https_dummy_svc_donotdelete Service " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
     }#CATCH Add Redir Service

#Add HTTP-HTTPS Responder Action
"$(Get-TimeStamp) ADD http_to_https_rsp_act Responder Action" | Out-File -filepath $logfile -Append -Encoding ascii
$rediractpayld = @{ }
$rediractpayld = @{
                 name = "http_to_https_rsp_act"
                 type = "Redirect"
                 responsestatuscode = "301"
                 target = '"https://" + HTTP.REQ.HOSTNAME.HTTP_URL_SAFE + HTTP.REQ.URL.PATH_AND_QUERY.HTTP_URL_SAFE'
                 }#rediractpayld
TRY {
    Invoke-Nitro -Method POST -Type responderaction -Payload $rediractpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Add Resp action
CATCH {
      "$(Get-TimeStamp) FAILED ADD http_to_https_rsp_act Responder Action " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
     }#CATCH Add Redir Action

#Add HTTP-HTTPS Responder Policy
"$(Get-TimeStamp) ADD http_to_https_rsp_pol Responder Policy" | Out-File -filepath $logfile -Append -Encoding ascii
$redirpolpayld = @{ }
$redirpolpayld = @{
                 name = "http_to_https_rsp_pol"
                 rule = "HTTP.REQ.IS_VALID"
                 action = "http_to_https_rsp_act"
                 undefaction = "RESET"
                 }#redirpolpayld
TRY {
    Invoke-Nitro -Method POST -Type responderpolicy -Payload $redirpolpayld -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
    }#TRY Add Resp policy
CATCH {
      "$(Get-TimeStamp) FAILED ADD http_to_https_rsp_pol Responder Policy " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
     }#CATCH Add Redir policy

"$(Get-TimeStamp) Save Configuration on " + $NEWNsip | Out-File -filepath $logfile -Append -Encoding ascii

Save-NSConfig

"$(Get-TimeStamp) Restart NetScaler " + $NEWNsip | Out-File -filepath $logfile -Append -Encoding ascii

Restart-NetScaler -WarmReboot -Confirm -Force -ErrorAction Continue

"$(Get-TimeStamp) *** END *** Script NetScaler_Best_Practice_setup for : " + $hostname | Out-File -filepath $logfile -Append -Encoding ascii
