

add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy


$AllProtocols = [System.Net.SecurityProtocolType]'Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

##### START OF FUNCTIONS #####

function Get-TimeStamp {
    return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
}



##### END OF FUNCTIONS #####


$logfile = $null
$logfile = "C:\Temp\Certbinding.txt"

"$(Get-TimeStamp) *** START *** Script sslcerts" | Out-File -filepath $logfile -Append -Encoding ascii



$admuri = $null
$admuri = "http://lab-adm-01.anoprop.com/nitro/v2/config/managed_device"
$admmethod = $null
$admmethod = "get"
$admdevices = $null
$Credential = $null
$Credential = Get-Credential


"$(Get-TimeStamp) Get ADM VPX and MPX" | Out-File -filepath $logfile -Append -Encoding ascii
TRY {
    $admdevices = Invoke-RestMethod -method $admmethod -uri $admuri -Credential $credential -ErrorAction Stop | select managed_device -ExpandProperty managed_device | select type, ip_address, name, instance_state, ha_master_state | Where-Object {($_.type -ne "nssdx") -and ($_.instance_state -eq "Up") -and ($_.ha_master_state -eq "Primary")}
    }#TRY ADM
CATCH {
       "$(Get-TimeStamp) FAILED Get ADM VPX and MPX" + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
      }#CATCH ADM


ForEach ($admnsip in $admdevices) {
    $vpxhostname = $null
"$(Get-TimeStamp) Get Hostname for: " + $admnsip.ip_address | Out-File -filepath $logfile -Append -Encoding ascii
TRY {
    $vpxhostname = Resolve-DnsName $admnsip.ip_address -ErrorAction Stop
        $ssladc += @($vpxhostname.NameHost)
    }#TRY Resolve DNS
CATCH {
"$(Get-TimeStamp) FAILED Get Hostname for: " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
}#CATCH Resolve DNS
}#ForEach admnsip

ForEach ($ssladchost in $ssladc) {

$nsip = $null
$nsip = $ssladchost

"$(Get-TimeStamp) Attempt Connect to: " + $ssladchost | Out-File -filepath $logfile -Append -Encoding ascii

    TRY {
        Connect-NetScaler -Hostname $nsip -Credential $Credential -Https

"$(Get-TimeStamp) Attempt Get SSL Certificates from: " + $nsip | Out-File -filepath $logfile -Append -Encoding ascii
TRY {
    $certkeys = Get-NSSSLCertificate | Where-Object {$_.sandns -ne $null} | select-object certkey, sandns, clientcertnotafter, status
    }#TRY Certkeys
CATCH {
    "$(Get-TimeStamp) FAILED Get SSL Certificates from: " + $nsip + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
    }#CATCH Certkeys


ForEach ($certname in $certkeys) {
        $certbind = $null
        $certbinduri = $null
        $certbinduri = "https://" + $nsip + "/nitro/v1/config/sslcertkey_binding/" + $certname.certkey

    "$(Get-TimeStamp) Attempt Get SSL bindings of " + $certname.certkey + " from: " + $nsip | Out-File -filepath $logfile -Append -Encoding ascii
    TRY {
        $certbind = Invoke-RestMethod -Method GET -uri $certbinduri -credential $credential -ErrorAction Continue
        IF ($certbind.sslcertkey_binding.sslcertkey_sslvserver_binding -ne $null) {
            ForEach ($certvserver in $certbind.sslcertkey_binding.sslcertkey_sslvserver_binding) {
                Write-Host $certvserver.certkey is bound to $certvserver.servername
            }#ForEach certvserver
        }#IF
        ELSE {
            Write-Host $certbind.sslcertkey_binding.certkey is not bound
        }#ELSE
           }#TRY GetSSL Cert Key Binding
    CATCH {
          "$(Get-TimeStamp) FAILED: Get SSL Cert Bindings " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
    }#CATCH SSL Binding


} #For Each certname


        }#TRY Connect-NetScaler
    CATCH {
          "$(Get-TimeStamp) FAILED Connect to ADC " + $nsip + " " + $_.Exception.Message | Out-File -filepath $logfile -Append -Encoding ascii
          }#CATCH Connect-NetScaler
}#ssladchost

"$(Get-TimeStamp) *** END *** Script sslcert" | Out-File -filepath $logfile -Append -Encoding ascii
