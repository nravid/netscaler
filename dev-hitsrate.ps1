


$dc = $null
$dclist = $null
$dclist = @("trm","grn")


ForEach ($dc in $dclist) {
    $dcinit = $null
    $dcinit = ($dc.Substring(0,1))

    $OLDNsip = $null
    $OLDNsip = 'n' + $dcinit + '0pnsint01.foo.bar'

    Connect-NetScaler -Hostname $OLDNsip -Credential $Credential

$devvips = Get-NSLBVirtualServer | Where-Object {$_.name -like '*.qa1.aqrcap*' } | select-object name | Sort-Object -Property name

foreach ($vip in $devvips) {
    $RestURI = "http://" + $OLDNsip + "/nitro/v1/stat/lbvserver?args=name:" + $vip.name
    TRY {
        $hitsrate = Invoke-RestMethod -Uri $RestURI -Credential $credential | select lbvserver -ExpandProperty lbvserver | select name,hitsrate,requestsrate,tothits
        IF ($hitsrate.tothits -gt 0) {
           Write-Host $hitsrate.name, $hitsrate.hitsrate, $hitsrate.requestsrate, $hitsrate.tothits
        }
        }#TRY REST CALL
    CATCH {
          Write-Host $vip.name $_.Exception.Message 
          }# CATCH REST CALL
    Start-Sleep -Milliseconds 750
}#ForEach VIP

}#ForEach DC

