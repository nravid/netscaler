


$dc = $null
$dclist = $null
$dclist = @("trm","grn")


ForEach ($dc in $dclist) {
    $dcinit = $null
    $dcinit = ($dc.Substring(0,1))

    $OLDNsip = $null
    $OLDNsip = 'n' + $dcinit + '0pnsint01.aqrcapital.com'

    Connect-NetScaler -Hostname $OLDNsip -Credential $Credential

$devvips = Get-NSLBVirtualServer | Where-Object {$_.name -like '*.dev.aqr*' } | select-object name | Sort-Object -Property name

foreach ($vip in $devvips) {
    $RestURI = "http://" + $OLDNsip + "/nitro/v1/stat/lbvserver?args=name:" + $vip.name
    $hitsrate = Invoke-RestMethod -Uri $RestURI -Credential $credential | select lbvserver -ExpandProperty lbvserver | select name,hitsrate,requestsrate,tothits
    Write-Host $hitsrate.name, $hitsrate.hitsrate, $hitsrate.requestsrate, $hitsrate.tothits
}#VIP

}#DC

