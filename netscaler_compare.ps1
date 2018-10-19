

$BigTRMsession = Connect-NetScaler -Credential $adm -Hostname "nt0pnsint.aqrcapital.com" -Https -PassThru
$SmallTRMsession = Connect-NetScaler -Credential $adm -Hostname "nt0pnsinty.aqrcapital.com" -Https -PassThru
$BigGRNsession = Connect-NetScaler -Credential $adm -Hostname "ng0pnsint.aqrcapital.com" -Https -PassThru
$SmallGRNsession = Connect-NetScaler -Credential $adm -Hostname "ng0pnsinty.aqrcapital.com" -Https -PassThru

Function CheckNetScalers($session1, $session2){
    Write-Host "Checking number of GSLB Domains with prd.int.aqrcapital.com"
    $GSLBDomain1 = Invoke-Nitro -Method GET -Type gslbdomain -Action getall -Session $session1
    $countwithinDomain1 = $GSLBDomain1.gslbdomain | ? {$_.name -like "*prd.int.aqrcapital.com"}
    "" + $session1.Endpoint + " contains " + $countwithinDomain1.count

    $GSLBDomain2 = Invoke-Nitro -Method GET -Type gslbdomain -Action getall -Session $session2
    $countwithinDomain2 = $GSLBDomain2.gslbdomain | ? {$_.name -like "*prd.int.aqrcapital.com"}
    "" + $session2.Endpoint + " contains " + $countwithinDomain2.count

    Compare-Object -ReferenceObject $countwithinDomain1.name -DifferenceObject $countwithinDomain2.name
}

CheckNetScalers $BigTRMsession $SmallTRMsession
CheckNetScalers $BigGRNsession $SmallGRNsession

