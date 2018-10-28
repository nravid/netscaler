

$BigTRMsession = Connect-NetScaler -Credential $credential -Hostname "nt0pnsint.foo.bar" -Https -PassThru
$SmallTRMsession = Connect-NetScaler -Credential $credential -Hostname "nt0pnsinty.foo.bar" -Https -PassThru
$BigGRNsession = Connect-NetScaler -Credential $credential -Hostname "ng0pnsint.foo.bar" -Https -PassThru
$SmallGRNsession = Connect-NetScaler -Credential $credential -Hostname "ng0pnsinty.foo.bar" -Https -PassThru

Function CheckNetScalers($session1, $session2){
    Write-Host "Checking number of GSLB Domains with prd.int.foo.bar"
    $GSLBDomain1 = Invoke-Nitro -Method GET -Type gslbdomain -Action getall -Session $session1
    $countwithinDomain1 = $GSLBDomain1.gslbdomain | ? {$_.name -like "*prd.int.foo.bar"}
    "" + $session1.Endpoint + " contains " + $countwithinDomain1.count

    $GSLBDomain2 = Invoke-Nitro -Method GET -Type gslbdomain -Action getall -Session $session2
    $countwithinDomain2 = $GSLBDomain2.gslbdomain | ? {$_.name -like "*prd.int.foo.bar"}
    "" + $session2.Endpoint + " contains " + $countwithinDomain2.count

    Compare-Object -ReferenceObject $countwithinDomain1.name -DifferenceObject $countwithinDomain2.name
}

CheckNetScalers $BigTRMsession $SmallTRMsession
CheckNetScalers $BigGRNsession $SmallGRNsession

