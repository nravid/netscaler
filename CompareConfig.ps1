
$Credential = Get-Credential


$Nsip = 'nt0dnsinty.foo.bar'
Connect-NetScaler -Hostname $Nsip -Credential $Credential -Https
$trmbefore = Get-NSConfig

Disconnect-NetScaler


$Nsip = 'ng0dnsinty.foo.bar'
Connect-NetScaler -Hostname $Nsip -Credential $Credential -Https
$grnbefore = Get-NSConfig

Disconnect-NetScaler


Read-Host "Press Enter to Continue..." | Out-Null

$Nsip = 'nt0dnsinty.foo.bar'
Connect-NetScaler -Hostname $Nsip -Credential $Credential -Https
$trmafter = Get-NSConfig

Disconnect-NetScaler


$Nsip = 'ng0dnsinty.foo.bar'
Connect-NetScaler -Hostname $Nsip -Credential $Credential
$grnafter = Get-NSConfig

Disconnect-NetScaler


$trmcomp = Compare-Object $trmbefore $trmafter

$grncomp = Compare-Object $grnbefore $grnafter

