
*** TRM ***
$Nsip = 'nt0dnsinty01.foobar.com'
$Credential = Get-Credential
Connect-NetScaler -Hostname $Nsip -Credential $Credential -HTTPS



*** GRN ***
$Nsip = 'ng0dnsinty01.foobar.com'
$Credential = Get-Credential
Connect-NetScaler -Hostname $Nsip -Credential $Credential -HTTPS


$devlist = import-csv -Path H:\NS-Migration\devipnumbertest.csv

ForEach ($vip in $devlist){

    $lbvsname = $null
    $lbvsnewip = $null
    $hashtbl = $null
    $payld = $null

    $lbvsname = $vip.name
    $lbvsnewip = $vip.newip
    $hashtbl = @{ }
    $hashtbl.Set_Item("name",$lbvsname) 
    $hashtbl.Set_Item("ipv46",$lbvsnewip) 
    $payld = $hashtbl

    Write-Host $lbvsname, $lbvsnewip
    Invoke-Nitro -Method PUT -Type lbvserver -Resource $lbvsname -OnErrorAction CONTINUE -Confirm -Force -Payload $payld


}



$hashtbl = $null
$hashtbl = @{ }
$hashtbl.Set_Item("name",$lbvsname) 
$hashtbl.Set_Item("ipv46",$lbvsnewip) 




$payld = $hashtbl

Set-NSLBVirtualServer -Name $lbvsname -IPAddress $lbvsnewip -Confirm -Force -ErrorAction SilentlyContinue 
Invoke-Nitro -Method PUT -Type lbvserver -Resource $lbvsname -OnErrorAction CONTINUE -Confirm -Force -Payload $payld
