
*** TRM OLD ***
$Nsip = 'nt0pnsint01.aqrcapital.com'
$Credential = Get-Credential
Connect-NetScaler -Hostname $Nsip -Credential $Credential



*** GRN OLD ***
$Nsip = 'ng0pnsint01.aqrcapital.com'
$Credential = Get-Credential
Connect-NetScaler -Hostname $Nsip -Credential $Credential


$devlist = import-csv -Path H:\NS-Migration\devipnumber.csv

ForEach ($vip in $devlist){

    $lbvsname = $null
    $lbvsnewip = $null
    $pos = $null
    $fqdn = $null
    $oldgslb = $null
    $gslbsvcname = $null

    $lbvsname = $vip.name
    $lbvsnewip = $vip.newip
    
    $pos = $lbvsname.IndexOf("_")
    $fqdn = $lbvsname.Substring(0, $pos)
    $dc = $lbvsname.Substring($lbvsname.Length - 3, 3)
    
    $gslbsvcname = $fqdn + "_gslb_svc_" + $dc

    Write-Host $gslbsvcname
    try {
        $oldgslb = Invoke-Nitro -Method GET -Type gslbservice -Resource $gslbsvcname -OnErrorAction CONTINUE -Confirm -Force | select -expand gslbservice | Export-Csv -NoTypeInformation H:\NS-Migration\old-dev-gslb.csv -Append
        try {
            Invoke-Nitro -Method DELETE -Type gslbservice -Resource $gslbsvcname -OnErrorAction CONTINUE -Confirm -Force
        }
        catch {
            Write-Host $gslbsvcname "NOT deleted..."
        }
    }
    catch {
        Write-Host $gslbsvcname "error..."
    }
            
}



