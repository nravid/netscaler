
<#
SHOW NS

                          Name: test-yksdx01-ext-lb
                    IP Address: 10.80.36.91
                Instance State: Out of Service
                      VM State: Running
                            Id: 5e2aab8d08598e7c6792f326
#>

$credential = Get-Credential

$sdxaddr = "10.80.36.151"

Connect-NetScaler -IPAddress $sdxaddr -Credential $credential

$nsid = "5e2aab8d08598e7c6792f326"

$sdxgeturi = "http://"+$sdxaddr+"/nitro/v1/config/ns/"+$nsid
$sdxputuri = "http://"+$sdxaddr+"/nitro/v1/config/ns/"+$nsid

$nsadminprof = @{ }
$nsadminprof = ConvertTo-Json @{"ns" = @{
                "profile_name" = "nsroot_2021"
                "user_profile_name" = "nsroot_2021"
                }}#nsadminprof


$sdxgetprofile = Invoke-RestMethod -Uri $sdxgeturi -Method GET -Credential $credential -ErrorAction Continue

$sdxputprofile = Invoke-RestMethod -Uri $sdxputuri -Method PUT -Credential $credential -Body $nsadminprof


