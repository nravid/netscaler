
$admcred = Get-Credential
$admip="192.168.137.25"

$admgetipblockuri = "http://"+$admip+"/nitro/v1/config/ip_block?onerror=continue"

$admipblock2 = @{"ip_block" = 
    @{
     "name" = 'Test2'
     "start_ip" = '192.168.1.200' 
     "end_ip" = '192.168.1.210'
     "country" = 'United States' 
     "region" = 'Florida'
     "city" = 'Miami'
      }} | ConvertTo-Json
$admipjson2 = 'object=' + $admipblock2




$admipblock = @{"ip_block" = 
    @{
     "custom_city" = $false
     "country_code" = 'US'
     "end_ip" = '192.168.1.110'
     "latitude" = 30.36 
     "start_ip_num" = 3232235876
     "id" = 'Test'
     "longitude" = -81.43
     "custom_region" = $false
     "end_ip_num" = 3232235886
     "region_code" = 'FL'
     "region" = 'Florida'
     "name" = 'Test'
     "description" = '' 
     "city" = 'Atlantic Beach'
     "country" = 'United States' 
     "start_ip" = '192.168.1.100' 
     "custom_country" = $false 
      }} | ConvertTo-Json
$admipjson = 'object=' + $admipblock



$result =  Invoke-RestMethod -Uri $admgetipblockuri -Credential $admcred -Body $admipjson2 -Method Post -ContentType 'application/json'




