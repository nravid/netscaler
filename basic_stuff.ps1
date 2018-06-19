
*** For-each


$files = Get-ChildItem D:\vmware

ForEach ($name in $files) {echo $name.name}


Get-ChildItem H:\NS-Migration | ForEach-Object -Process {echo $_.name}
Get-ChildItem H:\NS-Migration | % -Process {echo $_.name}


*** If-Then

if (1 -gt 0) {Write-Host "Yes"} else {Write-Host "No"}




