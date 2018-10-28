


function scanmonbinding {
     [CmdletBinding()]
    Param(
         [Parameter(Mandatory=$true)]
         [string]$nsipaddr
         )
    $AllProtocols = [System.Net.SecurityProtocolType]'Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

    $connected = $FALSE
    $output = @()
    TRY {
        Connect-NetScaler -Hostname $nsipaddr -Credential $Credential -HTTPS
        $connected = $TRUE
        }#TRY Connect HTTPS
    CATCH {
          $connected = $FALSE
          }#CATCH Connect HTTPS

    IF (!$connected) {
        TRY {
            Connect-NetScaler -Hostname $nsipaddr -Credential $Credential
            $connected = $TRUE
            }#TRY Connect HTTP
        CATCH {
              $connected = $FALSE
              }#CATCH Connect HTTP
    }#IF

    IF ($connected) {
        $monitorname = "tcp-default"
        $monbind = Invoke-Nitro -Method GET -Type lbmonbindings_servicegroup_binding -Resource $monitorname -Confirm -Force -ErrorAction Continue -OnErrorAction CONTINUE
        ForEach ($sgbound in $monbind.lbmonbindings_servicegroup_binding) {
                $sgobj = New-Object -TypeName PSObject
                Add-Member -InputObject $sgobj -MemberType NoteProperty -Name VPX -Value $nsipaddr
                Add-Member -InputObject $sgobj -MemberType NoteProperty -Name Name -Value $sgbound.monitorname
                Add-Member -InputObject $sgobj -MemberType NoteProperty -Name SvcGrp -Value $sgbound.servicegroupname
                Add-Member -InputObject $sgobj -MemberType NoteProperty -Name SvcType -Value $sgbound.servicetype
                $output +=  $sgobj
        }#For each servicegroup
    }#IF
    return $output
}#function scanmonbinding


$credential = Get-Credential

$nmasdevices = Invoke-RestMethod -uri "https://nt0pctxmas01.aqrcapital.com/nitro/v2/config/managed_device" -Credential $credential | select managed_device -ExpandProperty managed_device | select type, ip_address, instance_state, ha_master_state | Where-Object {($_.type -eq "nsvpx") -and ($_.instance_state -eq "Up") -and ($_.ha_master_state -eq "Primary")}

$report = @()

ForEach ($nsip in $nmasdevices) {
    TRY {
        $fqdn = Resolve-DnsName $nsip.ip_address
        $report += scanmonbinding $fqdn.namehost
    }#TRY DNS Resolve
    CATCH {
          $report += scanmonbinding $nsip.ip_address
          #scanmonbinding $nsip
    }#CATCH DNS Resolve
} #ForEach nsip

Function Set-AlternatingRows {
	<#
	.SYNOPSIS
		Simple function to alternate the row colors in an HTML table
	.DESCRIPTION
		This function accepts pipeline input from ConvertTo-HTML or any
		string with HTML in it.  It will then search for <tr> and replace 
		it with <tr class=(something)>.  With the combination of CSS it
		can set alternating colors on table rows.
		
		CSS requirements:
		.odd  { background-color:#ffffff; }
		.even { background-color:#dddddd; }
		
		Classnames can be anything and are configurable when executing the
		function.  Colors can, of course, be set to your preference.
		
		This function does not add CSS to your report, so you must provide
		the style sheet, typically part of the ConvertTo-HTML cmdlet using
		the -Head parameter.
	.PARAMETER Line
		String containing the HTML line, typically piped in through the
		pipeline.
	.PARAMETER CSSEvenClass
		Define which CSS class is your "even" row and color.
	.PARAMETER CSSOddClass
		Define which CSS class is your "odd" row and color.
	.EXAMPLE $Report | ConvertTo-HTML -Head $Header | Set-AlternateRows -CSSEvenClass even -CSSOddClass odd | Out-File HTMLReport.html
	
		$Header can be defined with a here-string as:
		$Header = @"
		<style>
		TABLE {border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}
		TH {border-width: 1px;padding: 3px;border-style: solid;border-color: black;background-color: #6495ED;}
		TD {border-width: 1px;padding: 3px;border-style: solid;border-color: black;}
		.odd  { background-color:#ffffff; }
		.even { background-color:#dddddd; }
		</style>
		"@
		
		This will produce a table with alternating white and grey rows.  Custom CSS
		is defined in the $Header string and included with the table thanks to the -Head
		parameter in ConvertTo-HTML.
	.NOTES
		Author:         Martin Pugh
		Twitter:        @thesurlyadm1n
		Spiceworks:     Martin9700
		Blog:           www.thesurlyadmin.com
		
		Changelog:
			1.1         Modified replace to include the <td> tag, as it was changing the class
                        for the TH row as well.
            1.0         Initial function release
	.LINK
		http://community.spiceworks.com/scripts/show/1745-set-alternatingrows-function-modify-your-html-table-to-have-alternating-row-colors
    .LINK
        http://thesurlyadmin.com/2013/01/21/how-to-create-html-reports/
	#>
    [CmdletBinding()]
   	Param(
       	[Parameter(Mandatory,ValueFromPipeline)]
        [string]$Line,
       
   	    [Parameter(Mandatory)]
       	[string]$CSSEvenClass,
       
        [Parameter(Mandatory)]
   	    [string]$CSSOddClass
   	)
	Begin {
		$ClassName = $CSSEvenClass
	}
	Process {
		If ($Line.Contains("<tr><td>"))
		{	$Line = $Line.Replace("<tr>","<tr class=""$ClassName"">")
			If ($ClassName -eq $CSSEvenClass)
			{	$ClassName = $CSSOddClass
			}
			Else
			{	$ClassName = $CSSEvenClass
			}
		}
		Return $Line
	}
}

#Found on Spiceworks: https://community.spiceworks.com/scripts/show/1745-set-alternatingrows-function-modify-your-html-table-to-have-alternating-row-colors?utm_source=copy_paste&utm_campaign=growth

$rpthdr = @"
<style>
TABLE {border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}
TH {border-width: 1px;padding: 3px;border-style: solid;border-color: black;background-color: #6495ED;}
TD {border-width: 1px;padding: 3px;border-style: solid;border-color: black;}
.odd  { background-color:#ffffff; }
.even { background-color:#dddddd; }
</style>
<title>
Service Groups with no Monitor
</title>
"@
$rpttitle = "Service Groups with no Monitor"
$rptpre = "<H1>Service Groups with no Monitor - Count: " + $report.count + "</H1>"
$rptpst = "*** End of Report ***"

$report | Sort-Object -Property nsip | ConvertTo-Html -Title $rpttitle -Head $rpthdr -PreContent $rptpre -PostContent $rptpst | Set-AlternatingRows -CSSEvenClass even -CSSOddClass odd | Out-File H:\sgmonbinding.html

