<#
    .SYNOPSIS
        Get an infoblox Host, A, CName, or PTR record
          
    .DESCRIPTION
        Get an infoblox Host, A, CName, or PTR record based on the criteria passed in. 

        This can run as a Module, as a Dot Source file, and Command line.

    .PARAMETER %PARAM%
        $Credential    - A PSCredential Object
        $RecordType    - Type of record (Host, A, CName, or PTR)
        $SearchText    - The text to search for
          
    .EXAMPLE
        Get-IbxRecord -Credential $Credential -RecordType Host -SearchText $ComputerName
        Get-IbxRecord -Credential $Credential -RecordType A -SearchText $ComputerName
        Get-IbxRecord -Credential $Credential -RecordType CName -SearchText $ComputerName
        Get-IbxRecord -Credential $Credential -RecordType PTR -SearchText $ComputerName

    .NOTES
        * Original Author         : Mike O'Rourke - Mike.ORourke@abc.com
        * Module Version Number   : 2.0
        * Date of Creation        : 3/22/2018
        * Date of Latest Update   : 5/22/2018
        * Latest Author           : 
        * Latest Build Version    : 
        * Comments                : 
        * Original Build Version  : 1.0, PSVersion 5.1.15063.966  
        * Build Version Details   :  
                                    ~ 2017.0615.01: * Template identifier (Do not Remove this flag)
                                                    * Updated the Global variables to be script / function specific.

    .LINK
         http://abcgit.foobar.com/orourkem/Powershell/blob/master/Get-IbxRecord.ps1

#>

##End Help Section##

Function Get-IbxRecord
{
    [CmdletBinding `
    (
        ConfirmImpact='None',#(High, Medium, Low, None)
        SupportsShouldProcess=$true, 
        HelpUri = ''
    )]
    Param 
    (
        
        [Parameter(Mandatory=$true,
                    ValueFromPipeline=$false,
                    ValueFromPipelineByPropertyName=$true,
                    Position=0)]
        [PSCredential] $Credential,

        [Parameter(Mandatory=$true,
                    ValueFromPipeline=$false,
                    ValueFromPipelineByPropertyName=$true,
                    Position=0)]
                    [ValidateSet("Host", "A", "CName", "PTR")]
        [string] $RecordType,

        [Parameter(Mandatory=$true,
                    ValueFromPipeline=$false,
                    ValueFromPipelineByPropertyName=$true,
                    Position=0)]
        [string] $SearchText

    )

#region -- Credential check
# Get the credentials if it was not passed in before
if (($Credential -eq "") -or ($Credential -eq $null)) {
    
    #$WriteHost = Write-Host $("`nPrompting for Credentials...") -ForegroundColor Yellow -BackgroundColor Black
    #$WriteHost

    $Credential = Get-Credential

    #$WriteHost = Write-Host $("`nCredentials set") -ForegroundColor Green -BackgroundColor Black
    #$WriteHost

} else {

    #$WriteHost = Write-Host $("`nCredentials were passed in, skipping...") -ForegroundColor Green -BackgroundColor Black
    #$WriteHost

}
#endregion

#region -- Static Variables
$InfobloxURLEndpoint = "https://ibxgridmaster.foobar.com/wapi/v2.5/"
#endregion

#region -- Get record ibx

# Check record type
if ($RecordType -eq "PTR") {

    #region -- PTR record
    #$WriteHost = Write-Host "`nRecord flag set to PTR" -ForegroundColor Cyan -BackgroundColor Black
    #$WriteHost

    $URL = $InfobloxURLEndpoint + "record:$($RecordType.ToLower())?ptrdname~=$($SearchText.ToLower())"
    $URL = $InfobloxURLEndpoint + "record:ptr?ptrdname~=$SearchText"

    try {
            
        # Clear the error so only fresh ones are recorded
        $Error.Clear()

        #$WriteHost = Write-Host "`nMaking Ibx web call" -ForegroundColor Cyan -BackgroundColor Black
        #$WriteHost

        # Ibx web call
        $Info = Invoke-WebRequest -Uri $URL -Credential $Credential

        #$WriteHost = Write-Host "`nIbx web call successful" -ForegroundColor Cyan -BackgroundColor Black
        #$WriteHost

    } catch {

    #$WriteHost = Write-Host "`nUnable to gather info: `n$Error" -ForegroundColor Red -BackgroundColor Black
    #$WriteHost 

    }

    # Make info readable
    $RecordInfo = ConvertFrom-Json -InputObject $Info.Content

    foreach ($Record in $RecordInfo) {
    
        #$WriteHost = Write-Host "`nptrdname: $($Record.ptrdname) `nview: $($Record.view) `n_ref: $($Record._ref)" -ForegroundColor Green -BackgroundColor Black
        #$WriteHost  

    }

    Return $RecordInfo

    #endregion

} elseif ($RecordType -eq "Host") {

    #region -- Host record
    #$WriteHost = Write-Host "`nRecord flag set to Host" -ForegroundColor Cyan -BackgroundColor Black
    #$WriteHost

    $URL = $InfobloxURLEndpoint + "record:$($RecordType.ToLower())?name~=$($SearchText.ToLower())"
    
    try {
            
        # Clear the error so only fresh ones are recorded
        $Error.Clear()

        #$WriteHost = Write-Host "`nMaking Ibx web call" -ForegroundColor Cyan -BackgroundColor Black
        #$WriteHost

        # Ibx web call
        $Info = Invoke-WebRequest -Uri $URL -Credential $Credential

        #$WriteHost = Write-Host "`nIbx web call successful" -ForegroundColor Cyan -BackgroundColor Black
        #$WriteHost

    } catch {

    #$WriteHost = Write-Host "`nUnable to gather info: `n$Error" -ForegroundColor Red -BackgroundColor Black
    #$WriteHost 

    }

    # Make info readable
    $RecordInfo = ConvertFrom-Json -InputObject $Info.Content

    foreach ($Record in $RecordInfo) {
    
        #$WriteHost = Write-Host "`nhost: $($Record.ipv4addrs.host) `nipv4addr: $($Record.ipv4addrs.ipv4addr) `nObject_ref: $($Record._ref) `n_ref: $($Record.ipv4addrs._ref) `nconfigure_for_dhcp: $($Record.ipv4addrs.configure_for_dhcp) " -ForegroundColor Green -BackgroundColor Black
        #$WriteHost  

    }

    Return $RecordInfo

    #endregion

} elseif ($RecordType -eq "A") {

    #region -- A record
    #$WriteHost = Write-Host "`nRecord flag set to A" -ForegroundColor Cyan -BackgroundColor Black
    #$WriteHost

    $URL = $InfobloxURLEndpoint + "record:$($RecordType.ToLower())?name~=$($SearchText.ToLower())"

    try {
            
        # Clear the error so only fresh ones are recorded
        $Error.Clear()

        #$WriteHost = Write-Host "`nMaking Ibx web call" -ForegroundColor Cyan -BackgroundColor Black
        #$WriteHost

        # Ibx web call
        $Info = Invoke-WebRequest -Uri $URL -Credential $Credential

        #$WriteHost = Write-Host "`nIbx web call successful" -ForegroundColor Cyan -BackgroundColor Black
        #$WriteHost

    } catch {

    #$WriteHost = Write-Host "`nUnable to gather info: `n$Error" -ForegroundColor Red -BackgroundColor Black
    #$WriteHost 

    }

    # Make info readable
    $RecordInfo = ConvertFrom-Json -InputObject $Info.Content

    foreach ($Record in $RecordInfo) {
    
        #$WriteHost = Write-Host "`nName: $($Record.name) `nCanonical: $($Record.ipv4addr) `nSite: $($Record.view)" -ForegroundColor Green -BackgroundColor Black
        #$WriteHost  

    }

    Return $RecordInfo

    #endregion

} elseif ($RecordType -eq "CName") {

    #region -- CName 

    #$WriteHost = Write-Host "`nRecord flag set to CName" -ForegroundColor Cyan -BackgroundColor Black
    #$WriteHost

    $URL = $InfobloxURLEndpoint + "record:$($RecordType.ToLower())?name~=$($SearchText.ToLower())"

    try {

        # Clear the error so only fresh ones are recorded
        $Error.Clear()

        #$WriteHost = Write-Host "`nMaking Ibx web call" -ForegroundColor Cyan -BackgroundColor Black
        #$WriteHost

        # Ibx web call
        $Info = Invoke-WebRequest -Uri $URL -Credential $Credential

        #$WriteHost = Write-Host "`nIbx web call successful" -ForegroundColor Cyan -BackgroundColor Black
        #$WriteHost

    } catch {

    #$WriteHost = Write-Host "`nUnable to gather info: `n$Error" -ForegroundColor Red -BackgroundColor Black
    #$WriteHost 

    }

    # Make info readable
    $RecordInfo = ConvertFrom-Json -InputObject $Info.Content

    foreach ($Record in $RecordInfo) {
    
        #$WriteHost = Write-Host "`nName: $($Record.name) `nCanonical: $($Record.canonical) `nSite: $($Record.view)" -ForegroundColor Green -BackgroundColor Black
        #$WriteHost  

    }

    Return $RecordInfo

    #endregion
}
#endregion

}

If
(
    -Not $($($($MyInvocation).Line -Split ($($MyInvocation).MyCommand,''))[0] -like '*. .*')
)
{
    $MyInvLineFunc = 'Get-IbxRecord'
    
    If
    (
        $MyInvocation.Line
    )
    {
        $MyInvLine = $MyInvocation.Line.Replace($MyInvocation.InvocationName,'@@')
        $MyInvLinePre = $($MyInvLine -split '@@')[0]
        $MyInvLinePost = $($MyInvLine -split '@@')[1].Split('|')[0]
    }
    
    $MyInvLineNewLine = $('{0}{1}{2}' -f $MyInvLinePre,$MyInvLineFunc,$MyInvLinePost)
    
    $ScriptBlock = [ScriptBlock]::Create($MyInvLineNewLine)
    Invoke-Command -ScriptBlock $ScriptBlock
} 
