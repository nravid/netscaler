<#
    .SYNOPSIS
        Create an infoblox Host, A, CName, PTR record
          
    .DESCRIPTION
        Create an infoblox Host, A, CName, PTR record based on the criteria passed in. 
        This script requires Get-IbxRecord to function
            - Found Here: http://aqrgit.aqrcapital.com/orourkem/Powershell/blob/master/Get-IbxRecord.ps1
    .PARAMETER %PARAM%
        $Credential    - A PSCredential Object
        $RecordType    - Type of record (A or CName)
        $ComputerName  - The hostname of the computer for the record
        $IPv4Address   - The IPv4 address of the computer (A Record Only)
        $Canonical     - The canonical name of the CName record 
        $Domain        - The Domain to create the record in
        $Force         - Skips the check portion of the script
          
    .EXAMPLE
    .NOTES
        * Original Author         : Mike O'Rourke - Mike.ORourke@aqr.com
        * Module Version Number   : 1.0
        * Date of Creation        : 3/22/2018
        * Date of Latest Update   : 3/22/2018
        * Latest Author           : 
        * Latest Build Version    : 
        * Comments                : 
        * Original Build Version  : 1.0, PSVersion 5.1.15063.966  
        * Build Version Details   :  
                                    ~ 2017.0615.01: * Template identifier (Do not Remove this flag)
                                                    * Updated the Global variables to be script / function specific.
    .LINK
         http://aqrgit.aqrcapital.com/orourkem/Powershell/blob/master/Create-IbxRecord.ps1
#>

##End Help Section##

Function Create-IbxRecord
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
        [string] $ComputerName,

        [Parameter(Mandatory=$true,
                    ValueFromPipeline=$false,
                    ValueFromPipelineByPropertyName=$true,
                    Position=0)]
                    [ValidateSet(".aqrcapital.com", ".aqr.com", ".aqrcapital.dmz")]
        [string] $Domain,

        [Parameter(Mandatory=$false,
                    ValueFromPipeline=$false,
                    ValueFromPipelineByPropertyName=$true,
                    Position=0)]
        [string] $IPv4Address,

        [Parameter(Mandatory=$false,
                    ValueFromPipeline=$false,
                    ValueFromPipelineByPropertyName=$true,
                    Position=0)]
        [string] $Canonical,

        [Parameter(Mandatory=$false,
                    ValueFromPipeline=$false,
                    ValueFromPipelineByPropertyName=$true,
                    Position=0)]
                    [ValidateSet("Force")]
        [string] $Force

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
$InfobloxURLEndpoint = "https://ibxgridmaster.aqrcapital.com/wapi/v2.5/"
#endregion

# Check record type
if ($RecordType -eq "Host") {

    #$WriteHost = Write-Host "`nRecord flag set to Host" -ForegroundColor Cyan -BackgroundColor Black
    #$WriteHost

    # Fully qualify the host name and concatenate 
    $FQDN = "$ComputerName" + "$Domain"

    #region -- Check if record exists - exit if it does
    # If force is set skip the check
    if ($Force -ne "Force") {

        $IbxRecord = Get-IbxRecord -Credential $Credential -RecordType $RecordType -SearchText $FQDN

        if ($IbxRecord -eq $null -or "") {

            #$WriteHost = Write-Host "`nNo existing Host record, proceeding..." -ForegroundColor Cyan -BackgroundColor Black
            #$WriteHost 

        } else {
    
            #$WriteHost = Write-Host "`nExisting Host record found, exiting..." -ForegroundColor Cyan -BackgroundColor Black
            #$WriteHost 

            break;
    
        }

    } else {
    
        #$WriteHost = Write-Host "`nForce Flag set, skipping check." -ForegroundColor Cyan -BackgroundColor Black
        #$WriteHost 
    
    }
    #endregion

    #region -- Host record
    $URL = $InfobloxURLEndpoint + "record:$($RecordType.ToLower())?_return_as_object=1"

    $Data = @{

        name = "$FQDN"
        ipv4addrs = @(@{ipv4addr="$IPv4Address"})

        }

    $Body = $Data | ConvertTo-Json

    try {
            
        # Clear the error so only fresh ones are recorded
        $Error.Clear()

        #$WriteHost = Write-Host "`nCreating Host Record" -ForegroundColor Cyan -BackgroundColor Black
        #$WriteHost

        # Ibx web call
        $Info = Invoke-WebRequest -Uri $URL -Method Post -Body $Body -ContentType "application/json" -Credential $Credential

        #$WriteHost = Write-Host "`nHost Record created successfully" -ForegroundColor Yellow -BackgroundColor Black
        #$WriteHost

    } catch {

    #$WriteHost = Write-Host "`nUnable to create Host record: `n$Error" -ForegroundColor Red -BackgroundColor Black
    #$WriteHost 

    }

    $RecordInfo = Get-IbxRecord -Credential $Credential -RecordType $RecordType -SearchText $FQDN

    Return $RecordInfo

    #endregion

} elseif ($RecordType -eq "A") {
    
    #$WriteHost = Write-Host "`nRecord flag set to A" -ForegroundColor Cyan -BackgroundColor Black
    #$WriteHost

    # Fully qualify the host name and concatenate 
    $FQDN = "$ComputerName" + "$Domain"

    #region -- Check if record exists - exit if it does
    # If force is set skip the check
    if ($Force -ne "Force") {

        $IbxRecord = Get-IbxRecord -Credential $Credential -RecordType $RecordType -SearchText $FQDN

        if ($IbxRecord -eq $null -or "") {

            #$WriteHost = Write-Host "`nNo existing A record, proceeding..." -ForegroundColor Cyan -BackgroundColor Black
            #$WriteHost 

        } else {
    
            #$WriteHost = Write-Host "`nExisting A record found, exiting..." -ForegroundColor Cyan -BackgroundColor Black
            #$WriteHost 

            break;
    
        }

    } else {
    
        #$WriteHost = Write-Host "`nForce Flag set, skipping check." -ForegroundColor Cyan -BackgroundColor Black
        #$WriteHost 
    
    }
    #endregion

    #region -- A record
    $URL = $InfobloxURLEndpoint + "record:$($RecordType.ToLower())" 

    $Data = @{

        name = "$FQDN"
        ipv4addr="$IPv4Address"

        }

    $Body = $Data | ConvertTo-Json

    try {
            
        # Clear the error so only fresh ones are recorded
        $Error.Clear()

        #$WriteHost = Write-Host "`nCreating A Record" -ForegroundColor Cyan -BackgroundColor Black
        #$WriteHost

        # Ibx web call
        $Info = Invoke-WebRequest -Uri $URL -Method Post -Body $Body -ContentType "application/json" -Credential $Credential

        #$WriteHost = Write-Host "`nA Record created successfully" -ForegroundColor Yellow -BackgroundColor Black
        #$WriteHost

    } catch {

    #$WriteHost = Write-Host "`nUnable to create A record: `n$Error" -ForegroundColor Red -BackgroundColor Black
    #$WriteHost 

    }

    $RecordInfo = Get-IbxRecord -Credential $Credential -RecordType $RecordType -SearchText $FQDN

    Return $RecordInfo

    #endregion

} elseif ($RecordType -eq "CName") {

    #$WriteHost = Write-Host "`nRecord flag set to CName" -ForegroundColor Cyan -BackgroundColor Black
    #$WriteHost

    # Fully qualify the host name and concatenate 
    $FQDN = "$ComputerName" + "$Domain"
    $CanonicalFQDN = "$Canonical" + "$Domain"

    #region -- Check if record exists - exit if it does
    # If force is set skip the check
    if ($Force -ne "Force") {

        $IbxRecord = Get-IbxRecord -Credential $Credential -RecordType $RecordType -SearchText $FQDN

        if ($IbxRecord -eq $null -or "") {

            #$WriteHost = Write-Host "`nNo existing CName record, proceeding..." -ForegroundColor Cyan -BackgroundColor Black
            #$WriteHost 

        } else {
    
            #$WriteHost = Write-Host "`nExisting CName record found, exiting..." -ForegroundColor Cyan -BackgroundColor Black
            #$WriteHost 

            break;
    
        }

    } else {
    
        #$WriteHost = Write-Host "`nForce Flag set, skipping check." -ForegroundColor Cyan -BackgroundColor Black
        #$WriteHost 
    
    }
    #endregion

    #region -- CName record
    $URL = $InfobloxURLEndpoint + "record:$($RecordType.ToLower())" 

    $Data = @{
        
        name = "$FQDN"
        canonical = "$CanonicalFQDN"
            
        }

    $Body = $Data | ConvertTo-Json

    $Body

    try {
            
        # Clear the error so only fresh ones are recorded
        $Error.Clear()

        #$WriteHost = Write-Host "`nCreating CName Record" -ForegroundColor Cyan -BackgroundColor Black
        #$WriteHost

        # Ibx web call
        $Info = Invoke-WebRequest -Uri $URL -Method Post -Body $Body -ContentType "application/json" -Credential $Credential

        #$WriteHost = Write-Host "`nCName Record created successfully" -ForegroundColor Yellow -BackgroundColor Black
        #$WriteHost

    } catch {

    #$WriteHost = Write-Host "`nUnable to create CName record: `n$Error" -ForegroundColor Red -BackgroundColor Black
    #$WriteHost 

    }

    $RecordInfo = Get-IbxRecord -Credential $Credential -RecordType $RecordType -SearchText $FQDN

    Return $RecordInfo

    #endregion

   
} elseif ($RecordType -eq "PTR") {

    #$WriteHost = Write-Host "`nRecord flag set to PTR" -ForegroundColor Cyan -BackgroundColor Black
    #$WriteHost

    # Fully qualify the host name and concatenate 
    $FQDN = "$ComputerName" + "$Domain"
    $CanonicalFQDN = "$Canonical" + "$Domain"

    #region -- Check if record exists - exit if it does
    # If force is set skip the check
    if ($Force -ne "Force") {

        $IbxRecord = Get-IbxRecord -Credential $Credential -RecordType $RecordType -SearchText $FQDN

        if ($IbxRecord -eq $null -or "") {

            #$WriteHost = Write-Host "`nNo existing PTR record, proceeding..." -ForegroundColor Cyan -BackgroundColor Black
            #$WriteHost 

        } else {
    
            #$WriteHost = Write-Host "`nExisting PTR record found, exiting..." -ForegroundColor Cyan -BackgroundColor Black
            #$WriteHost 

            break;
    
        }

    } else {
    
        #$WriteHost = Write-Host "`nForce Flag set, skipping check." -ForegroundColor Cyan -BackgroundColor Black
        #$WriteHost 
    
    }
    #endregion

    #region -- PTR record
    $URL = $InfobloxURLEndpoint + "record:$($RecordType.ToLower())" 

    #[array]::Reverse($PTR)

    $Data = @{
        
        ptrdname = "$FQDN"
        ipv4addr = "$IPv4Address"
            
        }

    $Body = $Data | ConvertTo-Json

    try {
            
        # Clear the error so only fresh ones are recorded
        $Error.Clear()

        #$WriteHost = Write-Host "`nCreating PTR Record" -ForegroundColor Cyan -BackgroundColor Black
        #$WriteHost

        # Ibx web call
        $Info = Invoke-WebRequest -Uri $URL -Method Post -Body $Body -ContentType "application/json" -Credential $Credential

        #$WriteHost = Write-Host "`PTR Record created successfully" -ForegroundColor Yellow -BackgroundColor Black
        #$WriteHost

    } catch {

    #$WriteHost = Write-Host "`nUnable to create PTR record: `n$Error" -ForegroundColor Red -BackgroundColor Black
    #$WriteHost 

    }

    $RecordInfo = Get-IbxRecord -Credential $Credential -RecordType $RecordType -SearchText $FQDN

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
    $MyInvLineFunc = 'Create-IbxRecord'
    
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