<#
.NOTES
	Name: Confirm-Credentials.ps1
	Author: Daniel Sheehan
	Requires: PowerShell version 2.0 or later.
	Version History:
	1.0 - 6/23/2018 - Initial public release.
	############################################################################
	The sample scripts are not supported under any Microsoft standard support
	program or service. The sample scripts are provided AS IS without warranty
	of any kind. Microsoft further disclaims all implied warranties including,
	without limitation, any implied warranties of merchantability or of fitness
	for a particular purpose. The entire risk arising out of the use or
	performance of the sample scripts and documentation remains with you. In no
	event shall Microsoft, its authors, or anyone else involved in the creation,
	production, or delivery of the scripts be liable for any damages whatsoever
	(including, without limitation, damages for loss of business profits,
	business interruption, loss of business information, or other pecuniary
	loss) arising out of the use of or inability to use the sample scripts or
	documentation, even if Microsoft has been advised of the possibility of such
	damages.
	############################################################################
.SYNOPSIS
	This sample script provides example code of how to validate credentials and
	subsequently confirm supplied via the Get-Credential cmdlet against Active
	Directory.
.DESCRIPTION
	This script was created to provide download-able sample code that
	demonstrates how to take credentials supplied to the Get-Credential cmdlet
	and actually validate them against Active Directory (AD). If the script
	can't validate the credentials on the first try, it will keep trying until
	the set number of maximum tries.
	If that maximum is reached, the script exits. Otherwise it returns the
	confirmed credentials back to the shell for further use as $Credentials.
.PARAMETER MaxAttempts
	Optional: Defines how many times the script can try to validate the
	supplied credentials against AD before giving up. Default of 5 attempts.
.EXAMPLE
	Confirm-Credentials.ps1
	The script will use the Get-Credential prompt to gather credentials and
	then try to validate them against AD a maximum of 5 times before giving up.
.EXAMPLE
	Confirm-Credentials.ps1 -MaxAttempts 3
	The script will use the Get-Credential prompt to gather credentials and
	then try to validate them against AD a maximum of 3 times before giving up.
.LINK
	https://gallery.technet.microsoft.com/ConfirmingValidating-5ac584ae
#>

[CmdletBinding()]
Param (
	[Parameter(Mandatory = $False)]
	[Int]$MaxAttempts = 5
)

# Prompt for Credentials and verify them using the DirectoryServices.AccountManagement assembly.
Write-Host "Please provide your credentials so the script can continue."
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
# Extract the current user's domain and also pre-format the user name to be used in the credential prompt.
$UserDomain = $env:USERDOMAIN
$UserName = "$UserDomain\$env:USERNAME"
# Define the starting number (always #1) and the initial credential prompt message to use.
$Attempt = 1
$CredentialPrompt = "Enter your Domain account password (attempt #$Attempt out of $MaxAttempts):"
# Set ValidAccount to false so it can be used to exit the loop when a valid account is found (and the value is changed to $True).
$ValidAccount = $False

# Loop through prompting for and validating credentials, until the credentials are confirmed, or the maximum number of attempts is reached.
Do {
	# Blank any previous failure messages and then prompt for credentials with the custom message and the pre-populated domain\user name.
	$FailureMessage = $Null
	$Credentials = Get-Credential -UserName $UserName -Message $CredentialPrompt
	# Verify the credentials prompt wasn't bypassed.
	If ($Credentials) {
		# If the user name was changed, then switch to using it for this and future credential prompt validations.
		If ($Credentials.UserName -ne $UserName) {
			$UserName = $Credentials.UserName
		}
		# Test the user name (even if it was changed in the credential prompt) and password.
		$ContextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
		Try {
			$PrincipalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext $ContextType,$UserDomain
		} Catch {
			If ($_.Exception.InnerException -like "*The server could not be contacted*") {
				$FailureMessage = "Could not contact a server for the specified domain on attempt #$Attempt out of $MaxAttempts."
			} Else {
				$FailureMessage = "Unpredicted failure: `"$($_.Exception.Message)`" on attempt #$Attempt out of $MaxAttempts."
			}
		}
		# If there wasn't a failure talking to the domain test the validation of the credentials, and if it fails record a failure message.
		If (-not($FailureMessage)) {
			$ValidAccount = $PrincipalContext.ValidateCredentials($UserName,$Credentials.GetNetworkCredential().Password)
			If (-not($ValidAccount)) {
				$FailureMessage = "Bad user name or password used on credential prompt attempt #$Attempt out of $MaxAttempts."
			}
		}
	# Otherwise the credential prompt was (most likely accidentally) bypassed so record a failure message.
	} Else {
		$FailureMessage = "Credential prompt closed/skipped on attempt #$Attempt out of $MaxAttempts."
	}

	# If there was a failure message recorded above, display it, and update credential prompt message.
	If ($FailureMessage) {
		Write-Warning "$FailureMessage"
		$Attempt++
		If ($Attempt -lt $MaxAttempts) {
			$CredentialPrompt = "Authentication error. Please try again (attempt #$Attempt out of $MaxAttempts):"
		} ElseIf ($Attempt -eq $MaxAttempts) {
			$CredentialPrompt = "Authentication error. THIS IS YOUR LAST CHANCE (attempt #$Attempt out of $MaxAttempts):"
		}
	}
} Until (($ValidAccount) -or ($Attempt -gt $MaxAttempts))

# If the credentials weren't successfully verified, then exit the script, otherwise pass them through for further use.
Write-Host ""
If (-not($ValidAccount)) {
	Write-Host -ForegroundColor Red "You failed $MaxAttempts attempts at providing a valid user credentials. Exiting the script now... "
	EXIT
} Else {
	Write-Host 'Your confirmed credentials have been saved to the $Credentials variable and is available after this script finishes.'
	$Global:Credentials = $Credentials
}
