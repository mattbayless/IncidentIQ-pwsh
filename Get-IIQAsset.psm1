

class IIQAsset {
	[ValidateNotNullOrEmpty()] [string]$iiqID
	[string]$AssetTag
	[string]$Model
	[string]$Status
	[string]$Owner
	[string]$Location
	[string]$Serial #Alias 'SerialNumber'
	[string]$JamfID
	[string]$SCCMID # CM cmdlets don't accept this via pipeline so no need to match name
	[string]$Name
	[string]$iIQURL
	[string]$JamfURL

	IIQAsset(
		[string]$iid,
		[string]$at,
		[string]$m,
		[string]$stat,
		[string]$o,
		[string]$l,
		[string]$ser,
		[string]$jid,
		[string]$sccmid,
		[string]$n,
		[string]$iurl,
		[string]$jurl
	) {
		$this.iiqID = $iid
		$this.AssetTag = $at
		$this.Model = $m
		$this.Status = $stat
		$this.Owner = $o
		$this.Location = $l
		$this.Serial = $ser
		$this.JamfID = $jid
		$this.SCCMID = $sccmid
		$this.Name = $n
		$this.iIQURL = $iurl
		$this.JamfURL = $jurl
	}
}

$IIQTypeData = @{
	TypeName                  = 'IIQAsset'
	DefaultDisplayPropertySet = 'AssetTag', 'Serial', 'Owner', 'Location', 'Model', 'Status', 'Name', 'iIQURL', 'JamfURL'
}
Update-TypeData @IIQTypeData -Force

function Initialize-IIQModule {
	param (
		[Alias("s")][Parameter(Mandatory)][string]$IIQSubdomain,
		[Alias("j")][Parameter()][ValidateNotNullOrEmpty()][string]$JamfDomain,
		[Alias("b")][Parameter()][switch]$UseBearerAuth,
		[Alias("p")][Parameter()][switch]$Persist
	)

	$Env:IIQSubdomain = $IIQSubdomain
	if ($JamfDomain) { $Env:JamfDomain = $JamfDomain }
	if ($BearerAuthentication) {
		$IIQBearerToken = Read-Host -Prompt "IIQ Bearer Token" -AsSecureString
		$Env:IIQBearerToken = ConvertFrom-SecureString $IIQBearerToken
	}

	if ($Persist) {
		if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
			[System.Environment]::SetEnvironmentVariable('IIQSubdomain', $IIQSubdomain, 'User')
			if ($BearerAuthentication) { [System.Environment]::SetEnvironmentVariable('IIQBearerToken', $Env:IIQBearerToken, 'User') }
			if ($JamfDomain) { [System.Environment]::SetEnvironmentVariable('JamfDomain', $JamfDomain, 'User') }
		}
		else {
			Write-Error "Command must be run as administrator to persist connection. Initialized for this session only."
		}
	}
}

# function Connect-IIQ {
# 	param (
# 		[Parameter(Mandatory)][pscredential]$Credential,
# 		[ValidateNotNullOrEmpty]$IIQSubdomain
# 	)
# 	if ($IIQSubdomain) { $Env:IIQSubdomain = $IIQSubdomain }

	# Untested spec code from Duet AI
	# $Username = $Credential.UserName
	# $Password = $Credential.GetNetworkCredential().Password
	# $script:Authorization = Invoke-WebRequest -Method Post -Uri "https://$IIQSubdomain.incidentiq.com/services/auth/login" -Body "username=$Username&password=$Password" -ContentType "application/x-www-form-urlencoded" -UseBasicParsing | ConvertFrom-Json | Select-Object -ExpandProperty token
	#TODO add error handling
	#Return in some way that Get-IIQAsset will stop if auth fails

	# return $Authorization
# }

function Get-IIQAsset {
	<#
	.SYNOPSIS
		Get-IIQAsset gets inventory information from an IncidentIQ site.
	.DESCRIPTION
		Get-IIQAsset gets inventory information for provided asset tags or serial numbers from an IncidentIQ site. The cmdlet returns an IIQAsset object, which can be piped to other cmdlets.
	.PARAMETER AssetTag
		The asset tag of the asset to get information about.
	.PARAMETER Serial
		The serial number of the asset to get information about.
	.PARAMETER Credential
		Credentials to connect to your IIQ site.
	.EXAMPLE
		Get-IIQAsset -AssetTag "45537"

		AssetTag : 45537
		Serial   : 53R141NUM83R
		Owner    : egoldstein
		Location : Bayside High
		Model    : iPad Pro Plus Ultra
		Status   : In Service
		Name     : Emmanuel's iPad
		iIQURL   : https://tammany.incidentiq.com/assets/477df4e6-1657-4f6f-adb4-53dd65758958
		JamfURL  : https://example.jamfcloud.com/mobileDevices.html?id=1984

	.EXAMPLE
		Get-IIQAsset -Serial "123abc456def7890"
	.EXAMPLE
		Get-IIQAsset -AssetTag "12345", "67890", "N101112"
	.EXAMPLE
		Get-IIQAsset -Serial "123abc456def7890", "0987fedcba654321"
	.OUTPUTS
		[IIQAsset]
		iiqID
		AssetTag
		Model
		Status
		Owner
		Location
		Serial
		JamfID
		SCCMID
		Name (From SCCM or Jamf integration)
		iIQURL
		JamfURL
	#>
	[Alias("ga")]
	[CmdletBinding(DefaultParameterSetName = "AssetTag")] #Doesn't seem like an auth method is being required now
	[OutputType('IIQAsset')]
	param (
		[Alias("at", "a")][Parameter(Mandatory, ParameterSetName = "AssetTag", ValueFromPipeline, Position = 0)][string]$AssetTag, #TODO add foreach to process and make these arrays
		[Alias("s", "sn", "SerialNumber")][Parameter(Mandatory, ParameterSetName = "Serial", ValueFromPipeline, Position = 0)][string]$Serial, #TODO add foreach to process and make these arrays
		# [Parameter()][ValidateNotNullOrEmpty()][securestring]$BearerToken,
		[Parameter()][ValidateNotNullOrEmpty()][PSCredential]$Credential
		# ,[Parameter()][ValidateNotNullOrEmpty()][string]$IIQSubdomain = $Env:IIQSubdomain
		# ,[Parameter()][ValidateNotNullOrEmpty()][string]$JamfDomain = $Env:JamfDomain
		<# could force running connect-iiq; could see about setting defaults only if they exist; could change connect-iiq to set defaultparametervalues instead of env variables but then that doesn't persist.
		Initialize-IIQModule for subdomain and jamf values set as env variables; if bearer token provided then store that I guess
		   Could change persist behavior to add to defaultparametervalues in $profile
		   $profilecontents = get-content $profile
		   switch ($profilecontents) {
			$null {write-host "profile is empty"}
			default {write-error "unhandled exception"}
		   }
		   if !get-content $profile, $profile = "psdefaultparametervalues *IIQ*$IIQSubdomain = $IIQSubdomain; *IIQ*$JamfDomain = $JamfDomain etc"
		#>

	)
	begin {
		if (!(Test-Path Env:IIQSubdomain)) { throw "Initialize-IIQModule must be run first." }
		if (Test-Path Env:IIQBearerToken) { $Authorization = "Bearer " + (ConvertTo-SecureString $Env:IIQBearerToken | ConvertFrom-SecureString -AsPlainText) }
		else {
			if (!$Credential) { $Credential = Get-Credential -Title "IIQ credential request" -Message "Enter your credentials for $Env:IIQSubdomain.incidentiq.com." }
			Connect-IIQ -Credential $Credential -ErrorAction Stop
		}
		$Headers = @{
			"Client"        = "ApiClient"
			"Authorization" = $Authorization
			"Content-Type"  = "application/json"
		}
	}
	process {
		$DeviceName = $null
		$JamfID = $null
		$JamfURL = $null

		switch ($PSCmdlet.ParameterSetName) {
			"AssetTag" {
				$Query = $AssetTag.Trim()
				$Request = Invoke-WebRequest -Method Get -Headers $Headers -Uri "https://$Env:IIQSubdomain.incidentiq.com/services/assets/assettag/$Query"
			}
			"Serial" {
				$Query = $Serial.Trim()
				$Request = Invoke-WebRequest -Method Get -Headers $Headers -Uri "https://$Env:IIQSubdomain.incidentiq.com/services/assets/serial/$Query"
			}
		}

		switch ($Request.StatusCode) {
			200 {
				$Converted = ConvertFrom-Json $Request.Content
				switch ($Converted.ItemCount) {
					1 {
						if ('jamf' -in $Converted.Items.DataMappings.Lookups.AppId) {
							$JamfID = $Converted.Items.DataMappings.Lookups.Where({ $_.AppId -eq 'jamf' -and $_.Key -eq 'ExternalId' }).Value.Substring(6) #MOBILE vs computers ...?
							if ($Env:JamfDomain) { $JamfURL = "$Env:JamfDomain/mobileDevices.html?id=$JamfID" }
						}
						$DeviceName = try { (ConvertFrom-Json $Converted.Items.CustomFieldValues.Where({ $_.EditorTypeID -eq 0 }).Value).AssetName } catch { $null } #ErrorAction Ignore doesn't work here

						return [IIQAsset]::new(
							$Converted.Items.AssetId,
							$Converted.Items.AssetTag,
							$Converted.Items.Name,
							$Converted.Items.Status.Name,
							$Converted.Items.Owner.Username,
							$Converted.Items.Location.Name,
							$Converted.Items.SerialNumber,
							$JamfID,
							$Converted.Items.DataMappings.Lookups.Where({ $_.AppId -eq 'microsoftSCCM' -and $_.Key -eq 'ExternalId' }).Value,
							$DeviceName,
							"https://$Env:IIQSubdomain.incidentiq.com/agent/assets/$($Converted.Items.AssetId)",
							$JamfURL
						)
					}
					0 { Write-Error -Message "No match found for `"$Query`"" }
					{ $_ -gt 1 } { Write-Error -Message "Multiple matches for `"$Query`", skipping" }
				}
			}
			400 {
				Write-Error "Invalid request." -ErrorAction Stop
			}
			401 {
				Write-Error "Not authorized." -ErrorAction Stop
			}
			403 {
				Write-Error "Forbidden." -ErrorAction Stop
			}
			404 {
				Write-Error "Page not found." -ErrorAction Stop
			}
			500 {
				Write-Error "Internal server error." -ErrorAction Stop
			}
			503 {
				Write-Error "Service unavailable." -ErrorAction Stop
			}
			504 {
				Write-Error "Gateway timeout." -ErrorAction Stop
			}
			429 {
				Write-Error "Too many requests." -ErrorAction Stop
			}
			Default {
				Write-Error "Unknown error."
			}
		}
	}
}