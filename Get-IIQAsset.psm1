<#
help will go here
#>

class IIQAsset {
    [ValidateNotNullOrEmpty()] [string]$iiqID
    [string]$AssetTag
    [string]$Model
    [string]$Status
    [string]$Owner
    [string]$Location
    [string]$Serial #Alias 'SerialNumber'
    [int]$JamfID
    [string]$SCCMID
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
        [int]$jid,
        [string]$sccmid,
        [string]$n,
        [string]$iurl,
        [string]$jurl
    ){
        $this.iiqID = $iid
        $this.AssetTag = $at
        $this.Model = $m
        $this.Status= $stat
        $this.Owner = $o
        $this.Location = $l
        $this.Serial= $ser
        $this.JamfID= $jid
        $this.SCCMID = $sccmid
        $this.Name = $n
        $this.iIQURL = $iurl
        $this.JamfURL = $jurl
    }
}

$IIQTypeData = @{
    TypeName = 'IIQAsset'
    DefaultDisplayPropertySet = 'AssetTag','Serial','Owner','Location','Model','Status','Name', 'iIQURL', 'JamfURL'
}
Update-TypeData @IIQTypeData -Force


function Get-IIQAsset {
	[Alias("ga")]
    [CmdletBinding(DefaultParameterSetName = "AssetTag")]
    [OutputType('IIQAsset')]
    param (
        [Parameter(Mandatory, ParameterSetName = "AssetTag", ValueFromPipeline, Position = 0)][string]$AssetTag,
        [Parameter(Mandatory, ParameterSetName = "Serial")][string]$Serial,
        [Parameter(Mandatory)][string]$BearerToken, # set default in profile
        [Parameter(Mandatory)][string]$IIQDomain, # set default in profile
        [Parameter()][string]$JamfDomain # set default in profile
    )
	begin {
		$iiqhost = "https://$IIQDomain.incidentiq.com" # does there need to be an initialize function? could include adding bearer to profile, optionally. Or, make these parameters and again suggest to add to profile. How is this thing usually handled for cloud tools? or set env variable via initialize function?
		$Headers = @{
			"Client" =  "ApiClient"
			"Authorization" = "Bearer $BearerToken"
			"Content-Type" = "application/json"
		}
	}
	process {
        if ($AssetTag) {$Query = $AssetTag.Trim()}
        elseif ($Serial) {$Query = $Serial.Trim()}
        $Body = ConvertTo-Json @{
            "Query" = $Query
            "SearchAssetTag" = $($null -ne $AssetTag)
            "SearchSerial" = $($null -ne $Serial)
        }

        $JamfID = $null
        $JamfURL = $null #Need to reset these in case one or more ifs below return false

        $Request = Invoke-WebRequest -Method Post -Headers $Headers -Uri "$iiqhost/services/assets/search/?`$s=2" -Body $Body # Maximum number of results is set by /search/?$s=(number)
        # $Request.Content > .\request.json
        if ($Request.StatusCode -eq 200) {
            $Converted = ConvertFrom-Json $Request.Content
            if ($Converted.ItemCount -eq 1) {
                if ('jamf' -in $Converted.Items.DataMappings.Lookups.AppId) {
                    $JamfID = $Converted.Items.DataMappings.Lookups.Where({$_.AppId -eq 'jamf' -and $_.Key -eq 'ExternalId'}).Value.Substring(6) #MOBILE vs computers ...?
                    if ($JamfDomain) {$JamfURL = "$JamfDomain/mobileDevices.html?id=$JamfID"}
                }

                # Custom class must be defined in auto-load module OR within -parallel block.
                return [IIQAsset]::new(
                    $Converted.Items.AssetId,
                    $Converted.Items.AssetTag,
                    $Converted.Items.Name,
                    $Converted.Items.Status.Name,
                    $Converted.Items.Owner.Username,
                    $Converted.Items.Location.Name,
                    $Converted.Items.SerialNumber,
                    $JamfID, # This should maybe be a string instead of int so it doesn't return 0 when null. Also, hidden since the url can be clicked or ID copied from.
                    $Converted.Items.DataMappings.Lookups.Where({$_.AppId -eq 'microsoftSCCM' -and $_.Key -eq 'ExternalId'}).Value,
                    (ConvertFrom-Json $Converted.Items.CustomFieldValues.Where({$_.EditorTypeID -eq 0}).Value).AssetName
                    ,"$iiqhost/agent/assets/$($Converted.Items.AssetId)"
                    ,$JamfURL
                )
            }
            if ($Converted.ItemCount -eq 0) {
                Write-Error -Message "No match found for `"$Query`""
            }
            if ($Converted.ItemCount -gt 1) {
                Write-Error -Message "Multiple matches for `"$Query`", skipping"
            }
        }
        else {
            Write-Error -Message "Error searching for `"$Query`""
        }
    }
}