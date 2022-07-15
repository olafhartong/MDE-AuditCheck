## Provided with no guaranties nor warranties by Olaf Hartong. @olafhartong

## Requires Remote Server Administration Tools (RSAT) 

# Get all GPOs in an array
$AllGPOs = (Get-GPO -All)

Write-Host "This script checks the Group Policies for Audit settings" -ForegroundColor Green
Write-Host "Next it makes sure all categories that can impact MDE functionality are set properly" -ForegroundColor Green
Write-Host "There is a total of" ($AllGPOs).Count "GPOs." -ForegroundColor Green
Write-Host "`nThe following GPOs contain Audit settings:" -ForegroundColor Green
# Loop through all GPOs to find ones that have audit settings
foreach ($TheGPO in $AllGPOs)
    {
        # Create XML report from current GPO
        [XML]$CurrentXML = Get-GPOReport -Name $TheGPO.DisplayName -ReportType XML
        
        if (@($currentxml.GPO.Computer.ExtensionData.Extension | Where-Object {$_.type -Match 'Audit'}).Count -ne 0)
            {
                Write-Host "Audit Settings: " -NoNewline -ForegroundColor Cyan
                $TheGPO.DisplayName
            }
    }

# Write second result header
Write-Host "`nOut of those, the following GPOs have potential blind spots due to lacking audit settings:" -ForegroundColor Green

# Loop through GPOs 
foreach ($TheGPO in $AllGPOs)
    {
        # Create XML report from current GPO
        [XML]$CurrentXML = Get-GPOReport -Name $TheGPO.DisplayName -ReportType XML

       if (@($currentxml.GPO.Computer.ExtensionData.Extension | Where-Object {$_.type -match 'Audit'})) 
       {
        Write-Host "GPO: " -ForegroundColor Cyan $TheGPO.DisplayName

        if (@($currentxml.GPO.Computer.ExtensionData.Extension.AuditSetting | Where-Object {$_.SubCategoryName -Match 'Audit Logon'}) )
            {
                $AuditSetting=$currentxml.GPO.Computer.ExtensionData.Extension.AuditSetting | Where-Object {$_.SubCategoryName -Match 'Audit Logon'}
                if ($AuditSetting.SettingValue -NotIn 3) { Write-Host " Audit Logon - Expected setting is 3, current setting is:" $AuditSetting.SettingValue -ForegroundColor Yellow }
            }
        else 
            {
                Write-Host  -ForegroundColor Yellow " Audit Logon - Not Set"
            }

        if (@($currentxml.GPO.Computer.ExtensionData.Extension.AuditSetting | Where-Object {$_.SubCategoryName -Match 'Authorization Policy Change'}) )
        {
            $AuditSetting=$currentxml.GPO.Computer.ExtensionData.Extension.AuditSetting | Where-Object {$_.SubCategoryName -Match 'Authorization Policy Change'}
            if ($AuditSetting.SettingValue -NotIn 1,3) { Write-Host " Authorization Policy Change - Expected setting is 1 or 3, current setting is:" $AuditSetting.SettingValue -ForegroundColor Yellow}
        }
        else 
            {
                Write-Host " Authorization Policy Change - Not Set" -ForegroundColor Yellow 
            }

        if (@($currentxml.GPO.Computer.ExtensionData.Extension.AuditSetting | Where-Object {$_.SubCategoryName -Match 'Audit Security Group Management'}) )
            {
                $AuditSetting=$currentxml.GPO.Computer.ExtensionData.Extension.AuditSetting | Where-Object {$_.SubCategoryName -Match 'Audit Security Group Management'}
                if ($AuditSetting.SettingValue -NotIn 1,3) { Write-Host " Audit Security Group Management - Expected setting is 1 or 3, current setting is:" $AuditSetting.SettingValue -ForegroundColor Yellow}
            }
        else 
            {
                Write-Host  -ForegroundColor Yellow " Audit Security Group Management - Not Set"
            }
        
        if (@($currentxml.GPO.Computer.ExtensionData.Extension.AuditSetting | Where-Object {$_.SubCategoryName -Match 'Audit User Account Management'}) )
            {
                $AuditSetting=$currentxml.GPO.Computer.ExtensionData.Extension.AuditSetting | Where-Object {$_.SubCategoryName -Match 'Audit User Account Management'}
                if ($AuditSetting.SettingValue -NotIn 1,3) { Write-Host " Audit User Account Management - Expected setting is 1 or 3, current setting is:" $AuditSetting.SettingValue -ForegroundColor Yellow}
            }
        else 
            {
                Write-Host  -ForegroundColor Yellow " Audit User Account Management - Not Set"
            }
        if (@($currentxml.GPO.Computer.ExtensionData.Extension.AuditSetting | Where-Object {$_.SubCategoryName -Match 'Audit PNP Activity'}) )
            {
                $AuditSetting=$currentxml.GPO.Computer.ExtensionData.Extension.AuditSetting | Where-Object {$_.SubCategoryName -Match 'Audit PNP Activity'}
                if ($AuditSetting.SettingValue -NotIn 1,3) { Write-Host " Audit PNP Activity - Expected setting is 1 or 3, current setting is:" $AuditSetting.SettingValue -ForegroundColor Yellow}
            }
        else 
            {
                Write-Host  -ForegroundColor Yellow " Audit PNP Activity - Not Set"
            }
        
        if (@($currentxml.GPO.Computer.ExtensionData.Extension.AuditSetting | Where-Object {$_.SubCategoryName -Match 'Audit Other Logon/Logoff Events'}) )
            {
                $AuditSetting=$currentxml.GPO.Computer.ExtensionData.Extension.AuditSetting | Where-Object {$_.SubCategoryName -Match 'Audit Other Logon/Logoff Events'}
                if ($AuditSetting.SettingValue -NotIn 2,3) { Write-Host " Audit Other Logon/Logoff Events - Expected setting is 2 or 3, current setting is:" $AuditSetting.SettingValue -ForegroundColor Yellow}
            }
        else 
            {
                Write-Host  -ForegroundColor Yellow " Audit Other Logon/Logoff Events - Not Set"
            }

        if (@($currentxml.GPO.Computer.ExtensionData.Extension.AuditSetting | Where-Object {$_.SubCategoryName -Match 'Audit File System'}) )
            {
                $AuditSetting=$currentxml.GPO.Computer.ExtensionData.Extension.AuditSetting | Where-Object {$_.SubCategoryName -Match 'Audit File System'}
                if ($AuditSetting.SettingValue -NotIn 1,3) { Write-Host " Audit File System - Expected setting is 1 or 3, current setting is:" $AuditSetting.SettingValue -ForegroundColor Yellow}
            }
        else 
            {
                Write-Host  -ForegroundColor Yellow " Audit File System - Not Set"
            }
        
        if (@($currentxml.GPO.Computer.ExtensionData.Extension.AuditSetting | Where-Object {$_.SubCategoryName -Match 'Audit Filtering Platform Connection'}) )
            {
                $AuditSetting=$currentxml.GPO.Computer.ExtensionData.Extension.AuditSetting | Where-Object {$_.SubCategoryName -Match 'Audit Filtering Platform Connection'}
                if ($AuditSetting.SettingValue -NotIn 2,3) { Write-Host " Audit Filtering Platform Connection - Expected setting is 2 or 3, current setting is:" $AuditSetting.SettingValue -ForegroundColor Yellow}
            }
        else 
            {
                Write-Host  -ForegroundColor Yellow " Audit Filtering Platform Connection - Not Set"
            }
            
        if (@($currentxml.GPO.Computer.ExtensionData.Extension.AuditSetting | Where-Object {$_.SubCategoryName -Match 'Audit Filtering Platform Packet Drop'}) )
            {
                $AuditSetting=$currentxml.GPO.Computer.ExtensionData.Extension.AuditSetting | Where-Object {$_.SubCategoryName -Match 'Filtering Platform Packet Drop'}
                if ($AuditSetting.SettingValue -NotIn 2) { Write-Host " Audit Filtering Platform Packet Drop - Expected setting is 2, current setting is:" $AuditSetting.SettingValue -ForegroundColor Yellow}
            }
        else 
            {
                Write-Host  -ForegroundColor Yellow " Audit Filtering Platform Packet Drop - Not Set"
            }

        if (@($currentxml.GPO.Computer.ExtensionData.Extension.AuditSetting | Where-Object {$_.SubCategoryName -Match 'Audit Other Object Access Events'}) )
            {
                $AuditSetting=$currentxml.GPO.Computer.ExtensionData.Extension.AuditSetting | Where-Object {$_.SubCategoryName -Match 'Audit Other Object Access Events'}
                if ($AuditSetting.SettingValue -NotIn 1,3) { Write-Host " Audit Other Object Access Events - Expected setting is 1 or 3, current setting is:" $AuditSetting.SettingValue -ForegroundColor Yellow}
            }
        else 
            {
                Write-Host  -ForegroundColor Yellow " Audit Other Object Access Events - Not Set"
            }
        
        if (@($currentxml.GPO.Computer.ExtensionData.Extension.AuditSetting | Where-Object {$_.SubCategoryName -Match 'Audit Audit Policy Change'}) )
            {
                $AuditSetting=$currentxml.GPO.Computer.ExtensionData.Extension.AuditSetting | Where-Object {$_.SubCategoryName -Match 'Audit Audit Policy Change'}
                if ($AuditSetting.SettingValue -NotIn 1,3) { Write-Host " Audit Audit Policy Change - Expected setting is 1 or 3, current setting is:" $AuditSetting.SettingValue -ForegroundColor Yellow}
            }
        else 
            {
                Write-Host  -ForegroundColor Yellow " Audit Audit Policy Change - Not Set"
            }

            if (@($currentxml.GPO.Computer.ExtensionData.Extension.AuditSetting | Where-Object {$_.SubCategoryName -Match 'Audit Other System Events'}) )
            {
                $AuditSetting=$currentxml.GPO.Computer.ExtensionData.Extension.AuditSetting | Where-Object {$_.SubCategoryName -Match 'Audit Other System Events'}
                if ($AuditSetting.SettingValue -NotIn 1,3) { Write-Host " Audit Other System Events - Expected setting is 1 or 3, current setting is:" $AuditSetting.SettingValue -ForegroundColor Yellow}
            }
        else 
            {
                Write-Host  -ForegroundColor Yellow " Audit Other System Events - Not Set"
            }
        
        if (@($currentxml.GPO.Computer.ExtensionData.Extension.AuditSetting | Where-Object {$_.SubCategoryName -Match 'Audit Security System Extension'}) )
            {
                $AuditSetting=$currentxml.GPO.Computer.ExtensionData.Extension.AuditSetting | Where-Object {$_.SubCategoryName -Match 'Audit Security System Extension'}
                if ($AuditSetting.SettingValue -NotIn 1,3) { Write-Host " Audit Security System Extension - Expected setting is 1 or 3, current setting is:" $AuditSetting.SettingValue -ForegroundColor Yellow}
            }
        else 
            {
                Write-Host  -ForegroundColor Yellow " Audit Security System Extension - Not Set"
            }
       }
}
