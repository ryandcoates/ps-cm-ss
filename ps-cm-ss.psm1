<#
filename..... ps-cm-ss.psm1
author....... David M. Stein
created...... 02/23/2016
updated...... 
version...... 5.0.0
purpose...... powershell configmgr site server builder
#>
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$xmlFile = "$ScriptPath\config.xml"
$ScriptVer = "5.0.0"

if (!(Test-Path $xmlFile)) {
    Write-Host "ERROR: unable to load config.xml file data!" -ForegroundColor Red
    Exit
}
[xml]$cfgdata = Get-Content $xmlFile

function Test-ServerOS {
    $((Get-WmiObject -Class Win32_OperatingSystem | Select -ExpandProperty Name).ToString() -like "*Server*")
}

function Test-RunAsAdmin {
    $myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
    $myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
    $adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
    if ($myWindowsPrincipal.IsInRole($adminRole)) {$true} else {$false}
}

function IsArrayMember {
	param (
		[parameter(Mandatory=$True, Position=0)] [ValidateNotNullOrEmpty()] $Item,
		[parameter(Mandatory=$True, Position=1)] [ValidateNotNullOrEmpty()] $List
	)
	if (($List | Where {$_ -eq $Item}) -ne $null) {$True} else {$False}
}

function Get-AltWinSource {
    $try = $cfgdata.settings.common.key | Where {$_.name -eq "AltWinSource"} | Select -ExpandProperty "value"
    if ($try -ne $null -and $try -ne "") {
        if (!(Test-Path $try)) {
            Write-Host "WARNING: alternate windows source path not found." -ForegroundColor Yellow
            return ""
        }
        else {
            return $try
        }
    }
    else {
        return ""
    }
}

function Show-HostInfo {
    $os = Get-WmiObject -Class Win32_OperatingSystem | Select -ExpandProperty Caption
    Write-Host "ps-cm-ss.psm1, build-cmsiteserver.ps1 (c) by David M. Stein"
    Write-Host "version....... $ScriptVer"
    Write-Host "hostname...... $($env:COMPUTERNAME)"
    Write-Host "username...... $($env:USERNAME)"
    Write-Host "domain........ $($env:USERDNSDOMAIN)"
    Write-Host "windows ver... $os"
}

function Convert-KeyString {
    param (
        [parameter(Mandatory=$True)] [string] $StringVal
    )
    $StringVal.Replace("##SCRIPTPATH##", $ScriptPath)
}

function Get-ProductProperty {
    param (
        [parameter(Mandatory=$True)] [string] $KeyName,
        [parameter(Mandatory=$True)] [string] $PropName
    )
    $cfgdata.settings.products.product | 
        where {$_.name -eq $KeyName} | 
            select -ExpandProperty key | 
                where {$_.name -eq $PropName} | 
                    select -ExpandProperty "value"
}

function Get-InstallState {
    param (
        [parameter(Mandatory=$True)] [string] $ProductKey
    )
    $Type = Get-ProductProperty $ProductKey "runtime"
    $Path = Get-ProductProperty $ProductKey "detect"

    $out = $False
    switch ($Type) {
        "FEATURE" 
        {
            if (Test-ServerOS) {
                if ($Path -ne "") {
                    Write-Host "`tsearch.... $Path"
                    $(Get-WindowsFeature $Path)
                }
                else {
                    $False
                }
            }
            else {
                Write-Host "`twarning... not running on Windows Server" -ForegroundColor Yellow
            }
            break;
        }
        "EXE" 
        {
            if ($Path -ne "") {
                Write-Host "`tsearch.... $Path"
                $out = (Test-Path $Path)
            }
            break;
        }
        "MSI" 
        {
            Write-Host "`tsearch.... $Path"
            $out = (Test-Path $Path)
            break;
        }
        "LDAP" 
        {
            if (Test-ServerOS) {
                if ($Path.Substring(0,9) -eq "Container") {
                    $ContainerName = "System Management"
                    $DomainDN  = ((Get-ADDomain).DistinguishedName)
                    $Container = "ad:CN=$ContainerName,CN=System,$DomainDN"
                    $ArgList   = " `"CN=$ContainerName,CN=System,$DomainDN`" /I:T /G `"$DelegateTo`:GA`""
                    Write-Host "`tsearch.... $Container"
                    $(Test-Path $Container)
                }
                elseif ($Path.Substring(0,9) -eq "Attribute") {
                    $att = $Path.Split(":")[1]
                    $dom = ((Get-ADDomain).DNSRoot)
                    $SchPath  = (Get-ADRootDSE).schemanamingContext
                    $SchemaDC = (Get-ADForest $dom | Select -ExpandProperty SchemaMaster).Split(".")[0]
                    Write-Host "`tsearch.... $att"
                    $(Get-ADObject -Filter * -SearchBase $SchPath -Properties * | Where Name -eq $att)
                }
            }
            else {
                Write-Host "`twarning... not running on Windows Server" -ForegroundColor Yellow
            }
            break;
        }
        default {
            $out = "Unknown"
        }
    }
    return $out
}

function Export-INI {
    param (
        [parameter(Mandatory=$True)] [string] $InputFile,
        [parameter(Mandatory=$True)] [string] $OutputFile,
        [parameter(Mandatory=$True)] [string] $KeyName
    )
    $xset = $cfgdata.settings.inifiles.ini |
        Where {$_.name -eq $KeyName} |
            Select -ExpandProperty key
    $f1 = "$ScriptPath\$InputFile"
    $f2 = "$ScriptPath\$OutputFile"

    if (Test-Path $f1) {
        $tmp = Get-Content $f1
        foreach ($x in $xset) {
            $old = $x.Name
            $old = $old.ToUpper()
            if ($x.name -eq "SQLADMINS") {
                $new = "`"" + ($x.value).Replace(",", "`" `"") + "`""
            }
            else {
                $new = $x.value
            }
            Write-Host "`t[old] $old --> [new] $new" -ForegroundColor Yellow
            $tmp = $tmp.Replace($old, $new)
        }
        $tmp = $tmp.Replace("%","")
    }
    else {
        write-host "oh shit!"
    }
    $tmp
}

function Get-SequenceList {
    $cfgdata.settings.sequence.key | Where {$_.enabled -eq "true"} | Select -ExpandProperty Name
}

function Invoke-Payload {
	[CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [parameter(Mandatory=$True)] [string] $ProductKey,
        [parameter(Mandatory=$False)] [switch] $Commit
    )
    $ProdName   = Get-ProductProperty $ProductKey "caption"
    $PkgType    = Get-ProductProperty $ProductKey "runtime"
    $DetRule    = Get-ProductProperty $ProductKey "detect"
    $SourcePath = Get-ProductProperty $ProductKey "source"
    $TargetPath = Get-ProductProperty $ProductKey "targetpath"
    $PayLoad    = Get-ProductProperty $ProductKey "payload"
    $Args       = Get-ProductProperty $ProductKey "args"

    if ($PayLoad -ne "" -and $SourcePath -ne "") {
        $PayLoad = $PayLoad.Replace("##SOURCEPATH##", $SourcePath)
    }
    $out = $false

    Write-Host $ProdName -ForegroundColor Cyan
    Write-Host "`tkey....... $ProductKey"
    Write-Host "`ttype...... $PkgType"
    Write-Host "`tdetect.... $detRule"
    Write-Host "`tsource.... $SourcePath"
    Write-Host "`ttarget.... $TargetPath"
    Write-Host "`tpayload... $PayLoad"
    Write-Host "`targs...... $Args"

    if (Get-InstallState $ProductKey) {
        Write-Host "`tstatus.... installed" -ForegroundColor Green
        $out = $True
    }
    if ($out -eq $False -or !$Commit) {
        if ($ProductKey -eq "SQL2014") {
            $ExecPath = "$PayLoad"
            Write-Host "`tcmd....... $ExecPath $Args"
        }
        elseif ($ProductKey -eq "SCCM1511") {
            $ExecPath = "$PayLoad"
            Write-Host "`tcmd....... $ExecPath $Args"
        }
        elseif ($ProductKey -eq "WSUS") {
            $AltWinSrc = Get-AltWinSource
            if ($Commit) {
                if ($AltWinSrc -ne "") {
                    Install-WindowsFeature -ConfigurationFilePath $ScriptPath\$PayLoad -Source $AltWinSrc
                }
                else {
                    Install-WindowsFeature -ConfigurationFilePath $ScriptPath\$PayLoad
                }
            }
            $WsusUtil = "$($env:PROGRAMFILES)\Update Services\Tools\WsusUtil.exe"
            if ($Commit) {
                if (Test-Path $WsusUtil) {
                    Start-Sleep -s 10
                    Write-Host "`tfeature... WSUS post install"
                    & $WsusUtil postinstall SQL_INSTANCE_NAME=CM01 CONTENT_DIR=$TargetPath
                    Write-Host "`tcompleted"
                    $HotFix = "$SourcePath\Windows8.1-KB3095113-x64.msu"
                    if (Test-Path $HotFix) {
                        Write-Host "`tfeature... WSUS hotfix KB3095113"
                        Start-Process "wusa.exe" -Wait -ArgumentList "$HotFix /quiet /norestart"
                        Write-Host "done!"
                    }
                    else {
                        Write-Host "error: hotfix kb3095113.msu was not found." -ForegroundColor Red
                        Write-Host "error: this hotfix is required for windows 10 support." -ForegroundColor Red
                    }
                }
                else {
                    Write-Host "error: wsusutil.exe not found!" -ForegroundColor Red
                    Write-Host "error: wsus post configuration was not completed." -ForegroundColor Red
                }
            }
            else {
                Write-Host "`tfeature... WSUS post install"
                Write-Host "`tcmd....... $WsusUtil postinstall SQL_INSTANCE_NAME=CM01 CONTENT_DIR=$TargetPath"
                $HotFix = "$SourcePath\Windows8.1-KB3095113-x64.msu"
                if (Test-Path $HotFix) {
                    Write-Host "`tfeature... WSUS hotfix KB3095113"
                    Write-Host "`tcmd....... Start-Process wusa.exe -Wait -ArgumentList $HotFix /quiet /norestart"
                }
                else {
                    Write-Host "`tfeature... WSUS hotfix KB3095113 not found"
                }
            }
        }
        elseif ($PkgType -eq "MSI") {
            $ExecPath = "msiexec.exe"
            $RunFile = $SourcePath+"\"+$PayLoad
            $Cmd = $RunFile + " " + $Args
            Write-Host "`tcmd....... msiexec.exe /i $Cmd"
            if ($Commit) {
                Start-Process "msiexec.exe" -Wait -ArgumentList $Cmd
                Start-Sleep 10
                Write-Host "`tstatus.... completed"
            }
        }
        elseif ($PkgType -eq "EXE") {
            $ExecPath = "$SourcePath\$PayLoad"
            $Cmd = $ExecPath+" "+$Args
            Write-Host "`tcmd....... $Cmd"
            if ($Commit) {
                Start-Process $ExecPath -Wait -ArgumentList $Cmd
                Start-Sleep 10
                Write-Host "`tstatus.... completed"
            }
        }
        elseif ($PkgType -eq "LDAP") {
            Write-Host "`tscript.... branched"
        }
        elseif ($PkgType -eq "FEATURE") {
            if ($PayLoad.EndsWith(".xml")) {
                Write-Host "`tfeature... xml parse"
                $AltWinSrc = Get-AltWinSource
                if ($AltWinSrc -ne "") {
                    Install-WindowsFeature -ConfigurationFilePath $ScriptPath\$PayLoad -Source $AltWinSrc
                }
                else {
                    Install-WindowsFeature -ConfigurationFilePath $ScriptPath\$PayLoad
                }
            }
            else {
                Write-Host "`tfeature... other"
            }
        }
        else {
            Write-Host "`tunknown... invalid payload type ($PkgType)" -ForegroundColor DarkYellow
        }
    }
    <#

    $SetupFile = "wusa.exe"
    Write-Host "Installing Hotfix KB 3095113"
    Start-Process -FilePath $SetupFile -Wait -ArgumentList "$SourcePath\Windows8.1-KB3095113-x64.msu /quiet /norestart"
    Write-Host "done!"
    #>
}

