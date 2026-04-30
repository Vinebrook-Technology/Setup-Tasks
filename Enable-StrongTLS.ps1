#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Configures secure TLS settings on Windows systems with SQL Server compatibility awareness.


.DESCRIPTION
This script hardens TLS configuration by enabling modern protocols, disabling weak protocols
when safe, configuring cipher suites, and enforcing strong cryptographic defaults for SCHANNEL
and .NET applications.

The script performs the following actions in order:

- Enables TLS 1.2 for both Server and Client SCHANNEL roles.
- Enables TLS 1.3 only when the operating system supports it (Windows build 20348 or newer).
- Detects installed SQL Server Database Engine instances and evaluates their version/build.
- Determines whether TLS 1.0 can be safely disabled based on SQL Server TLS 1.2 readiness.
- Disables TLS 1.0 only when SQL Server is not present or confirmed compatible with TLS 1.2.
- Disables TLS 1.1 and SSL 3.0 for all systems.
- Disables weak SCHANNEL ciphers, including DES, 3DES, RC2, RC4, and NULL ciphers.
- Enables strong SCHANNEL ciphers (AES 128 and AES 256).
- Configures TLS cipher suite order:
  - Includes TLS 1.3 cipher suites only when supported by the OS.
  - Prioritizes ECDHE and DHE GCM cipher suites.
  - Optionally allows a CBC fallback cipher when SystemType is set to Server.
- Applies cipher suite order via both local and policy registry paths.
- Configures ECDH elliptic curve priority (NistP384, NistP256).
- Disables weak TLS cipher suites using Disable-TlsCipherSuite when available:
  - NULL, RC4, DES, 3DES, MD5, and optionally CBC cipher suites.
- Configures .NET Framework (v2.0 and v4.x, 32-bit and 64-bit) to:
  - Use strong cryptography (SchUseStrongCrypto = 1)
  - Use system default TLS versions (SystemDefaultTlsVersions = 1)
- Outputs the current TLS cipher suite configuration after applying changes.
- Supports a full revert mode that removes all applied registry overrides.
- Recommends or performs a system reboot to ensure all changes take effect.

The script is designed to avoid breaking SQL Server connectivity by conditionally
preserving TLS 1.0 when compatibility cannot be guaranteed.

.LINKS
https://www.vinebrooktechnology.com/

.NOTES
Last Modified: 4/30/2026
Author: Robert Osborne (Vinebrook Technology)
#>

Function Configure-TLSSettings {
<#
.SYNOPSIS
Configures TLS settings on Windows systems.


.DESCRIPTION
Enables TLS 1.2, enables TLS 1.3 when supported, disables weak protocols when safe,
configures SCHANNEL ciphers, configures cipher suite order, configures ECDH curve order,
and configures .NET strong cryptography.

TLS 1.0 will only be disabled when SQL Server is not installed, or installed SQL Server
versions are determined to be TLS 1.2-ready.


.PARAMETER SystemType
Select 'Server' or 'Workstation'. Controls whether a CBC fallback suite is allowed.

.PARAMETER Revert
Reverts TLS settings by removing registry overrides.

.PARAMETER Reboot
Reboots the system after applying changes.
#>
[CmdletBinding()]
    param (
        [Parameter(
            Mandatory=$False
        )]  # End Parameter
        [ValidateSet('Server','Workstation')]
        [String]$SystemType = 'Workstation',

        [Parameter(
            Mandatory=$False
        )]  # End Parameter
        [Switch]$Revert,

        [Parameter(
            Mandatory=$False
        )]  # End Parameter
        [Switch]$Reboot
    )  # End param

    Function Set-RegistryValue {
        param (
            [Parameter(
                Mandatory=$True
            )]  # End Parameter
            [String]$Path,
            
            [Parameter(
                Mandatory=$True
            )]  # End Parameter
            [String]$Name,
            
            [Parameter(
                Mandatory=$True
            )]  # End Parameter
            [Object]$Value,

            [Parameter(
                Mandatory=$False
            )]  # End Parameter
            [ValidateSet('DWord','QWord','String','MultiString')]
            [String]$Type = 'DWord'
        )  # End param

        If (-NOT (Test-Path -Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }  # End If
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null

    }  # End Function Set-RegistryValue

    Function Remove-RegistryItem {
        param (
            [Parameter(
                Mandatory=$True
            )]  # End Parameter
            [String]$Path,

            [Parameter(
                Mandatory=$False
            )]  # End Parameter
            [String]$Name = $Null
        )  # End param

        If ($Name) {
            If (Test-Path -Path $Path) {
                Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            }  # End If
        } Else {
            If (Test-Path -Path $Path) {
                Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
            }  # End If
        }  # End If Else
        
    }  # End Function Remove-RegistryItem

    Function Set-CipherRegistryValue {
        param (
            [Parameter(
                Mandatory=$True
            )]  # End Parameter
            [String]$CipherName,
            
            [Parameter(
                Mandatory=$True
            )]  # End Parameter
            [String]$Name,
            
            [Parameter(
                Mandatory=$True
            )]  # End Parameter
            [Int]$Value,
            
            [Microsoft.Win32.RegistryValueKind]$Type = [Microsoft.Win32.RegistryValueKind]::DWord
        )  # End param

        $BaseKeyPath = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers'
        $KeyPath = "$($BaseKeyPath)\$($CipherName)"
        $RegKey = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($KeyPath)
        $RegKey.SetValue($Name, $Value, $Type)
        $RegKey.Close()

    }  # End Function Set-CipherRegistryValue

    Function Remove-CipherRegistryItem {
        param (
            [Parameter(
                Mandatory=$True
            )]  # End Parameter
            [String]$CipherName,
            
            [Parameter(
                Mandatory=$True
            )]  # End Parameter
            [String]$Name
        )  # End param

        $BaseKeyPath = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers'
        $KeyPath = "$($BaseKeyPath)\$($CipherName)"
        $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($KeyPath, $True)
        If ($RegKey) {
            $RegKey.DeleteValue($Name, $False)
            $RegKey.Close()
        }  # End If

    }  # End Function Remove-CipherRegistryItem

    Function Get-SQLServerInstallations {
    
        $SqlInstances = @()
        $InstanceRootPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL"
        )

        ForEach ($InstanceRootPath in $InstanceRootPaths) {
        
            If (Test-Path -Path $InstanceRootPath) {
            
                $InstanceNames = Get-ItemProperty -Path $InstanceRootPath
                ForEach ($Property in $InstanceNames.PSObject.Properties) {
                
                    If ($Property.Name -notlike "PS*") {
                    
                        $InstanceName = $Property.Name
                        $InstanceId = $Property.Value
                        $SetupPaths = @(
                            "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$InstanceId\Setup",
                            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Microsoft SQL Server\$InstanceId\Setup"
                        )

                        ForEach ($SetupPath in $SetupPaths) {
                        
                            If (Test-Path -Path $SetupPath) {
                            
                                $Setup = Get-ItemProperty -Path $SetupPath
                                $SqlInstances += [PSCustomObject]@{
                                    InstanceName  = $InstanceName
                                    InstanceId    = $InstanceId
                                    Version       = $Setup.Version
                                    Edition       = $Setup.Edition
                                    PatchLevel    = $Setup.PatchLevel
                                    SqlProgramDir = $Setup.SQLProgramDir
                                }
                                
                            }  # End If
                            
                        }  # End ForEach
                        
                    }  # End If
                    
                }  # End ForEach
            }  # End If
            
        }  # End ForEach

        Return $SqlInstances

    }  # End Function Get-SQLServerInstallations

    Function Test-SQLServerTls10CanBeDisabled {
    
        $SqlInstances = Get-SQLServerInstallations
        If (-NOT $SqlInstances -or $SqlInstances.Count -eq 0) {
            Write-Output -InputObject "No SQL Server Database Engine instances detected. TLS 1.0 can be disabled."
            Return $True
        }  # End If

        Write-Output -InputObject "SQL Server Database Engine instance detected. Checking SQL Server TLS 1.2 readiness..."
        ForEach ($SqlInstance in $SqlInstances) {
        
            $VersionString = $SqlInstance.Version
            Write-Output -InputObject "Detected SQL Server instance $($SqlInstance.InstanceName), version $VersionString, edition $($SqlInstance.Edition)"
            If (-not $VersionString) {
                Write-Warning -Message "SQL Server instance $($SqlInstance.InstanceName) version could not be determined. TLS 1.0 will not be disabled."
                Return $False
            }  # End If

            Try {
                $Version = [Version]$VersionString
            } Catch {
                Write-Warning -Message "SQL Server instance $($SqlInstance.InstanceName) version $VersionString could not be parsed. TLS 1.0 will not be disabled."
                Return $False
            }  # End Try Catch

            $Major = $Version.Major
            $Build = $Version.Build
            Switch ($Major) {

                17 {
                    # SQL Server 2025+
                    Continue
                } 16 {
                    # SQL Server 2022
                    Continue
                } 15 {
                    # SQL Server 2019
                    Continue
                } 14 {
                    # SQL Server 2017
                    Continue
                } 13 {
                    # SQL Server 2016
                    Continue
                } 12 {
                    # SQL Server 2014
                    If ($Build -ge 4219) {
                        Continue
                    } Else {
                        Write-Warning -Message "SQL Server 2014 instance $($SqlInstance.InstanceName) build $VersionString may not be TLS 1.2-ready. TLS 1.0 will not be disabled."
                        Return $False
                    }
                } 11 {
                    # SQL Server 2012
                    If ($Build -ge 5352) {
                        Continue
                    } Else {
                        Write-Warning -Message "SQL Server 2012 instance $($SqlInstance.InstanceName) build $VersionString may not be TLS 1.2-ready. TLS 1.0 will not be disabled."
                        Return $False
                    }
                } 10 {
                    # SQL Server 2008 / 2008 R2
                    Write-Warning -Message "SQL Server 2008 / 2008 R2 instance $($SqlInstance.InstanceName) detected. TLS 1.0 will not be disabled automatically."
                    Return $False
                } Default {
                    Write-Warning -Message "Unsupported or unknown SQL Server version $VersionString detected on instance $($SqlInstance.InstanceName). TLS 1.0 will not be disabled."
                    Return $False
                }  # End Switch Options

            }  # End Switch
            
        }  # End Function Test-SQLServerTls10CanBeDisabled

        Write-Output -InputObject "All detected SQL Server instances appear TLS 1.2-ready. TLS 1.0 can be disabled."
        Return $True

    }  # End Function Test-SQLServerTls10CanBeDisabled

    $CbcFallbackSuite = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
    $AllowCbcFallback = ($SystemType -eq 'Server')

    $Os = Get-CimInstance -ClassName Win32_OperatingSystem
    $BuildNumberInt = [Int]$Os.BuildNumber

    # TLS 1.3 is restricted here to Windows Server 2022 / Windows build 20348 or newer.
    $IsTls13Supported = ($BuildNumberInt -ge 20348)
    If (-NOT $Revert) {

        # Enable TLS 1.2
        $Tls12Paths = @(
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server",
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"
        )

        ForEach ($Path in $Tls12Paths) {
            Set-RegistryValue -Path $Path -Name "Enabled" -Value 1 -Type DWord
            Set-RegistryValue -Path $Path -Name "DisabledByDefault" -Value 0 -Type DWord
        }  # End ForEach

        # Enable TLS 1.3 If supported
        If ($IsTls13Supported) {
        
            $Tls13Paths = @(
                "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server",
                "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client"
            )
            ForEach ($Path in $Tls13Paths) {
                Set-RegistryValue -Path $Path -Name "Enabled" -Value 1 -Type DWord
                Set-RegistryValue -Path $Path -Name "DisabledByDefault" -Value 0 -Type DWord
            }  # End ForEach
            Write-Output -InputObject "TLS 1.3 enabled because OS build $BuildNumberInt supports it."
            
        } Else {
            Write-Warning -Message "TLS 1.3 was not enabled because OS build $BuildNumberInt is below build 20348."
        }  # End If Else

        # Determine If TLS 1.0 can be safely disabled
        $CanDisableTls10 = Test-SQLServerTls10CanBeDisabled
        If ($CanDisableTls10) {
        
            $OldProtocols = @(
                @{ Protocol = "TLS 1.0"; Type = "Server" },
                @{ Protocol = "TLS 1.0"; Type = "Client" },
                @{ Protocol = "TLS 1.1"; Type = "Server" },
                @{ Protocol = "TLS 1.1"; Type = "Client" },
                @{ Protocol = "SSL 3.0"; Type = "Server" },
                @{ Protocol = "SSL 3.0"; Type = "Client" }
            )
            
        } Else {
            $OldProtocols = @(
                @{ Protocol = "TLS 1.1"; Type = "Server" },
                @{ Protocol = "TLS 1.1"; Type = "Client" },
                @{ Protocol = "SSL 3.0"; Type = "Server" },
                @{ Protocol = "SSL 3.0"; Type = "Client" }
            )
            Write-Warning -Message "TLS 1.0 was left unchanged because SQL Server compatibility could not be confirmed."
            
        }  # End If Else

        ForEach ($Item in $OldProtocols) {
        
            $Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$($Item.Protocol)\$($Item.Type)"
            Set-RegistryValue -Path $Path -Name "Enabled" -Value 0 -Type DWord
            Set-RegistryValue -Path $Path -Name "DisabledByDefault" -Value 1 -Type DWord
            
        }  # End ForEach

        # Disable weak SCHANNEL ciphers
        $WeakCiphers = @(
            'DES 56/56',
            'Triple DES 168/168',
            'NULL',
            'RC2 40/128',
            'RC2 56/128',
            'RC2 128/128',
            'RC4 40/128',
            'RC4 56/128',
            'RC4 64/128',
            'RC4 128/128'
        )

        ForEach ($Cipher in $WeakCiphers) {
            Set-CipherRegistryValue -CipherName $Cipher -Name "Enabled" -Value 0
        }  # End ForEach

        # Enable strong SCHANNEL ciphers
        $StrongCiphers = @(
            'AES 256/256',
            'AES 128/128'
        )

        ForEach ($Cipher in $StrongCiphers) {
            Set-CipherRegistryValue -CipherName $Cipher -Name "Enabled" -Value 1
        }  # End ForEach

        # Cipher suite order
        $CipherSuites = @()
        If ($IsTls13Supported) {
            $CipherSuites += @(
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_AES_128_GCM_SHA256"
            )
        }  # End If

        $CipherSuites += @(
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
        )

        If ($AllowCbcFallback) {
            $CipherSuites += $CbcFallbackSuite
            Write-Output -InputObject "SystemType is Server: Allowing CBC fallback cipher suite $CbcFallbackSuite"
        } Else {
            Write-Output -InputObject "SystemType is Workstation: Not allowing CBC fallback cipher suites"
        }  # End If Else

        $CipherSuitePaths = @(
            "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002",
            "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002"
        )

        ForEach ($Path in $CipherSuitePaths) {
            Set-RegistryValue -Path $Path -Name "Functions" -Value $CipherSuites -Type MultiString
        }  # End ForEach

        # ECDH curve order
        $EccCurves = @(
            "NistP384",
            "NistP256"
        )

        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name "EccCurves" -Value $EccCurves -Type MultiString

        # Disable weak cipher suites
        If (Get-Command -Name Get-TlsCipherSuite -ErrorAction SilentlyContinue) {

            $AllSuites = Get-TlsCipherSuite

            If ($AllowCbcFallback) {
            
                $DisableSuites = $AllSuites | Where-Object -FilterScript {
                    ($_.Name -like "*_NULL_*") -or
                    ($_.Name -like "*_RC4_*") -or
                    ($_.Name -like "*_3DES_*") -or
                    ($_.Name -like "*_DES_*") -or
                    ($_.Name -like "*_MD5") -or
                    ($_.Name -like "*_CBC_*" -and $_.Name -ne $CbcFallbackSuite)
                }
                
            } Else {
            
                $DisableSuites = $AllSuites | Where-Object -FilterScript {
                    ($_.Name -like "*_NULL_*") -or
                    ($_.Name -like "*_RC4_*") -or
                    ($_.Name -like "*_3DES_*") -or
                    ($_.Name -like "*_DES_*") -or
                    ($_.Name -like "*_MD5") -or
                    ($_.Name -like "*_CBC_*")
                }
                
            }  # End If Else

            ForEach ($Suite in $DisableSuites) {
                Write-Output -InputObject "Disabling TLS Cipher Suite $($Suite.Name)"
                Disable-TlsCipherSuite -Name $Suite.Name -ErrorAction SilentlyContinue
            }  # End ForEach

        } Else {
            Write-Warning -Message "Get-TlsCipherSuite is not available on this system. Skipping per-suite disable operations."
        }  # End If Else

        # Configure .NET to use strong cryptography and system defaults
        $NetPaths = @(
            "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727",
            "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
        )

        ForEach ($Path in $NetPaths) {
            Set-RegistryValue -Path $Path -Name "SchUseStrongCrypto" -Value 1 -Type DWord
            Set-RegistryValue -Path $Path -Name "SystemDefaultTlsVersions" -Value 1 -Type DWord
        }  # End ForEach

        Write-Output -InputObject "TLS settings configured successfully."
        If (Get-Command -Name Get-TlsCipherSuite -ErrorAction SilentlyContinue) {
            Write-Output -InputObject "Current TLS Cipher Suites:"
            Get-TlsCipherSuite | Select-Object -Property Name
        }  # End If

    } Else {

        # Revert TLS 1.2 and TLS 1.3 overrides
        $TlsPaths = @(
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server",
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client",
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server",
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client"
        )

        ForEach ($Path in $TlsPaths) {
            Remove-RegistryItem -Path $Path -Name "Enabled"
            Remove-RegistryItem -Path $Path -Name "DisabledByDefault"
        }  # End ForEach

        # Revert old protocol overrides
        $OldProtocolPaths = @(
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server",
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client",
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server",
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client",
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server",
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client"
        )

        ForEach ($Path in $OldProtocolPaths) {
            Remove-RegistryItem -Path $Path -Name "Enabled"
            Remove-RegistryItem -Path $Path -Name "DisabledByDefault"
        }  # End ForEach

        # Remove cipher configurations
        $Ciphers = @(
            'DES 56/56',
            'Triple DES 168/168',
            'NULL',
            'RC2 40/128',
            'RC2 56/128',
            'RC2 128/128',
            'RC4 40/128',
            'RC4 56/128',
            'RC4 64/128',
            'RC4 128/128',
            'AES 256/256',
            'AES 128/128'
        )

        ForEach ($Cipher in $Ciphers) {
            Remove-CipherRegistryItem -CipherName $Cipher -Name "Enabled"
        }  # End ForEach

        # Remove cipher suite order and ECDH curve order
        Remove-RegistryItem -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name "Functions"
        Remove-RegistryItem -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name "EccCurves"
        Remove-RegistryItem -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002" -Name "Functions"

        # Remove .NET strong crypto settings
        $NetPaths = @(
            "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727",
            "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
        )

        ForEach ($Path in $NetPaths) {
            Remove-RegistryItem -Path $Path -Name "SchUseStrongCrypto"
            Remove-RegistryItem -Path $Path -Name "SystemDefaultTlsVersions"
        }  # End ForEach

        Write-Output -InputObject "TLS settings reverted to default."

    }  # End If Else

    If ($Reboot) {
        Write-Output -InputObject "Initiating system reboot to apply changes..."
        Restart-Computer -Force
    } Else {
        Write-Warning -Message "A system reboot is recommended to apply changes."
    }  # End If Else

}  # End Function Configure-TLSSettings
