# =====================================================================================================
#  Morning Health Check - configuration
#
#  Copy this file to HealthCheck.config.psd1 (same folder) and edit it. That copy is ignored by git so
#  your inventory stays out of the repository.
#
#  NO PASSWORDS HERE. "Credential = 'netapp'" refers to a credential stored encrypted with
#      .\Set-HealthCheckCredential.ps1 -Name netapp        (or -Missing to create all of them)
#  run as the same Windows account the scheduled task uses.
#
#  Syntax: this is a PowerShell data file - only text, numbers, $true/$false/$null, @( ) lists and
#  @{ } tables are allowed. Test it with:  Import-PowerShellDataFile .\config\HealthCheck.config.psd1
# =====================================================================================================
@{
    General    = @{
        Title         = 'Morning Infrastructure Health Check'
        Organization  = 'Contoso IT'
        ThrottleLimit = 8          # systems checked in parallel
        TimeoutSec    = 20         # per network request
        TcpTimeoutMs  = 3000
        MaxRunMinutes = 20         # a system that has not finished by then is reported as Unknown
        KeepDays      = 30         # reports and logs older than this are deleted
        # ReportFolder = 'Reports'; LogFolder = 'Logs'; CredentialFolder = 'Credentials'   (relative to the script)
    }

    Email      = @{
        Enabled                = $true
        SmtpServer             = 'mail.contoso.local'   # Exchange server / receive connector that may relay to the internet
        Port                   = 25                     # 25 = anonymous relay connector; 587 = authenticated client submission
        UseStartTls            = $false                 # $true for 587 (required when Credential is set)
        Credential             = $null                  # e.g. 'smtp' - a mailbox account, only for authenticated submission
        From                   = 'Infrastructure Health Check <healthcheck@contoso.com>'
        To                     = @('your.name@gmail.com')
        Cc                     = @()
        SubjectPrefix          = 'Morning Health Check'
        UseEmojiInSubject      = $true                  # red / yellow / green dot in front of the subject
        HighPriorityOnCritical = $true
        AttachFullReport       = $true                  # complete report (every check, certificate, license) as .html
        ShowAddresses          = $true                  # $false hides host names / IPs under the system names
        CertificateDays        = 90                     # e-mail lists certificates expiring within N days (attachment lists all)
        LicenseDays            = 120                    # same for licenses / subscriptions
    }

    # Every value has a sensible default - keep only what you want to change.
    Thresholds = @{
        CertWarningDays          = 30
        CertCriticalDays         = 7
        CertUntrustedStatus      = 'Info'    # 'Warning' to flag certificates this server does not trust (self-signed etc.)
        LicenseWarningDays       = 60
        LicenseCriticalDays      = 14
        DiskFreeWarningPct       = 15
        DiskFreeCriticalPct      = 5
        AggregateUsedWarningPct  = 85
        AggregateUsedCriticalPct = 95
        VolumeUsedWarningPct     = 90
        VolumeUsedCriticalPct    = 97
        DatastoreUsedWarningPct  = 85
        DatastoreUsedCriticalPct = 95
        TimeSkewWarningSec       = 5
        TimeSkewCriticalSec      = 60
        ReplicationWarningHours  = 24
        SnapMirrorLagWarningHours = 26
        BackupMaxAgeHours        = 36
        StaleAgentDays           = 7
        StaleAgentWarningPct     = 10
        StaleAgentCriticalPct    = 25
    }

    # Settings applied to all targets of a type (any target can override any of them).
    Defaults   = @{
        All               = @{
            Ping                 = $true     # $false where ICMP is blocked
            SkipCertificateCheck = $true     # API calls accept self-signed appliance certificates. The certificate is
                                             # still inspected and reported; set $false where the CA is trusted.
            IgnoreCertificates   = @()       # wildcards on friendly name / CN / thumbprint, e.g. 'old-test-*'
        }
        DomainController  = @{
            # Credential = $null -> runs as the scheduled-task account (Kerberos). Recommended.
            Ports            = @(53, 88, 135, 389, 445, 636)
            Services         = @('NTDS', 'Netlogon', 'Kdc', 'W32Time', 'DFSR', 'ADWS')
            OptionalServices = @('DNS', 'IsmServ')     # checked only when installed
            CheckLdaps       = $true
            CheckReplication = $true
            CheckActivation  = $true
            CheckCertificateStore = $true
        }
        NetApp            = @{ Credential = 'netapp'; CertificateTypes = @('server', 'client'); IgnoreVolumes = @() }
        VCenter           = @{ Credential = 'vcenter'; CheckBackup = $true; IgnoreDatastores = @() }
        ForcepointProxy   = @{
            ProxyPort   = 8080
            ManagerPort = 8081                       # Content Gateway Manager (its certificate is checked)
            TestUrls    = @('https://www.google.com/generate_204', 'http://www.msftconnecttest.com/connecttest.txt')
            UseDefaultCredentials = $true            # authenticate to the proxy as the task account (NTLM/Kerberos)
            # BlockTestUrl          = 'http://www.example-blocked-category.test/'   # a URL your policy blocks
            # BlockPageKeyword      = 'Forcepoint'
            # SslInspectionTestHost = 'www.microsoft.com'                          # a site you decrypt
            # SslInspectionCAName   = 'Contoso Web Inspection CA'
        }
        ForcepointManager = @{ ConsolePort = 9443; ServicePatterns = @('Websense*', 'Forcepoint*', 'TRITON*') }
        Portnox           = @{ ConsolePort = 443; ServicePatterns = @('*Portnox*'); CheckCertificateStore = $true }
        Juniper           = @{ Credential = 'juniper'; IgnoreAlarms = @('*Rescue configuration is not set*') }
        CheckPoint        = @{ Credential = 'checkpoint' }
        TrellixESM        = @{ Credential = 'trellix-esm'; CheckAlarms = $true }
        TrellixEPO        = @{
            Credential = 'trellix-epo'; Port = 8443
            # Are the signatures (AMCore content / DAT) up to date - on the systems and in the master repository?
            Signatures = @{
                MaxAgeDays           = 3     # content older than this is out of date (ePO's own compliance query uses 7)
                WarningPct           = 5     # share of managed systems out of date -> Warning
                CriticalPct          = 15    # ... -> Critical
                RepositoryMaxAgeDays = 2     # content is released daily: warn when nothing newer arrived for this long
                # QueryId            = 456   # only if the automatic detection reports Unknown - see README
            }
        }
        TrellixEDR        = @{ }
    }

    Targets    = @(
        # ------------------------------------------------------------------ Domain controllers
        # Discover every DC of a domain (needs the ActiveDirectory PowerShell module):
        @{ Type = 'DomainController'; Discover = 'contoso.local'; Exclude = @('OLD-DC*') }
        # ...or list them:
        # @{ Type = 'DomainController'; Name = 'DC01'; Address = 'dc01.contoso.local' }

        # ------------------------------------------------------------------ NetApp (cluster management LIF)
        @{ Type = 'NetApp'; Name = 'NA-PROD'; Address = 'na-prod.contoso.local' }
        @{ Type = 'NetApp'; Name = 'NA-DR'; Address = 'na-dr.contoso.local' }

        # ------------------------------------------------------------------ vCenter
        @{ Type = 'VCenter'; Name = 'VC01'; Address = 'vc01.contoso.local' }

        # ------------------------------------------------------------------ Forcepoint
        @{ Type = 'ForcepointProxy'; Name = 'FP-PROXY1'; Address = 'fp-proxy1.contoso.local' }
        @{ Type = 'ForcepointProxy'; Name = 'FP-PROXY2'; Address = 'fp-proxy2.contoso.local' }
        @{
            Type     = 'ForcepointManager'; Name = 'FP-MGMT'; Address = 'fp-mgmt.contoso.local'
            # WindowsCredential = 'windows-admin'   # only if the task account cannot reach it via WinRM
            Licenses = @(
                # Not readable through an API - copy the date from the Security Manager "Subscription" page.
                @{ Name = 'Forcepoint Web Security subscription'; Expires = '2027-06-30'; Usage = '2,500 users' }
            )
        }

        # ------------------------------------------------------------------ Portnox CORE
        @{
            Type     = 'Portnox'; Name = 'PORTNOX01'; Address = 'portnox01.contoso.local'
            # Real RADIUS test: add this server as a RADIUS client in Portnox, store the shared secret with
            #   .\Set-HealthCheckCredential.ps1 -Name portnox-radius-secret -UserName radius   (secret = password)
            # Radius = @{ SecretCredential = 'portnox-radius-secret'; Port = 1812 }
            Licenses = @( @{ Name = 'Portnox CORE license'; Expires = '2027-03-31'; Usage = '1,800 devices' } )
        }

        # ------------------------------------------------------------------ Juniper switches (SSH, needs Posh-SSH)
        @{ Type = 'Juniper'; Name = 'CORE-SW1'; Address = '10.10.0.1' }
        @{ Type = 'Juniper'; Name = 'CORE-SW2'; Address = '10.10.0.2' }
        # @{ Type = 'Juniper'; Name = 'ACC-SW-1F'; Address = '10.10.1.11'; HttpsPort = 443 }   # also check the J-Web certificate

        # ------------------------------------------------------------------ Check Point cluster
        @{
            Type    = 'CheckPoint'; Name = 'FW-CLUSTER'; Address = 'cp-mgmt.contoso.local'   # Management server (API)
            Members = @(
                @{ Name = 'fw-a'; Address = '10.0.0.2' }      # Name = gateway object name in SmartConsole
                @{ Name = 'fw-b'; Address = '10.0.0.3' }
            )
            ManagementObjectName = 'cp-mgmt'                   # optional: also check the management server itself
            # Domain = 'MyDomain'                              # Multi-Domain Server only
        }

        # ------------------------------------------------------------------ Trellix
        @{
            Type = 'TrellixESM'; Name = 'ESM01'; Address = 'esm01.contoso.local'
            Licenses = @( @{ Name = 'Trellix SIEM support'; Expires = '2027-08-31' } )
        }
        @{
            Type         = 'TrellixEPO'; Name = 'EPO01'; Address = 'epo01.contoso.local'
            SavedQueries = @(
                # Any ePO query you saved (Menu > Queries & Reports, the ID is in the URL). Alerts on the row count.
                # @{ Id = 123; Name = 'Systems without Endpoint Security installed'; WarningAbove = 0; CriticalAbove = 25 }
            )
            Licenses     = @( @{ Name = 'Trellix Endpoint Security'; Expires = '2027-01-31'; Usage = '1,600 nodes' } )
        }
        @{
            Type     = 'TrellixEDR'; Name = 'EDR'; Url = 'https://edr.contoso.local/'   # console URL (on-prem or SaaS)
            Licenses = @( @{ Name = 'Trellix EDR'; Expires = '2027-01-31'; Usage = '1,600 nodes' } )
        }

        # ------------------------------------------------------------------ anything else
        # @{ Type = 'WindowsServer'; Name = 'EXCH01'; Address = 'exch01.contoso.local'; ServicePatterns = @('MSExchange*') }
        # @{ Type = 'WebService'; Name = 'Intranet'; Url = 'https://intranet.contoso.local/'; Keyword = 'Welcome' }
    )
}
