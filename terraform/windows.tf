# Data source to get latest Windows Server 2022 AMI
data "aws_ami" "windows" {
  most_recent = true
  owners      = [var.windows_ami_owner]

  filter {
    name   = "name"
    values = [var.windows_ami_name_filter]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Windows Security Events Server
resource "aws_instance" "windows" {
  ami                    = data.aws_ami.windows.id
  instance_type          = "t3.small"
  key_name               = aws_key_pair.demo.key_name
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.windows.id]
  get_password_data      = true

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  user_data = <<-EOF
              <powershell>
              # Log output
              Start-Transcript -Path "C:\cribl-demo-setup.log" -Append

              Write-Host "=========================================="
              Write-Host "Windows Security Events Server Setup"
              Write-Host "Starting: $(Get-Date)"
              Write-Host "=========================================="

              # Set administrator password
              Write-Host "[1/7] Setting administrator password..."
              $Password = ConvertTo-SecureString "${var.windows_admin_password}" -AsPlainText -Force
              Set-LocalUser -Name "Administrator" -Password $Password

              # Enable WinRM
              Write-Host "[2/7] Enabling WinRM..."
              Enable-PSRemoting -Force -SkipNetworkProfileCheck
              Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
              Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true -Force

              # Enable command-line logging in process creation events
              Write-Host "[3/7] Enabling advanced audit policies..."
              $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
              if (-not (Test-Path $regPath)) {
                  New-Item -Path $regPath -Force | Out-Null
              }
              Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force

              # Enable audit policies
              auditpol /set /subcategory:"Logon" /success:enable /failure:enable
              auditpol /set /subcategory:"Logoff" /success:enable
              auditpol /set /subcategory:"Account Lockout" /failure:enable
              auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
              auditpol /set /subcategory:"Process Creation" /success:enable
              auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

              # Download and install NXLog Community Edition
              Write-Host "[4/7] Downloading NXLog Community Edition..."
              $nxlogUrl = "https://nxlog.co/system/files/products/files/348/nxlog-ce-3.2.2329-1_x64.msi"
              $nxlogInstaller = "C:\nxlog-ce.msi"

              try {
                  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                  Invoke-WebRequest -Uri $nxlogUrl -OutFile $nxlogInstaller -UseBasicParsing
              } catch {
                  Write-Host "Failed to download NXLog from primary URL, trying alternative..."
                  # Alternative: Download from GitHub releases or other mirror
                  Write-Host "Please download NXLog manually from https://nxlog.co/downloads/nxlog-ce"
              }

              Write-Host "[5/7] Installing NXLog..."
              if (Test-Path $nxlogInstaller) {
                  Start-Process msiexec.exe -ArgumentList "/i", $nxlogInstaller, "/quiet", "/norestart" -Wait
              }

              # Configure NXLog
              Write-Host "[6/7] Configuring NXLog..."
              $criblIp = "${aws_instance.cribl.private_ip}"
              $nxlogConf = @"
              ## NXLog Configuration for Cribl Demo
              ## Forwards Windows Security events to Cribl Stream

              define ROOT C:\Program Files\nxlog

              Moduledir %ROOT%\modules
              CacheDir %ROOT%\data
              Pidfile %ROOT%\data\nxlog.pid
              SpoolDir %ROOT%\data
              LogFile %ROOT%\data\nxlog.log

              <Extension _syslog>
                  Module      xm_syslog
              </Extension>

              <Input in_security>
                  Module      im_msvistalog
                  Query       <QueryList>\
                                  <Query Id="0">\
                                      <Select Path="Security">*</Select>\
                                  </Query>\
                              </QueryList>
              </Input>

              <Input in_system>
                  Module      im_msvistalog
                  Query       <QueryList>\
                                  <Query Id="0">\
                                      <Select Path="System">*</Select>\
                                  </Query>\
                              </QueryList>
              </Input>

              <Output out_cribl>
                  Module      om_tcp
                  Host        $criblIp
                  Port        9514
                  Exec        to_syslog_bsd();
              </Output>

              <Route security_to_cribl>
                  Path        in_security => out_cribl
              </Route>

              <Route system_to_cribl>
                  Path        in_system => out_cribl
              </Route>
              "@

              $nxlogConfPath = "C:\Program Files\nxlog\conf\nxlog.conf"
              if (Test-Path (Split-Path $nxlogConfPath -Parent)) {
                  $nxlogConf | Out-File -FilePath $nxlogConfPath -Encoding UTF8 -Force
              }

              # Start NXLog service
              Write-Host "[7/7] Starting NXLog service..."
              if (Get-Service -Name nxlog -ErrorAction SilentlyContinue) {
                  Set-Service -Name nxlog -StartupType Automatic
                  Start-Service -Name nxlog
              }

              # Create demo script for generating security events
              $demoScript = @'
              # Generate demo security events
              Write-Host "Generating Windows Security Events for demo..."

              # Generate failed logon (Event 4625)
              Write-Host "Generating failed logon attempt..."
              $null = Start-Process -FilePath "net" -ArgumentList "use \\localhost\c$ /user:fakeuser wrongpassword" -NoNewWindow -Wait 2>$null

              # Create and delete test user (Events 4720, 4726)
              Write-Host "Creating and deleting test user..."
              net user DemoTestUser P@ssw0rd123! /add 2>$null
              net user DemoTestUser /delete 2>$null

              # Process creation (Event 4688)
              Write-Host "Generating process creation events..."
              whoami
              hostname
              ipconfig /all
              systeminfo

              Write-Host ""
              Write-Host "Security events generated!"
              Write-Host "Check Windows Event Viewer -> Security log"
              Write-Host "Events should appear in Cribl shortly."
              '@

              $demoScript | Out-File -FilePath "C:\generate-security-events.ps1" -Encoding UTF8 -Force

              # Create info file
              $privateIp = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" } | Select-Object -First 1).IPAddress
              $infoContent = @"
              Cribl Elastic Demo - Windows Security Events Server
              Generated: $(Get-Date)

              Server Information:
                Hostname: $env:COMPUTERNAME
                Private IP: $privateIp

              Credentials:
                Username: Administrator
                Password: (set via terraform variable)

              NXLog Configuration:
                Config: C:\Program Files\nxlog\conf\nxlog.conf
                Logs: C:\Program Files\nxlog\data\nxlog.log
                Service: nxlog
                Forwarding to: ${aws_instance.cribl.private_ip}:9514 (TCP)

              Audit Policies Enabled:
                - Logon/Logoff
                - Account Lockout
                - User Account Management
                - Process Creation
                - Credential Validation
                - Command-line logging

              Demo Script:
                C:\generate-security-events.ps1

              Useful Commands:
                # Check NXLog status
                Get-Service nxlog

                # View NXLog log
                Get-Content "C:\Program Files\nxlog\data\nxlog.log" -Tail 50

                # View Security events
                Get-WinEvent -LogName Security -MaxEvents 20

                # Generate test events
                .\generate-security-events.ps1

              Setup Log: C:\cribl-demo-setup.log
              "@

              $infoContent | Out-File -FilePath "C:\cribl-demo-info.txt" -Encoding UTF8 -Force

              Write-Host ""
              Write-Host "=========================================="
              Write-Host "Windows Security Events Setup Complete!"
              Write-Host "Completed: $(Get-Date)"
              Write-Host "=========================================="
              Write-Host ""
              Write-Host "Forwarding security events to: $criblIp`:9514"

              Stop-Transcript
              </powershell>
              EOF

  tags = {
    Name = "windows-security"
    Role = "windows"
  }

  depends_on = [aws_instance.cribl]
}
