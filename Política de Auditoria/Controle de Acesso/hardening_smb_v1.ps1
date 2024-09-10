# Verifica se o script está sendo executado com privilégios de administrador
If (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Este script precisa ser executado como administrador."
    Exit
}

# Função para verificar o status do SMB
Function Check-SMBStatus {
    Write-Output "`nVerificando status do SMB..."

    # Verifica se SMBv1 está instalado
    $smbv1Status = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol"
    Write-Output "SMBv1 Status: $($smbv1Status.State)"

    # Verifica se SMBv2 e SMBv3 estão habilitados
    $smbv2Status = Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB2Protocol
    If ($smbv2Status) {
        Write-Output "SMBv2/v3 está habilitado."
    } Else {
        Write-Output "SMBv2/v3 está desabilitado."
    }
}

# Função para desabilitar SMBv1
Function Disable-SMBv1 {
    Write-Output "`nDesabilitando SMBv1..."

    # Desativa o SMBv1 sem reiniciar imediatamente
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue

    # Verifica se o SMBv1 foi desativado com sucesso
    $smbv1Status = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol"
    If ($smbv1Status.State -eq "Disabled") {
        Write-Output "SMBv1 desabilitado com sucesso."

        # Salva o progresso para retomar depois
        Set-ItemProperty -Path "HKCU:\Software\SMB_Hardening" -Name "StepCompleted" -Value "DisableSMBv1"
    } Else {
        Write-Output "Falha ao desabilitar SMBv1."
    }
}

# Função para habilitar a criptografia para SMBv2/v3
Function Enable-SMBEncryption {
    Write-Output "`nHabilitando criptografia para SMBv2/v3..."

    # Habilita a criptografia SMBv2 e SMBv3
    Set-SmbServerConfiguration -EncryptData $true -Force

    # Verifica se a criptografia foi habilitada
    $encryptionStatus = Get-SmbServerConfiguration | Select-Object -ExpandProperty EncryptData
    If ($encryptionStatus -eq $true) {
        Write-Output "Criptografia para SMBv2/v3 habilitada com sucesso."

        # Salva o progresso para retomar depois
        Set-ItemProperty -Path "HKCU:\Software\SMB_Hardening" -Name "StepCompleted" -Value "EnableSMBEncryption"
    } Else {
        Write-Output "Falha ao habilitar a criptografia para SMBv2/v3."
    }
}

# Função para bloquear SMB no firewall
Function Block-SMBFirewall {
    $response = Read-Host "`nVocê deseja bloquear SMB no firewall? (S/N)"
    If ($response -eq "S" -or $response -eq "s") {
        Write-Output "`nBloqueando SMB no firewall..."

        # Bloqueia portas SMB no firewall (137, 138, 139, 445)
        $firewallRules = @("137", "138", "139", "445")
        ForEach ($port in $firewallRules) {
            New-NetFirewallRule -DisplayName "Block SMB Inbound Port $port" -Direction Inbound -Action Block -Protocol TCP -LocalPort $port -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName "Block SMB Outbound Port $port" -Direction Outbound -Action Block -Protocol TCP -LocalPort $port -ErrorAction SilentlyContinue
        }

        Write-Output "Regras de firewall adicionadas para bloquear SMB."

        # Salva o progresso para retomar depois
        Set-ItemProperty -Path "HKCU:\Software\SMB_Hardening" -Name "StepCompleted" -Value "BlockSMBFirewall"
    } Else {
        Write-Output "`nBloqueio de SMB no firewall cancelado pelo usuário."
    }
}

# Função para verificar o status do firewall SMB
Function Check-FirewallSMB {
    Write-Output "`nVerificando status do SMB no firewall..."

    $firewallRules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "Block SMB*" }
    If ($firewallRules) {
        Write-Output "SMB está bloqueado no firewall."
        $response = Read-Host "Você deseja habilitar SMB no firewall novamente? (S/N)"
        If ($response -eq "S" -or $response -eq "s") {
            Write-Output "`nHabilitando SMB no firewall..."

            # Remove as regras de bloqueio de SMB
            ForEach ($rule in $firewallRules) {
                Remove-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue
            }

            Write-Output "Regras de firewall removidas para permitir SMB."

            # Salva o progresso para retomar depois
            Set-ItemProperty -Path "HKCU:\Software\SMB_Hardening" -Name "StepCompleted" -Value "EnableSMBFirewall"
            # Define que uma reinicialização é necessária
            $restartRequired = $true
        } Else {
            Write-Output "`nSMB permanecerá bloqueado no firewall."
        }
    } Else {
        Write-Output "SMB não está bloqueado no firewall."
    }
}

# Função para verificar o progresso salvo e retomar a execução
Function Continue-AfterRestart {
    If (-Not (Test-Path "HKCU:\Software\SMB_Hardening")) {
        New-Item -Path "HKCU:\Software\SMB_Hardening" -Force | Out-Null
    }

    $stepCompleted = Get-ItemProperty -Path "HKCU:\Software\SMB_Hardening" -Name "StepCompleted" -ErrorAction SilentlyContinue
    $restartRequired = $false

    If ($stepCompleted -eq "DisableSMBv1") {
        Write-Output "`nRetomando após desativação do SMBv1..."
        Enable-SMBEncryption
        Block-SMBFirewall
        Check-FirewallSMB
        Write-Output "`nHardening de SMB concluído."
        $restartRequired = $true
    } ElseIf ($stepCompleted -eq "EnableSMBEncryption") {
        Write-Output "`nRetomando após habilitação da criptografia para SMBv2/v3..."
        Block-SMBFirewall
        Check-FirewallSMB
        Write-Output "`nHardening de SMB concluído."
        $restartRequired = $true
    } ElseIf ($stepCompleted -eq "BlockSMBFirewall") {
        Write-Output "`nTodas as etapas já foram concluídas anteriormente. Reinicie o sistema para aplicar as alterações."
    } ElseIf ($stepCompleted -eq "EnableSMBFirewall") {
        Write-Output "`nRetomando após habilitação do SMB no firewall..."
        Write-Output "`nHardening de SMB concluído."
    } Else {
        Write-Output "`nExecutando todos os passos de hardening."
        Check-SMBStatus
        Disable-SMBv1
        Enable-SMBEncryption
        Block-SMBFirewall
        Check-FirewallSMB
        Write-Output "`nHardening de SMB concluído."
        $restartRequired = $true
    }

    If ($restartRequired) {
        Write-Output "`nReiniciando o sistema para aplicar as alterações..."
        Restart-Computer -Force
    }
}

# Execução principal
Continue-AfterRestart
