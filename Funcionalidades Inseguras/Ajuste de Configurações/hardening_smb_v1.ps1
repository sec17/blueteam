<#

.DESCRIPTION

    Script de hardening SMB para sistemas operacionais Windows 10 e 11.
    
.CONTACT

    LinkedIn:
      - Larissa Castro Correa: https://linkedin.com/in/larissa-castro-correa
      - Giovanna Frutero: https://www.linkedin.com/in/fruterogiovanna

.VERSION
    Versão 1.0
#>


# Verifica se o script está sendo executado com privilégios de administrador
If (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Este script precisa ser executado como administrador."
    Exit
}

# Função para verificar o status do SMB
Function Check-SMBStatus {
    Write-Output "Verificando status do SMB..."

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

    # Verifica o status do SMB Signing
    Write-Output "Verificando configuração do SMB Signing..."
    $clientSigning = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' | Select-Object -ExpandProperty EnableSecuritySignature
    $serverSigning = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' | Select-Object -ExpandProperty EnableSecuritySignature

    Write-Output "SMB Signing no Cliente: $clientSigning"
    Write-Output "SMB Signing no Servidor: $serverSigning"
}

# Função para desabilitar SMBv1
Function Disable-SMBv1 {
    Write-Output "Desabilitando SMBv1..."

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
    Write-Output "Habilitando criptografia para SMBv2/v3..."

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
    $response = Read-Host "Você deseja bloquear SMB no firewall? (S/N)"
    If ($response -eq "S" -or $response -eq "s") {
        Write-Output "Bloqueando SMB no firewall..."

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
        Write-Output "Bloqueio de SMB no firewall cancelado pelo usuário."
    }
}

# Função para habilitar o SMB Signing
Function Enable-SMBSigning {
    Write-Output "Habilitando SMB Signing..."

    # Habilita o SMB Signing no cliente
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name EnableSecuritySignature -Value 1
    # Habilita o SMB Signing no servidor
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name EnableSecuritySignature -Value 1

    # Verifica se o SMB Signing foi habilitado
    $clientSigning = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' | Select-Object -ExpandProperty EnableSecuritySignature
    $serverSigning = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' | Select-Object -ExpandProperty EnableSecuritySignature

    If ($clientSigning -eq 1 -and $serverSigning -eq 1) {
        Write-Output "SMB Signing habilitado com sucesso."
        # Salva o progresso para retomar depois
        Set-ItemProperty -Path "HKCU:\Software\SMB_Hardening" -Name "StepCompleted" -Value "EnableSMBSigning"
    } Else {
        Write-Output "Falha ao habilitar SMB Signing."
    }
}

# Função para verificar o progresso salvo e retomar a execução
Function Continue-AfterRestart {
    If (-Not (Test-Path "HKCU:\Software\SMB_Hardening")) {
        New-Item -Path "HKCU:\Software\SMB_Hardening" -Force | Out-Null
    }

    $stepCompleted = Get-ItemProperty -Path "HKCU:\Software\SMB_Hardening" -Name "StepCompleted" -ErrorAction SilentlyContinue

    If ($stepCompleted -eq "DisableSMBv1") {
        Write-Output "Retomando após desativação do SMBv1..."
        Enable-SMBEncryption
        Enable-SMBSigning
        Block-SMBFirewall
        Write-Output "Hardening de SMB concluído. Reinicie o sistema para aplicar as alterações."
        Restart-Computer -Force
    } ElseIf ($stepCompleted -eq "EnableSMBEncryption") {
        Write-Output "Retomando após habilitação da criptografia para SMBv2/v3..."
        Enable-SMBSigning
        Block-SMBFirewall
        Write-Output "Hardening de SMB concluído. Reinicie o sistema para aplicar as alterações."
        Restart-Computer -Force
    } ElseIf ($stepCompleted -eq "EnableSMBSigning") {
        Write-Output "Retomando após habilitação do SMB Signing..."
        Block-SMBFirewall
        Write-Output "Hardening de SMB concluído. Reinicie o sistema para aplicar as alterações."
        Restart-Computer -Force
    } ElseIf ($stepCompleted -eq "BlockSMBFirewall") {
        Write-Output "Todas as etapas já foram concluídas anteriormente. Reinicie o sistema para aplicar as alterações."
    } Else {
        Write-Output "Executando todos os passos de hardening."
        Check-SMBStatus
        Disable-SMBv1
        Enable-SMBEncryption
        Enable-SMBSigning
        Block-SMBFirewall
        Write-Output "Hardening de SMB concluído. Reinicie o sistema para aplicar as alterações."
        Restart-Computer -Force
    }
}

# Execução principal
Continue-AfterRestart
