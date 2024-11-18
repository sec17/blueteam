## PowerShell
## Desenvolvido por SEC17 - Blue Team 
## https://sec17.com
## Versão Alpha 1.1

## ESTE SCRIPT AINDA ESTÁ EM CONSTRUÇÃO


# Configurações para corrigir problemas de acentuação
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 > $null  # Configura o PowerShell para usar UTF-8

# Função para verificar o estado do SMBv1
function Verificar-SMBv1 {
    $estado = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
    return $estado.State
}

# Função para desativar o SMBv1 (Hardening 1.1)
function Desativar-SMBv1 {
    Write-Host "Verificando o estado do SMBv1..." -ForegroundColor Cyan
    if ((Verificar-SMBv1) -eq "Enabled") {
        Write-Host "SMBv1 está ATIVADO. Desativando..." -ForegroundColor Yellow
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
        Write-Host "SMBv1 foi desativado com sucesso." -ForegroundColor Green
    } else {
        Write-Host "SMBv1 já está desativado." -ForegroundColor Green
    }
}

# Função para ativar o SMBv1 (Rollback 2.1)
function Ativar-SMBv1 {
    Write-Host "Verificando o estado do SMBv1..." -ForegroundColor Cyan
    if ((Verificar-SMBv1) -eq "Disabled") {
        Write-Host "SMBv1 está DESATIVADO. Ativando..." -ForegroundColor Yellow
        Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
        Write-Host "SMBv1 foi ativado com sucesso." -ForegroundColor Green
    } else {
        Write-Host "SMBv1 já está ativado." -ForegroundColor Green
    }
}

# Menu Principal para Hardening e Rollback
function Menu-Principal {
    do {
        Clear-Host
        Write-Host "Menu Principal - Hardening de Windows" -ForegroundColor Cyan
        Write-Host "1. Realizar Hardening"
        Write-Host "2. Realizar Rollback"
        Write-Host "3. Sair"
        $opcao = Read-Host "Escolha uma opção"

        switch ($opcao) {
            "1" { Menu-Hardening }
            "2" { Menu-Rollback }
            "3" { Write-Host "Saindo..." -ForegroundColor Red }
            default { Write-Host "Opção inválida. Tente novamente." -ForegroundColor Yellow; Pause }
        }
    } while ($opcao -ne "3")
}

# Submenu para Hardening
function Menu-Hardening {
    do {
        Clear-Host
        Write-Host "Menu de Hardening" -ForegroundColor Green
        Write-Host "1.1. Verificar e Desativar SMBv1"
        Write-Host "Tudo. Executar todos os itens de Hardening"
        Write-Host "Voltar. Retornar ao menu principal"
        $opcaoHardening = Read-Host "Escolha uma opção"

        switch ($opcaoHardening) {
            "1.1" { Desativar-SMBv1 }
            "Tudo" { Desativar-SMBv1 }
            "Voltar" { break }
            default { Write-Host "Opção inválida. Tente novamente." -ForegroundColor Yellow; Pause }
        }
    } while ($opcaoHardening -notlike "Voltar")
}

# Submenu para Rollback
function Menu-Rollback {
    do {
        Clear-Host
        Write-Host "Menu de Rollback" -ForegroundColor Green
        Write-Host "2.1. Verificar e Ativar SMBv1"
        Write-Host "Tudo. Reverter todos os itens de Hardening"
        Write-Host "Voltar. Retornar ao menu principal"
        $opcaoRollback = Read-Host "Escolha uma opção"

        switch ($opcaoRollback) {
            "2.1" { Ativar-SMBv1 }
            "Tudo" { Ativar-SMBv1 }
            "Voltar" { break }
            default { Write-Host "Opção inválida. Tente novamente." -ForegroundColor Yellow; Pause }
        }
    } while ($opcaoRollback -notlike "Voltar")
}

# Iniciar o Menu Principal
Menu-Principal
