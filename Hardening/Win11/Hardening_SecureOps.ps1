# Caminho para o Notepad
$notepadPath = "C:\Windows\System32\notepad.exe"

# Lista de extensões
$extensoes = @(
    ".vbs", ".ps1", ".scr", ".bat", ".js", ".hta", 
    ".scf", ".reg", ".wsh", ".pl", ".py", ".cmd"
)


# Função para associar extensões ao Notepad
function AssociarExtensao {
    param (
        [string]$escopo,  # 'HKLM'
        [string]$extensao,
        [string]$programa
    )

    $key = "${escopo}:\Software\Classes\$extensao"
    $keyNotepad = "${escopo}:\Software\Classes\notepadfile\shell\open\command"

    Write-Host "Associando $extensao ao Notepad ($escopo)..." -ForegroundColor Cyan

    # Criar as chaves necessárias no Registro
    New-Item -Path $key -Force | Out-Null
    Set-ItemProperty -Path $key -Name "(Default)" -Value "notepadfile" -Force

    New-Item -Path $keyNotepad -Force | Out-Null
    Set-ItemProperty -Path $keyNotepad -Name "(Default)" -Value "`"$programa`" `%1" -Force
}

# Função para reverter associações de extensões
function ReverterExtensao {
    param (
        [string]$escopo,  # 'HKLM'
        [string]$extensao
    )

    $key = "${escopo}:\Software\Classes\$extensao"
    $keyNotepad = "${escopo}:\Software\Classes\notepadfile"

    Write-Host "Revertendo associação de $extensao ($escopo)..." -ForegroundColor Yellow

    # Remover as chaves do registro
    Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $keyNotepad -Recurse -Force -ErrorAction SilentlyContinue
}

# Função para verificar se o sistema suporta AppLocker
function Check-AppLockerSupport {
    $applockerService = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
    if ($applockerService) {
        Write-Host "`nEste sistema suporta o AppLocker.`n" -ForegroundColor Yellow
        return $true
    } else {
        Write-Host "Este sistema NÃO suporta o AppLocker. Operação não será realizada." -ForegroundColor Red
        return $false
    }
}

# Função para habilitar o AppLocker
function Enable-AppLocker {
    if (-not (Check-AppLockerSupport)) {
        return
    }

    Write-Host "`n=== Habilitando o AppLocker ===`n" -ForegroundColor Green

    $GpoPath = "HKLM:\Software\Policies\Microsoft\Windows\AppLocker"

    # Criar a chave de registro se não existir
    if (-not (Test-Path $GpoPath)) {
        Write-Host "Criando chave de registro para AppLocker..."
        New-Item -Path $GpoPath -Force | Out-Null
        Write-Host "Chave criada com sucesso."
    }

    # Habilitar o AppLocker nas políticas de grupo
    Set-ItemProperty -Path $GpoPath -Name "Enabled" -Value 1 -Force
    Write-Host "AppLocker habilitado nas políticas de grupo."

    # Iniciar o serviço AppLocker se não estiver em execução
    $applockerService = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
    if ($applockerService.Status -ne "Running") {
        Write-Host "Iniciando o serviço AppLocker..."
        Start-Service -Name "AppIDSvc"
        Write-Host "Serviço AppLocker iniciado."
    } else {
        Write-Host "O serviço AppLocker já está em execução."
    }

    Write-Host "=== Habilitação do AppLocker concluída ===`n"
    Read-Host "Pressione Enter para continuar..."
}

# Função para desabilitar o AppLocker
function Disable-AppLocker {
    if (-not (Check-AppLockerSupport)) {
        return
    }

    Write-Host "`n=== Desabilitando o AppLocker ===`n" -ForegroundColor Yellow

    # Parar o serviço AppLocker
    $applockerService = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
    if ($applockerService -and $applockerService.Status -ne "Stopped") {
        Write-Host "Parando o serviço AppLocker..."
        Stop-Service -Name "AppIDSvc" -Force
        Write-Host "Serviço AppLocker parado."
    } else {
        Write-Host "O serviço AppLocker já está parado ou não foi encontrado."
    }

    Write-Host "=== AppLocker desabilitado com sucesso ===`n"
    Read-Host "Pressione Enter para continuar..."
}

function VerificarWindowsDefender {
    Write-Host "`nVerificando as proteções do Windows Defender..." -ForegroundColor Cyan

    $protecoes = @(
        @{ Nome = "Proteção em tempo real"; Status = (Get-MpPreference).DisableRealtimeMonitoring -eq $false },
        @{ Nome = "Proteção de comportamento"; Status = (Get-MpPreference).DisableBehaviorMonitoring -eq $false },
        @{ Nome = "Cloud-delivered Protection"; Status = (Get-MpPreference).MAPSReporting -ne "Disabled" }
    )

    $todasAtivadas = $true
    foreach ($protecao in $protecoes) {
        if ($protecao.Status) {
            Write-Host ($protecao.Nome + ": Ativada") -ForegroundColor Green
        } else {
            Write-Host ($protecao.Nome + ": Desativada ") -ForegroundColor Red
            $todasAtivadas = $false
            # Instruções para o analista
            if ($protecao.Nome -eq "Proteção em tempo real") {
                Write-Host "Vá para 'Proteção contra vírus e ameaças' e ative a 'Proteção em tempo real'." -ForegroundColor Yellow
            } elseif ($protecao.Nome -eq "Proteção de comportamento") {
                Write-Host "Vá para 'Proteção contra vírus e ameaças' e ative a 'Proteção de comportamento'." -ForegroundColor Yellow
            } elseif ($protecao.Nome -eq "Cloud-delivered Protection") {
                Write-Host "Vá para 'Proteção contra vírus e ameaças' e ative a 'Proteção entregue pela nuvem'." -ForegroundColor Yellow
            }
        }
    }

    # Se alguma proteção estiver desativada, abrir a janela do Windows Defender
    if (-not $todasAtivadas) {
        Write-Host "`nAlgumas proteções estão desativadas. Abrindo a janela do Windows Defender..." -ForegroundColor Yellow
        Start-Process "windowsdefender:"
    }
}



# Submenu de Hardening
function Menu-Hardening {
    do {
        Clear-Host
        Write-Host "Menu de Hardening"
        Write-Host "1. Habilitar o AppLocker"
        Write-Host "2. Associar extensões ao Notepad"
        Write-Host "3. Verificar status do Windows Defender"
        Write-Host "4. Executar todas as opções de Hardening"
        Write-Host "5. Voltar ao Menu Principal"
        $opcaoHardening = Read-Host "Escolha uma opção"

        switch ($opcaoHardening) {
            "1" { Enable-AppLocker }
            "2" {
                foreach ($extensao in $extensoes) {
                    AssociarExtensao -escopo "HKLM" -extensao $extensao -programa $notepadPath
                }
                Write-Host "Associação de extensões concluída!"
                Read-Host "Pressione Enter para continuar..."
            }
            "3" { VerificarWindowsDefender; Read-Host "Pressione Enter para continuar..." }
            "4" {
                Enable-AppLocker
                foreach ($extensao in $extensoes) {
                    AssociarExtensao -escopo "HKLM" -extensao $extensao -programa $notepadPath
                }
                VerificarWindowsDefender
                Write-Host "Hardening completo!" -ForegroundColor Green
                Read-Host "Pressione Enter para continuar..."
            }
            "5" { break }
            default {
                Write-Host "Opção inválida. Tente novamente." -ForegroundColor Red
                Read-Host "Pressione Enter para continuar..."
            }
        }
    } while ($opcaoHardening -ne "5")
}


# Submenu de Rollback
function Menu-Rollback { 
    do {
        Clear-Host
        Write-Host "Menu de Rollback"
        Write-Host "1. Desabilitar o AppLocker"
        Write-Host "2. Reverter associações de extensões"
        Write-Host "3. Reverter todas as opções de Hardening"
        Write-Host "4. Voltar ao Menu Principal"
        $opcaoRollback = Read-Host "Escolha uma opção"

        switch ($opcaoRollback) {
            "1" { Disable-AppLocker }
            "2" {
                foreach ($extensao in $extensoes) {
                    ReverterExtensao -escopo "HKLM" -extensao $extensao
                }
                Write-Host "Reversão de associações concluída!"
                Read-Host "Pressione Enter para continuar..."
            }
            "3" {
                Disable-AppLocker
                foreach ($extensao in $extensoes) {
                    ReverterExtensao -escopo "HKLM" -extensao $extensao
                }
                Write-Host "Rollback completo!" -ForegroundColor Yellow
                Read-Host "Pressione Enter para continuar..."
            }
            "4" { break }
            default {
                Write-Host "Opção inválida. Tente novamente." -ForegroundColor Red
                Read-Host "Pressione Enter para continuar..."
            }
        }
    } while ($opcaoRollback -ne "4")
}

# Menu Principal
function Menu-Principal { 
    do {
        Clear-Host
        Write-Host "=== Menu Principal ==="
        Write-Host "1. Acessar Menu de Hardening"
        Write-Host "2. Acessar Menu de Rollback"
        Write-Host "3. Sair do Script"
        $opcaoPrincipal = Read-Host "Escolha uma opção"

        switch ($opcaoPrincipal) {
            "1" { Menu-Hardening }
            "2" { Menu-Rollback }
            "3" { break }
            default {
                Write-Host "Opção inválida. Tente novamente." -ForegroundColor Red
                Read-Host "Pressione Enter para continuar..."
            }
        }
    } while ($opcaoPrincipal -ne "3")
}

# Inicia o Menu Principal
Menu-Principal
