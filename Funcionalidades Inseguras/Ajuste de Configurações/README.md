# Hardening SMB - Versão 1

Este repositório contém um script PowerShell para hardening de SMB (Server Message Block) em sistemas operacionais Windows. O script realiza uma série de medidas de segurança para proteger o serviço de SMB, que inclui a desativação do SMBv1, habilitação de criptografia para SMBv2/v3 e bloqueio de portas SMB no firewall.

## Funcionalidades

- **Desabilitar SMBv1**: Desativa o SMBv1, um protocolo mais antigo e vulnerável, para evitar possíveis ataques.
- **Habilitar Criptografia SMBv2/v3**: Ativa a criptografia de dados para SMBv2 e SMBv3, aumentando a segurança da comunicação na rede.
- **Gerenciar Regras de Firewall**: Bloqueia ou desbloqueia as portas SMB (137, 138, 139 e 445) no firewall do Windows conforme a necessidade.

## Suporte a Sistemas Operacionais

O script é compatível com os seguintes sistemas operacionais:
- Windows 10
- Windows 11

## Requisitos

- O script deve ser executado com privilégios de administrador.
- O PowerShell deve estar habilitado no sistema operacional.

## Uso

1. Clone o repositório ou baixe o script diretamente.
2. Execute o script no PowerShell com privilégios de administrador.
3. Siga as instruções interativas para aplicar ou reverter as medidas de hardening.

```powershell
# Exemplo de execução
.\hardening-smb.ps1
