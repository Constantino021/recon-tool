# recon.py — Mini Recon Tool

Script de reconhecimento em Python que automatiza a primeira fase de um pentest/OSINT: descobrir o que existe sobre um domínio antes de tocar em qualquer coisa mais invasiva.

Ele junta em uma única ferramenta o que normalmente seria feito com 4 ou 5 comandos separados (`whois`, `dig`, brute-force manual de subdomínio, `nmap`) — automatizando e organizando tudo num único relatório, no terminal e em JSON.

---

## O que ele faz

O script roda em cadeia, e cada etapa alimenta a próxima:

```
WHOIS  →  DNS Enum  →  Subdomain Enum  →  Port Scan  →  Resumo de Risco
```

### 1. WHOIS Lookup
Consulta informações públicas de registro do domínio: registrar, data de criação, data de expiração, nameservers e e-mails de contato. É o ponto de partida clássico de qualquer recon — dados totalmente passivos e públicos.

### 2. DNS Enumeration
Resolve os principais tipos de registro DNS do domínio:
- **A / AAAA** — IPs (IPv4/IPv6)
- **MX** — servidores de e-mail
- **TXT** — registros de texto (verificações, SPF, etc)
- **NS** — servidores de nome
- **CNAME / SOA** — aliases e autoridade da zona

### 3. Subdomain Enumeration (dois métodos combinados)
- **Brute-force com wordlist** — testa uma lista de palavras (`www`, `admin`, `dev`...) na frente do domínio e vê quais resolvem via DNS. Ativo, mas simples.
- **crt.sh (Certificate Transparency)** — consulta os logs públicos de certificados SSL emitidos para o domínio. Totalmente passivo: não faz nenhuma tentativa contra o alvo, só olha um banco de dados público. Costuma achar subdomínios que o brute-force nunca acharia (porque não estavam na wordlist).

### 4. Port Scan (opcional, via `--scan-ports`)
Pega os subdomínios que **realmente resolveram** e roda `nmap` neles (`-sV`, detecção de versão de serviço), usando `python-nmap` se disponível ou o binário `nmap` direto como fallback. Só escaneia o que foi confirmado ativo — não perde tempo com subdomínios "fantasmas" que só apareceram no crt.sh sem resolver.

### 5. Resumo de Risco (automático quando o port scan roda)
Cruza as portas abertas encontradas com uma lista de portas classicamente perigosas de estarem expostas na internet (RDP, SMB, FTP, Telnet, bancos de dados, VNC) e already explica o motivo de cada uma ser risco. É o tipo de coisa que, num pentest real, já vira um achado pro relatório.

---

## Instalação

### 1. Clonar o repositório
```bash
git clone https://github.com/Constantino021/recon-tool.git
cd recon-tool
```

### 2. Instalar as dependências
```bash
sudo dnf install nmap          # Fedora — já traz o binário nmap
pip install requests dnspython python-whois python-nmap --break-system-packages
```

> Se preferir isolar as dependências Python numa venv em vez de instalar globalmente:
> ```bash
> python3 -m venv venv
> source venv/bin/activate
> pip install requests dnspython python-whois python-nmap
> ```

> `dnspython` e `python-whois` são opcionais — o script tem fallback (DNS cai pra resolução básica via `socket`, WHOIS avisa e pula). Mas pra usar 100% das features, instala tudo.

---

## Como usar

### Recon básico (WHOIS + DNS + crt.sh, sem brute-force nem port scan)
```bash
python3 recon.py -d exemplo.com
```

### Com brute-force de subdomínio
```bash
python3 recon.py -d exemplo.com -w subdomains-small.txt
```

### Fluxo completo: subdomínios + port scan + resumo de risco + salvar em JSON
```bash
python3 recon.py -d exemplo.com -w subdomains-small.txt --scan-ports -o resultado.json
```

### Opções disponíveis

| Flag | Descrição |
|---|---|
| `-d`, `--domain` | Domínio alvo (obrigatório) |
| `-w`, `--wordlist` | Caminho da wordlist para brute-force de subdomínio |
| `-o`, `--output` | Salva o resultado completo em JSON |
| `-t`, `--threads` | Threads para o brute-force de subdomínio (padrão: 20) |
| `--no-crtsh` | Pula a consulta ao crt.sh (só brute-force, se houver wordlist) |
| `--scan-ports` | Ativa o port scan (nmap) nos subdomínios resolvidos |
| `--ports` | Lista de portas a escanear (padrão: as mais comuns) |
| `--scan-threads` | Threads para o port scan (padrão: 5 — nmap é pesado, não vale forçar muito) |

---

## Sobre a wordlist incluída

`subdomains-small.txt` é uma lista **pequena, de exemplo/teste** — 30 palavras comuns (`www`, `mail`, `admin`, `dev`...). Serve pra validar que o script funciona.

Pra recon sério, o ideal é usar wordlists maiores, tipo as da [SecLists](https://github.com/danielmiessler/SecLists) (`Discovery/DNS/subdomains-top1million-5000.txt` ou maiores).

---

## ⚠️ Uso responsável

- **WHOIS e crt.sh são passivos** — consultam bancos de dados públicos, não tocam na infraestrutura do alvo.
- **Brute-force de subdomínio e port scan são ativos** — geram tráfego direto contra a infraestrutura de terceiros.

Só rode as etapas ativas (`-w` e `--scan-ports`) contra:
- Domínios/infraestrutura que você possui
- Labs de prática (TryHackMe, HackTheBox, etc)
- Alvos com escopo de autorização assinado (bug bounty, pentest contratado)

Rodar port scan ou brute-force contra domínio de terceiros sem autorização é ilegal na maioria das jurisdições — inclusive em Angola.

---

## Roadmap (ideias futuras)

- [ ] Exportar relatório também em Markdown/HTML pronto pra colar no portfólio
- [ ] Integração com Shodan/Censys como fonte extra de subdomínio
- [ ] Detecção de tecnologia web (headers, CMS) nos alvos ativos
- [ ] Modo "quiet" pra rodar em pipeline/CI
