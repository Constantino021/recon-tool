#!/usr/bin/env python3
"""
recon.py — Mini recon tool: WHOIS + DNS enum + Subdomain enum
Autor: Constantino021
Uso: python3 recon.py -d exemplo.com [-w wordlist.txt] [-o resultado.json] [-t 20]

Dependências: requests, dnspython, python-whois
  pip install requests dnspython python-whois --break-system-packages
"""

import argparse
import json
import random
import shutil
import socket
import string
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("[!] Falta o módulo 'requests'. Instale com: pip install requests --break-system-packages")
    sys.exit(1)

# --- Cores no terminal (ANSI), sem dependência externa ---
class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    END = "\033[0m"


def banner():
    print(f"""{C.CYAN}{C.BOLD}
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{C.END}{C.YELLOW}   Recon Script — WHOIS / DNS / Subdomains{C.END}
""")


# ------------------- WILDCARD DNS CHECK -------------------
def detect_wildcard_dns(domain, samples=3):
    """
    Testa subdomínios aleatórios que quase certamente não existem.
    Se eles resolverem, o domínio tem wildcard DNS (*.dominio.com aponta
    tudo pra algum IP), o que invalida um brute-force normal — qualquer
    nome vai "existir", então não dá pra confiar que o subdomínio é real.
    Retorna (is_wildcard: bool, wildcard_ips: set).
    """
    print(f"{C.BOLD}[*] Checando Wildcard DNS{C.END}")
    wildcard_ips = set()

    for _ in range(samples):
        fake_sub = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
        fqdn = f"{fake_sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            wildcard_ips.add(ip)
        except socket.gaierror:
            pass

    if wildcard_ips:
        print(f"    {C.RED}[!] WILDCARD DNS DETECTADO{C.END} — subdomínios aleatórios e inexistentes "
              f"resolveram para: {', '.join(wildcard_ips)}")
        print(f"    {C.YELLOW}Isso significa que *QUALQUER* nome.{domain} vai \"existir\". "
              f"O brute-force abaixo não é confiável para provar existência real —{C.END}")
        print(f"    {C.YELLOW}trate os resultados como candidatos, não como confirmados.{C.END}\n")
        return True, wildcard_ips
    else:
        print(f"    {C.GREEN}nenhum wildcard detectado — resultados do brute-force são confiáveis{C.END}\n")
        return False, wildcard_ips


# ------------------- WHOIS -------------------
def run_whois(domain):
    print(f"{C.BOLD}[*] WHOIS Lookup{C.END}")
    result = {}
    try:
        import whois as pywhois
        w = pywhois.whois(domain)
        result = {
            "registrar": str(w.registrar),
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": list(w.name_servers) if w.name_servers else [],
            "emails": w.emails if isinstance(w.emails, list) else ([w.emails] if w.emails else []),
        }
        for k, v in result.items():
            print(f"    {C.GREEN}{k:16}{C.END}: {v}")
    except ImportError:
        print(f"    {C.YELLOW}[!] python-whois não instalado. pip install python-whois --break-system-packages{C.END}")
    except Exception as e:
        print(f"    {C.RED}[!] Erro no WHOIS: {e}{C.END}")
    print()
    return result


# ------------------- DNS ENUM -------------------
def run_dns_enum(domain):
    print(f"{C.BOLD}[*] DNS Enumeration{C.END}")
    records = {}
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]

    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                values = [str(r) for r in answers]
                records[rtype] = values
                print(f"    {C.GREEN}{rtype:6}{C.END}: {', '.join(values)}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                records[rtype] = []
            except Exception as e:
                records[rtype] = []
                print(f"    {C.YELLOW}{rtype:6}: erro ({e}){C.END}")
    except ImportError:
        # fallback sem dnspython: só resolve A record via socket
        print(f"    {C.YELLOW}[!] dnspython não instalado, usando fallback básico (só A record){C.END}")
        try:
            ip = socket.gethostbyname(domain)
            records["A"] = [ip]
            print(f"    {C.GREEN}A{C.END}     : {ip}")
        except socket.gaierror as e:
            print(f"    {C.RED}[!] Não resolveu: {e}{C.END}")

    print()
    return records


# ------------------- SUBDOMAIN ENUM -------------------
def check_subdomain(sub, domain, wildcard_ips=None):
    """Tenta resolver um subdomínio via DNS. Ignora resultado se bater num IP de wildcard."""
    fqdn = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        if wildcard_ips and ip in wildcard_ips:
            return None  # provavelmente falso positivo do wildcard
        return fqdn, ip
    except socket.gaierror:
        return None


def bruteforce_subdomains(domain, wordlist_path, threads=20, wildcard_ips=None):
    print(f"{C.BOLD}[*] Subdomain Bruteforce (wordlist: {wordlist_path}){C.END}")
    found = {}

    try:
        with open(wordlist_path) as f:
            words = [w.strip() for w in f if w.strip() and not w.startswith("#")]
    except FileNotFoundError:
        print(f"    {C.RED}[!] Wordlist não encontrada: {wordlist_path}{C.END}")
        return found

    print(f"    testando {len(words)} palavras com {threads} threads...")
    if wildcard_ips:
        print(f"    {C.YELLOW}(filtrando automaticamente respostas iguais ao IP de wildcard){C.END}")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_subdomain, w, domain, wildcard_ips): w for w in words}
        for future in as_completed(futures):
            result = future.result()
            if result:
                fqdn, ip = result
                found[fqdn] = ip
                print(f"    {C.GREEN}[+] {fqdn:35}{C.END} -> {ip}")

    print()
    return found


def crtsh_subdomains(domain):
    """Consulta o Certificate Transparency log via crt.sh (não faz brute-force, é passivo)."""
    print(f"{C.BOLD}[*] Subdomain Enum via crt.sh (Certificate Transparency){C.END}")
    found = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    try:
        resp = requests.get(url, timeout=15, headers={"User-Agent": "recon.py/1.0"})
        resp.raise_for_status()
        data = resp.json()
        for entry in data:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name and "*" not in name and name.endswith(domain):
                    found.add(name)
    except requests.exceptions.RequestException as e:
        print(f"    {C.RED}[!] Erro ao consultar crt.sh: {e}{C.END}")
        return found
    except (json.JSONDecodeError, ValueError):
        print(f"    {C.YELLOW}[!] crt.sh não retornou JSON válido (rate limit? tente de novo em instantes){C.END}")
        return found

    for sub in sorted(found):
        print(f"    {C.GREEN}[+]{C.END} {sub}")

    print(f"    total: {len(found)} subdomínios (via CT logs, não confirma se estão ativos)\n")
    return found


# ------------------- PORT SCAN -------------------
COMMON_PORTS = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443"


def scan_target(target, ports, use_python_nmap):
    """Escaneia um único alvo. Retorna (target, dict_de_portas_abertas)."""
    if use_python_nmap:
        import nmap
        scanner = nmap.PortScanner()
        try:
            scanner.scan(target, ports, arguments="-T4 -sV")
            open_ports = {}
            if target in scanner.all_hosts():
                for proto in scanner[target].all_protocols():
                    for port, data in scanner[target][proto].items():
                        if data["state"] == "open":
                            svc = data.get("name", "?")
                            product = data.get("product", "")
                            version = data.get("version", "")
                            label = f"{svc}" + (f" ({product} {version})".strip() if product else "")
                            open_ports[port] = label.strip()
            return target, open_ports
        except Exception as e:
            return target, {"error": str(e)}
    else:
        # fallback: chama o binário nmap via subprocess
        try:
            out = subprocess.run(
                ["nmap", "-T4", "-sV", "-p", ports, target],
                capture_output=True, text=True, timeout=120
            )
            open_ports = {}
            for line in out.stdout.splitlines():
                line = line.strip()
                if "/tcp" in line and "open" in line:
                    parts = line.split()
                    port_num = parts[0].split("/")[0]
                    svc_info = " ".join(parts[2:]) if len(parts) > 2 else parts[1]
                    open_ports[port_num] = svc_info
            return target, open_ports
        except FileNotFoundError:
            return target, {"error": "binário nmap não encontrado no PATH"}
        except subprocess.TimeoutExpired:
            return target, {"error": "timeout"}


def run_port_scan(targets, ports=COMMON_PORTS, threads=5):
    print(f"{C.BOLD}[*] Port Scan nos subdomínios encontrados{C.END}")

    use_python_nmap = False
    try:
        import nmap  # noqa: F401
        use_python_nmap = True
        print(f"    usando python-nmap")
    except ImportError:
        if shutil.which("nmap"):
            print(f"    {C.YELLOW}python-nmap não instalado, usando binário nmap via subprocess{C.END}")
        else:
            print(f"    {C.RED}[!] nmap não encontrado (nem lib nem binário). Instale com: sudo dnf install nmap "
                  f"&& pip install python-nmap --break-system-packages{C.END}")
            return {}

    print(f"    portas: {ports} | alvos: {len(targets)}\n")

    results = {}
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_target, t, ports, use_python_nmap): t for t in targets}
        for future in as_completed(futures):
            target, open_ports = future.result()
            results[target] = open_ports
            if open_ports and "error" not in open_ports:
                print(f"    {C.GREEN}{target}{C.END}")
                for port, info in sorted(open_ports.items(), key=lambda x: int(x[0])):
                    print(f"        {C.CYAN}{port:6}{C.END} {info}")
            elif "error" in open_ports:
                print(f"    {C.RED}{target}: {open_ports['error']}{C.END}")
            else:
                print(f"    {target}: nenhuma porta aberta (das testadas)")

    print()
    return results


# ------------------- RISK SUMMARY -------------------
RISK_PORTS = {
    "21": ("FTP", "credenciais em texto puro, permite anonymous login"),
    "23": ("Telnet", "protocolo sem criptografia, credenciais em texto puro"),
    "135": ("MSRPC", "usado em exploits clássicos do Windows (ex: MS08-067)"),
    "139": ("NetBIOS", "enumeração de shares/usuários, historicamente explorável"),
    "445": ("SMB", "alvo de ransomware (EternalBlue), nunca deveria estar exposto à internet"),
    "1723": ("PPTP VPN", "protocolo de VPN quebrado/obsoleto, evitar"),
    "3306": ("MySQL", "banco de dados exposto publicamente é sempre red flag"),
    "3389": ("RDP", "alvo constante de brute-force e ransomware, exposição direta é crítica"),
    "5432": ("PostgreSQL", "banco de dados exposto publicamente é sempre red flag"),
    "5900": ("VNC", "frequentemente sem senha ou com senha fraca por padrão"),
}


def build_risk_summary(port_scan_results):
    print(f"{C.BOLD}[*] Resumo de Risco{C.END}")
    flags = []

    for target, ports in port_scan_results.items():
        if not ports or "error" in ports:
            continue
        for port in ports:
            if port in RISK_PORTS:
                name, reason = RISK_PORTS[port]
                flags.append({"target": target, "port": port, "service": name, "reason": reason})

    if not flags:
        print(f"    {C.GREEN}nenhuma porta de alto risco encontrada nos alvos escaneados{C.END}\n")
        return flags

    for f in flags:
        print(f"    {C.RED}[!] {f['target']:30}{C.END} porta {f['port']} ({f['service']}) — {f['reason']}")
    print(f"\n    {C.YELLOW}total: {len(flags)} flag(s) de risco{C.END}\n")
    return flags


# ------------------- MAIN -------------------
def main():
    parser = argparse.ArgumentParser(description="Mini recon tool: WHOIS + DNS + Subdomain enum")
    parser.add_argument("-d", "--domain", required=True, help="Domínio alvo (ex: exemplo.com)")
    parser.add_argument("-w", "--wordlist", help="Wordlist para brute-force de subdomínios")
    parser.add_argument("-o", "--output", help="Arquivo JSON de saída")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Threads para brute-force (padrão: 20)")
    parser.add_argument("--no-crtsh", action="store_true", help="Pula a consulta ao crt.sh")
    parser.add_argument("--scan-ports", action="store_true",
                         help="Roda nmap nos subdomínios resolvidos (ativos) que forem encontrados")
    parser.add_argument("--ports", default=COMMON_PORTS,
                         help=f"Portas para o scan (padrão: top comuns — {COMMON_PORTS})")
    parser.add_argument("--scan-threads", type=int, default=5,
                         help="Threads paralelas para o port scan (padrão: 5 — nmap já é pesado por si só)")
    args = parser.parse_args()

    banner()
    start = time.time()

    results = {
        "domain": args.domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "whois": {},
        "dns_records": {},
        "wildcard_dns": {"detected": False, "ips": []},
        "subdomains": {},
    }

    results["whois"] = run_whois(args.domain)
    results["dns_records"] = run_dns_enum(args.domain)

    is_wildcard, wildcard_ips = detect_wildcard_dns(args.domain)
    results["wildcard_dns"] = {"detected": is_wildcard, "ips": sorted(wildcard_ips)}

    all_subs = {}

    if args.wordlist:
        brute_results = bruteforce_subdomains(args.domain, args.wordlist, args.threads, wildcard_ips)
        all_subs.update(brute_results)

    if not args.no_crtsh:
        crt_results = crtsh_subdomains(args.domain)
        for sub in crt_results:
            if sub not in all_subs:
                all_subs[sub] = None  # não resolvido, só encontrado no CT log

    results["subdomains"] = all_subs

    if args.scan_ports:
        # só escaneia os que sabemos que resolvem (têm IP confirmado);
        # os que vieram só do crt.sh sem IP (None) o script domain principal também entra
        scannable = [sub for sub, ip in all_subs.items() if ip is not None]
        scannable.append(args.domain)  # sempre inclui o domínio raiz
        scannable = sorted(set(scannable))

        if scannable:
            port_results = run_port_scan(scannable, ports=args.ports, threads=args.scan_threads)
            results["port_scan"] = port_results
            results["risk_flags"] = build_risk_summary(port_results)
        else:
            print(f"{C.YELLOW}[!] Nenhum alvo resolvido para escanear{C.END}\n")
            results["port_scan"] = {}
            results["risk_flags"] = []

    elapsed = time.time() - start
    print(f"{C.BOLD}{C.CYAN}[*] Finalizado em {elapsed:.2f}s — {len(all_subs)} subdomínios únicos encontrados{C.END}")
    if is_wildcard:
        print(f"{C.YELLOW}[!] Lembrete: este domínio tem wildcard DNS — trate os subdomínios do brute-force "
              f"com cautela (crt.sh continua confiável, pois é baseado em certificados reais emitidos).{C.END}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"{C.GREEN}[+] Resultados salvos em {args.output}{C.END}")


if __name__ == "__main__":
    main()
