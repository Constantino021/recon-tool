# Write-up: recon.py — Reconhecimento automatizado + o caso do Wildcard DNS

**Repositório:** [recon-tool](https://github.com/Constantino021/recon-tool)

## O problema que a ferramenta resolve

A primeira fase de qualquer pentest ou investigação OSINT é reconhecimento (recon): descobrir o que existe sobre um alvo antes de tocar em qualquer coisa mais invasiva. Na prática isso normalmente significa rodar vários comandos separados — `whois`, `dig`, brute-force manual de subdomínio, depois `nmap` em cima do que foi achado. `recon.py` junta essa cadeia inteira numa ferramenta só, com relatório no terminal e em JSON.

## Arquitetura da cadeia

```
WHOIS  →  DNS Enum  →  Wildcard Check  →  Subdomain Enum  →  Port Scan  →  Resumo de Risco
```

Cada etapa alimenta a próxima. WHOIS e DNS enum são sempre passivos — só consultam informação já pública. Subdomain enum combina dois métodos: **crt.sh** (Certificate Transparency, passivo — consulta logs públicos de certificados SSL emitidos) e **brute-force** com wordlist (ativo — testa nomes contra o DNS do alvo). Port scan e o resumo de risco só rodam opcionalmente, via flag, contra os subdomínios que o script confirma que realmente resolveram.

## O teste real: `assistentedebolso.netfly.app`

Rodei a ferramenta completa contra meu próprio projeto (`assistentedebolso.netfly.app`, o mesmo onde documentei o achado de XSS anteriormente), com brute-force + port scan ativados.

**Resultado bruto:** 29 subdomínios "encontrados" no brute-force — `mail.`, `www.`, `smtp.`, `admin.`, `dev.`, `staging.`, `git.`, `gitlab.`, `jenkins.` e por aí vai — cada um resolvendo pra um IP.

À primeira vista, isso pareceria um achado enorme: uma aplicação hospedada supostamente teria dezenas de subdomínios ativos, incluindo painéis administrativos e ambientes de CI/CD (`jenkins`, `gitlab`) que nem deveriam estar expostos. Só que isso não fazia sentido — eu sei que esse projeto não tem 29 subdomínios de verdade.

## Investigando a anomalia: Wildcard DNS

O padrão que chamou atenção: os IPs retornados **não eram sempre o mesmo**. `mail.` e `www.` apontavam para `212.92.104.118`, mas `smtp.` apontava pra `5.79.75.210`, `vpn.` pra `37.48.77.83`, `ns1.` pra `172.241.213.98` — uma mistura de IPs sem relação óbvia entre si.

A explicação: **Wildcard DNS**. Quando um domínio (ou o provedor por trás dele, nesse caso a infraestrutura por trás do `netlify.app`) configura um registro `*.dominio` que responde a **qualquer** subdomínio, mesmo os que nunca foram criados de propósito, o brute-force deixa de significar alguma coisa — o DNS vai "confirmar a existência" de literalmente qualquer nome que eu inventar, porque a resposta não depende do nome, só do wildcard.

Prova simples disso: se eu tivesse testado `xyzqwerty12345.assistentedebolso.netfly.app` — um nome que certamente não foi criado por ninguém — ele também teria resolvido.

## A correção implementada

Adicionei uma etapa nova no início da cadeia, **antes do brute-force real**: gerar 2-3 subdomínios aleatórios de 20 caracteres (praticamente impossível de existir por coincidência) e testar se eles resolvem.

```python
def detect_wildcard_dns(domain, samples=3):
    for _ in range(samples):
        fake_sub = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
        fqdn = f"{fake_sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            wildcard_ips.add(ip)
        except socket.gaierror:
            pass
```

Se algum desses nomes-lixo resolver, o script:
1. Avisa explicitamente no terminal que detectou wildcard DNS
2. Passa a **filtrar automaticamente** qualquer resultado do brute-force que bata exatamente no(s) mesmo(s) IP(s) do wildcard — descartando os falsos positivos
3. Registra o achado no JSON de saída (`wildcard_dns: {detected, ips}`), pra qualquer análise posterior citar com dado concreto
4. Reforça no resumo final que os resultados restantes do brute-force devem ser tratados com cautela — diferente de crt.sh, que continua confiável, pois é baseado em certificados SSL realmente emitidos, não em resposta de DNS

## Por que isso importa

Um scanner que não detecta wildcard DNS gera **falsos positivos em massa** — e um analista júnior que não sabe o que é wildcard pode facilmente reportar "encontrei 29 subdomínios expostos, incluindo painéis administrativos" quando na real encontrou zero, só um comportamento de infraestrutura completamente normal e sem risco algum. Isso é o tipo de erro que mina a credibilidade de um relatório de pentest.

Ferramentas profissionais de verdade (Sublist3r, Amass, etc) já implementam essa checagem por padrão — descobrir isso na prática, através de um resultado que "não batia", e implementar a correção do zero, valeu mais como aprendizado do que se eu tivesse lido sobre wildcard DNS num artigo sem nunca ter esbarrado nele de verdade.

## Limitações conhecidas

- A detecção assume que o wildcard responde de forma consistente (mesmo IP ou conjunto pequeno de IPs); provedores com balanceamento de carga agressivo no wildcard podem exigir mais amostras pra detectar com confiança
- crt.sh, sendo um serviço de terceiros, pode falhar por instabilidade própria (timeout, 502) — o script trata isso sem quebrar a execução, mas não há retry automático ainda
- Port scan só roda contra subdomínios com IP confirmado — subdomínios que aparecem apenas no crt.sh (candidatos, não confirmados via DNS) ficam de fora do scan por segurança

## Próximos passos possíveis

- Retry automático nas consultas ao crt.sh
- Suporte a mais fontes passivas de subdomínio (Shodan, Censys)
- Detecção de tecnologia web (headers, CMS) nos alvos que respondem HTTP
