# Bug Bounty Recon Local

Web app local para recon de bug bounty en Kali Linux.

Pones el URL del scope y en paralelo corre:
1. **Subdominios vivos** → Subfinder + httpx
2. **Tecnologías** → WhatWeb
3. **Fuzzing de directorios** → ffuf con rate limit bajo (~20k-30k wordlist)

## Requisitos (Kali)

```bash
sudo apt update
sudo apt install -y python3-pip python3-venv subfinder ffuf whatweb seclists httpx-toolkit
# o el httpx de ProjectDiscovery si prefieres:
# go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

## Instalación y uso

```bash
git clone https://github.com/robchvz97/bugbounty-recon-local.git
cd bugbounty-recon-local
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# (opcional) wordlist si no usas seclists
# mkdir -p wordlists && wget -O wordlists/raft-medium.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt

python app.py
```

Abre en el navegador: **http://127.0.0.1:5000**

## Notas

- Rate limit bajo en ffuf (10 req/s) para no quemar tu IP de casa.
- Solo para targets en scope. Usa responsable.
- Los resultados se muestran en vivo en tres paneles.
