#!/bin/bash
set -e
echo "Instalando dependencias del sistema..."
sudo apt update
sudo apt install -y python3-pip python3-venv subfinder ffuf whatweb seclists || true
# httpx (elige uno)
sudo apt install -y httpx-toolkit 2>/dev/null || go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

echo "Creando venv..."
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

echo "Listo. Corre: source venv/bin/activate && python app.py"
