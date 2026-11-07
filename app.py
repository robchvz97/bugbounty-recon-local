import subprocess
import threading
import uuid
import os
import re
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# Almacenamiento en memoria de scans
scans = {}

def extract_domain(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    domain = domain.split(':')[0]  # quitar puerto
    return domain, url if parsed.scheme else f'https://{domain}'

def run_subdomains(scan_id, domain):
    try:
        scans[scan_id]['subdomains']['status'] = 'running'
        # Subfinder
        cmd_sf = ['subfinder', '-d', domain, '-silent']
        result_sf = subprocess.run(cmd_sf, capture_output=True, text=True, timeout=120)
        subs = [s.strip() for s in result_sf.stdout.splitlines() if s.strip()]
        
        # Filtrar vivos con httpx
        if subs:
            cmd_httpx = ['httpx', '-silent', '-status-code', '-title', '-timeout', '5']
            proc = subprocess.run(cmd_httpx, input='\n'.join(subs), capture_output=True, text=True, timeout=180)
            live = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
            scans[scan_id]['subdomains']['results'] = live if live else subs[:50]  # fallback
        else:
            scans[scan_id]['subdomains']['results'] = []
        scans[scan_id]['subdomains']['status'] = 'done'
    except Exception as e:
        scans[scan_id]['subdomains']['status'] = 'error'
        scans[scan_id]['subdomains']['results'] = [str(e)]

def run_tech(scan_id, target_url):
    try:
        scans[scan_id]['tech']['status'] = 'running'
        cmd = ['whatweb', '-a', '1', '--color=never', target_url]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = result.stdout.strip() or result.stderr.strip()
        scans[scan_id]['tech']['results'] = output.splitlines() if output else ['Sin resultados']
        scans[scan_id]['tech']['status'] = 'done'
    except Exception as e:
        scans[scan_id]['tech']['status'] = 'error'
        scans[scan_id]['tech']['results'] = [str(e)]

def run_fuzz(scan_id, target_url):
    try:
        scans[scan_id]['fuzz']['status'] = 'running'
        # Wordlist: seclists medium (~30k) o local
        wordlist = '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt'
        if not os.path.exists(wordlist):
            wordlist = 'wordlists/raft-medium-directories.txt'
            if not os.path.exists(wordlist):
                scans[scan_id]['fuzz']['results'] = ['Wordlist no encontrada. Instala seclists o descarga raft-medium.']
                scans[scan_id]['fuzz']['status'] = 'error'
                return
        
        # Asegurar https
        if not target_url.startswith('http'):
            target_url = 'https://' + target_url
        base = target_url.rstrip('/')
        
        cmd = [
            'ffuf', '-u', f'{base}/FUZZ',
            '-w', wordlist,
            '-rate', '10',          # rate limit bajo
            '-t', '10',
            '-mc', '200,204,301,302,307,401,403',
            '-fs', '0',
            '-timeout', '5',
            '-s'                    # silent, solo matches
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip() and not l.startswith('#')]
        scans[scan_id]['fuzz']['results'] = lines if lines else ['No se encontraron directorios interesantes (o error)']
        if result.stderr:
            scans[scan_id]['fuzz']['results'].append('STDERR: ' + result.stderr[:200])
        scans[scan_id]['fuzz']['status'] = 'done'
    except Exception as e:
        scans[scan_id]['fuzz']['status'] = 'error'
        scans[scan_id]['fuzz']['results'] = [str(e)]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start', methods=['POST'])
def start_scan():
    data = request.json
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL requerida'}), 400
    
    domain, full_url = extract_domain(url)
    scan_id = str(uuid.uuid4())[:8]
    
    scans[scan_id] = {
        'url': full_url,
        'domain': domain,
        'subdomains': {'status': 'pending', 'results': []},
        'tech': {'status': 'pending', 'results': []},
        'fuzz': {'status': 'pending', 'results': []}
    }
    
    # Correr en paralelo
    threading.Thread(target=run_subdomains, args=(scan_id, domain), daemon=True).start()
    threading.Thread(target=run_tech, args=(scan_id, full_url), daemon=True).start()
    threading.Thread(target=run_fuzz, args=(scan_id, full_url), daemon=True).start()
    
    return jsonify({'scan_id': scan_id, 'domain': domain})

@app.route('/status/<scan_id>')
def status(scan_id):
    if scan_id not in scans:
        return jsonify({'error': 'Scan no encontrado'}), 404
    return jsonify(scans[scan_id])

if __name__ == '__main__':
    os.makedirs('templates', exist_ok=True)
    os.makedirs('wordlists', exist_ok=True)
    app.run(host='127.0.0.1', port=5000, debug=True)
