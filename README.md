# IDS-IPS (Python + Scapy)

Detecção e resposta a tráfego suspeito em redes locais — implementação educacional/defensiva usando Python e Scapy.

## Instalação

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Execução

```bash
python src/main.py -c src/config.yaml
```

## Testes

```bash
python examples/tests_simulate_scan.py
```

# Arquitetura do IDS/IPS

## Componentes e responsabilidades
- **sniffer**: captura e encaminha pacotes para o engine
- **engine**: aplica detecções com uso de janelas temporais
- **alert manager**: grava e envia notificações
- **mitiger**: função manual/administrativa para bloquear

# Estrutura do projeto
```
ids-ips-scapy/
├── .gitignore
├── requirements.txt
├── README.md
├── src/
│ ├── main.py
│ ├── engine.py
│ ├── rules.py
│ ├── alerts.py
│ ├── utils.py
│ ├── mitiger.py # opcional (requere sudo) - comentado por padrão
│ └── config.yaml
├── examples/
│ └── tests_simulate_scan.py
├── docs/
│ ├── architecture.md
│ └── screenshots/ # coloque aqui os prints para o README
└── .vscode/
├── launch.json
└── tasks.json
```
