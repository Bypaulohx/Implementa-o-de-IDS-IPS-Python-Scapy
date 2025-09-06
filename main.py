import argparse
import logging
from scapy.all import sniff
from .rules import load_config
from .alerts import AlertManager
from .engine import Engine

def setup_logging():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

def main():
    parser = argparse.ArgumentParser(description='IDS/IPS - Python + Scapy')
    parser.add_argument("-c", "--config", default="src/config.yaml")
    parser.add_argument("-i", "--iface", default=None)
    args = parser.parse_args()

    setup_logging()
    cfg = load_config(args.config)
    if args.iface:
        cfg['interface'] = args.iface

    alert_mgr = AlertManager(cfg)
    engine = Engine(cfg, alert_mgr)

    iface = cfg.get('interface') or None
    bpf = cfg.get('bpf') or "ip"

    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    logging.info("Starting capture on iface=%s bpf=%s", iface, bpf)

    sniff(filter=bpf, iface=iface, prn=engine.process_packet, store=0)

if __name__ == '__main__':
    main()
