import subprocess
import logging

logger = logging.getLogger("ids.mitiger")

def block_ip_iptables(ip):
    cmd = ["/sbin/iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
    try:
        subprocess.check_call(cmd)
        logger.info("Bloqueado: %s", ip)
        return True
    except Exception:
        logger.exception("Falha ao bloquear IP %s", ip)
        return False
