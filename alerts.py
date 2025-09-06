import logging
import json
import requests
from .utils import ensure_dir

logger = logging.getLogger("ids.alerts")

class AlertManager:
    def __init__(self, config):
        self.log_file = config.get("log_file") or "logs/alerts.log"
        ensure_dir(self.log_file)
        self.webhook = config.get("alert_webhook")

    def _write_log(self, data: dict):
        with open(self.log_file, "a") as f:
            f.write(json.dumps(data) + "\n")

    def alert(self, alert_type, src, details):
        data = {
            "time": __import__("time").ctime(),
            "type": alert_type,
            "src": src,
            "details": details,
        }
        logger.warning("ALERT: %s %s %s", alert_type, src, details)
        try:
            self._write_log(data)
        except Exception:
            logger.exception("Falha ao gravar log")

        if self.webhook:
            try:
                requests.post(self.webhook, json=data, timeout=5)
            except Exception:
                logger.exception("Falha no webhook")
