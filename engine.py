import time
from collections import defaultdict, deque
from scapy.all import TCP, UDP, ICMP, DNS, DNSQR

class Engine:
    def __init__(self, config, alert_manager):
        self.cfg = config
        self.alerts = alert_manager
        self.tcp_history = defaultdict(lambda: deque())
        self.icmp_history = defaultdict(lambda: deque())
        self.dns_history = defaultdict(lambda: deque())

    def _cleanup(self, dq, window):
        now = time.time()
        while dq and dq[0][1] < now - window:
            dq.popleft()

    def process_packet(self, pkt):
        now = time.time()
        src = pkt[0][1].src if pkt and pkt.haslayer("IP") else None

        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
            dq = self.tcp_history[src]
            dq.append((dport, now))
            window = self.cfg["thresholds"]["portscan"]["window_seconds"]
            self._cleanup(dq, window)
            unique_ports = {p for p, _ in dq}
            if len(unique_ports) >= self.cfg["thresholds"]["portscan"]["unique_ports"]:
                details = {"count": len(unique_ports), "ports": list(unique_ports)}
                self.alerts.alert("PORT_SCAN", src, details)
                dq.clear()

        if pkt.haslayer(ICMP):
            dq = self.icmp_history[src]
            dq.append((None, now))
            window = self.cfg["thresholds"]["icmp"]["window_seconds"]
            self._cleanup(dq, window)
            pps = len(dq) / max(1, window)
            if pps >= self.cfg["thresholds"]["icmp"]["pps"]:
                details = {"pps": pps}
                self.alerts.alert("ICMP_FLOOD", src, details)
                dq.clear()

        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode() if hasattr(pkt[DNSQR], 'qname') else str(pkt[DNSQR])
            dq = self.dns_history[src]
            dq.append((qname, now))
            window = 60
            while dq and dq[0][1] < now - window:
                dq.popleft()
            labels = qname.split(b".") if isinstance(qname, bytes) else qname.split('.')
            longest = max((len(l) for l in labels), default=0)
            if longest >= self.cfg["thresholds"]["dns_exfil"]["long_label_len"]:
                self.alerts.alert("DNS_EXFIL_SUSPECT", src, {"qname": qname})
