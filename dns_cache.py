import logging
import pickle
import time
import threading
from collections import defaultdict

from dns_packet import DNSPacket


class DNSCacheServer:
    def __init__(self, ip="127.0.0.1", port=53, forwarder="8.8.8.8"):
        self.ip = ip
        self.port = port
        self.forwarder = (forwarder, 53)
        self.cache = {
            "domain_to_ip": defaultdict(list),
            "ip_to_domain": defaultdict(list)
        }
        self.load_cache()  # Загрузка кэша при старте
        self.cleanup_thread = threading.Thread(target=self.cleanup_expired, daemon=True)
        self.cleanup_thread.start()

    def cleanup_expired(self):
        while True:
            time.sleep(60)
            now = time.time()
            for cache_type in ["domain_to_ip", "ip_to_domain"]:
                for key in list(self.cache[cache_type].keys()):
                    self.cache[cache_type][key] = [
                        (ip, ttl) for (ip, ttl) in self.cache[cache_type][key]
                        if now <= ttl
                    ]

    def save_cache(self):
        """Сохранение кэша на диск."""
        with open("dns_cache.pkl", "wb") as f:
            pickle.dump(self.cache, f)

    def load_cache(self):
        try:
            with open("dns_cache.pkl", "rb") as f:
                self.cache = pickle.load(f)
        except FileNotFoundError:
            pass

    def handle_query(self, data, client_addr):
        try:
            request = DNSPacket(data)
            if self.check_cache(request):
                return

            response = self.forward_query(data)
            if response:
                self.parse_and_cache(response)

        except Exception as e:
            logging.error(f"Ошибка: {e}")

    def parse_and_cache(self, response):
        packet = DNSPacket(response)
        for section in ["answers", "authority", "additional"]:
            for record in getattr(packet, section, []):
                if record.type in ["A", "AAAA", "NS", "PTR"]:
                    self.cache["domain_to_ip"][record.name].append(
                        (record.data, time.time() + record.ttl)
                    )
                    if record.type == "A":
                        self.cache["ip_to_domain"][record.data].append(
                            (record.name, time.time() + record.ttl)
                        )
        self.save_cache()