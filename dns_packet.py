class DNSRecord:
    def __init__(self, name, type_, class_, ttl, data):
        self.name = name
        self.type = type_  # "A", "NS", и т.д.
        self.class_ = class_  # "IN"
        self.ttl = ttl
        self.data = data  # IP или домен

class DNSPacket:
    def __init__(self, data):
        self.answers = []
        self.authority = []
        self.additional = []
        self.parse_sections(data)

    def parse_sections(self, data):
        # Парсинг answers, authority, additional
        # (реализация зависит от структуры DNS-пакета)
        pass