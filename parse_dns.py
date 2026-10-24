import socket
import struct


class parse_dns:

    @staticmethod
    def skip_name(data, offset):
        while data[offset] != 0:
            length = data[offset]

            if length >= 192:
                return offset + 2

            offset += 1 + length

        return offset + 1

    @staticmethod
    def skip_records(data, offset, count):
        for _ in range(count):
            offset = parse_dns.skip_name(data, offset)

            size = struct.unpack("!H", data[offset + 8:offset + 10])[0]

            offset += 10 + size

        return offset

    @staticmethod
    def find_a_record(data, offset, count,qtype):
        for _ in range(count):
            offset = parse_dns.skip_name(data, offset)

            rtype, rclass, ttl, size = struct.unpack(
                "!HHIH", data[offset:offset + 10]
            )

            offset += 10

            if rtype == qtype and rclass == 1:
                if rtype == 1 and size == 4:
                    ip = socket.inet_ntoa(data[offset:offset + 4])
                    return ip, ttl, offset

                if rtype == 28 and size == 16:
                    ip = socket.inet_ntop(socket.AF_INET6, data[offset:offset + 16])
                    return ip, offset, ttl

            offset += size

        return None, offset, None

    @staticmethod
    def parse_dns_response(data,qtype):
        _, flags, qd, an, ns, ar = struct.unpack(
            "!HHHHHH", data[:12]
        )

        if flags & 15:
            return None, None, None

        offset = parse_dns.skip_name(data, 12) + 4 # пропускаю вопрос

        ip, offset, ttl = parse_dns.find_a_record(data, offset, an,qtype) # ищу ip сайта

        if ip is not None:
            return ip, None, ttl

        offset = parse_dns.skip_records(data, offset, ns) # пропускаю ns

        next_server, offset, ttl = parse_dns.find_a_record(data, offset, ar,1) # ищем ip следующего dns

        return None, next_server,ttl