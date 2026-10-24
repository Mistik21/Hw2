import socket
import struct


class request_dns:
    @staticmethod
    def create_dns_query(request):
        header = struct.pack(
            "!HHHHHH",
            request.id,
            0,
            1,
            0,
            0,
            0
        )

        question = request.data[12:request.question_end]

        return header + question

    @staticmethod
    def ask(server_ip, request_data):
        query = request_dns.create_dns_query(request_data)

        dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dns_sock.settimeout(3)

        try:
            dns_sock.sendto(query, (server_ip, 53))
            data, addr = dns_sock.recvfrom(4096)

            return data
        finally:
            dns_sock.close()
