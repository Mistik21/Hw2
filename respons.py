import struct
import socket


class respons:

    @staticmethod
    def ok(request, addr, ip, sock,ttl=300):
        flags = (1 << 15) | (request.rd << 8)
        header = struct.pack("!HHHHHH", request.id, flags, 1, 1, 0, 0)
        question = request.data[12:request.question_end]
        response = header + question + respons.create_answer(ip, request,ttl)
        sock.sendto(response, addr)

    @staticmethod
    def error(request_id, rd, rcode, addr, sock):
        flags = (1 << 15) | (rd << 8) | rcode

        header = struct.pack(
            "!HHHHHH",
            request_id,
            flags,
            1,
            0,
            0,
            0
        )
        sock.sendto(header, addr)

    @staticmethod
    def create_answer(ip, request,ttl):
        name = request.data[12:request.question_end - 4]
        if request.qtype == 1:
            ip_bytes = socket.inet_aton(ip)
        else:
            ip_bytes = socket.inet_pton(socket.AF_INET6, ip)

        return (
                name +
                struct.pack("!HHIH", request.qtype, 1, ttl, len(ip_bytes)) +
                ip_bytes
        )
