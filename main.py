import os
import socket
import struct
from respons import respons
from dns import request_dns
from user import request_user
from parse_dns import parse_dns
from multiply import multiply_ip


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 53))

while True:
    data, addr = sock.recvfrom(1024)

    if len(data) < 12:
        continue

    try:
        header = struct.unpack("!HHHHHH", data[:12])
        request = request_user(header[0], header[1], data)

    except ValueError as e:
        rd = (header[1] >> 8) & 1
        rcode = e.args[0]

        if rcode != 0:
            respons.error(header[0], rd, rcode, addr, sock)
        continue

    except (IndexError, struct.error, UnicodeError):
        rd = (header[1] >> 8) & 1
        respons.error(header[0], rd, 1, addr, sock)
        continue

    if request.qtype == 1 and "multiply" in request.url.split("."):
        try:
            ip = multiply_ip(request.url)
            respons.ok(request, addr, ip, sock, 300)
        except ValueError:
            respons.error(request.id, request.rd, 1, addr, sock)

        continue

    try:
        server_ip = "198.41.0.4"
        for _ in range(20):
            dns_response = request_dns.ask(server_ip, request)

            ip, next_server, ttl = parse_dns.parse_dns_response(dns_response, request.qtype)

            if ip is not None:
                respons.ok(request, addr, ip, sock, ttl)
                break

            if next_server is None:
                respons.error(request.id, request.rd, 2, addr, sock)
                break

            server_ip = next_server

        else:
            respons.error(request.id, request.rd, 2, addr, sock)

    except (socket.timeout, OSError, ValueError, IndexError, struct.error):
        respons.error(request.id, request.rd, 2, addr, sock)


