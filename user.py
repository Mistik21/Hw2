import struct


class request_user:
    def __init__(self, id, flags, data):
        self.id = id
        self.qr = (flags >> 15) & 1
        self.opcode = (flags >> 11) & 15
        self.rd = (flags >> 8) & 1
        self.data = data

        if self.qr != 0:
            raise ValueError(0)
        if self.opcode != 0:
            raise ValueError(4)

        self.pars_url(data)

        if self.qtype not in (1, 28) or self.qclass != 1:
            raise ValueError(4)

    def pars_url(self, data):
        offset = 12
        parts = []

        while data[offset] != 0:
            length = data[offset]
            offset += 1
            part = data[offset:offset + length].decode("ascii")
            parts.append(part)
            offset += length

        self.url = ".".join(parts)
        self.qtype, self.qclass = struct.unpack(
            "!HH", data[offset + 1:offset + 5]
        )
        self.question_end = offset + 5
