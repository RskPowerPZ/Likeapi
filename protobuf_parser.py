
import struct

class Utils:
    @staticmethod
    def read_varint(buffer, offset):
        result = 0
        shift = 0
        while True:
            b = buffer[offset]
            result |= (b & 0x7F) << shift
            offset += 1
            if not (b & 0x80):
                break
            shift += 7
        return result, offset

    @staticmethod
    def read_field(buffer, offset):
        key, offset = Utils.read_varint(buffer, offset)
        field_number = key >> 3
        wire_type = key & 0x7
        return field_number, wire_type, offset

    @staticmethod
    def read_length_delimited(buffer, offset):
        length, offset = Utils.read_varint(buffer, offset)
        data = buffer[offset:offset + length]
        offset += length
        return data, offset

class Parser:
    def __init__(self):
        self.parsed = {}

    def parse(self, buffer):
        offset = 0
        while offset < len(buffer):
            field_number, wire_type, offset = Utils.read_field(buffer, offset)
            if wire_type == 0:  # Varint
                value, offset = Utils.read_varint(buffer, offset)
            elif wire_type == 1:  # 64-bit
                value = struct.unpack('<Q', buffer[offset:offset+8])[0]
                offset += 8
            elif wire_type == 2:  # Length-delimited
                value, offset = Utils.read_length_delimited(buffer, offset)
            elif wire_type == 5:  # 32-bit
                value = struct.unpack('<I', buffer[offset:offset+4])[0]
                offset += 4
            else:
                raise Exception(f"Unsupported wire type: {wire_type}")

            self.parsed[field_number] = value

        return self.parsed
