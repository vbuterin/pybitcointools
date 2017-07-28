import sys, re
import binascii
import os
import hashlib

is_python2 = bytes == str

if str == bytes:
    
    st = lambda u: str(u)          # equivalent to u.encode("utf-8")
    by = lambda v: bytes(v)        # equivalent to v.decode("utf-8")

    string_types = (str, unicode)
    string_or_bytes_types = (str, unicode)
    int_types = (int, float, long)

    # Base switching
    code_strings = {
        2: '01',
        10: '0123456789',
        16: '0123456789abcdef',
        32: 'abcdefghijklmnopqrstuvwxyz234567',
        58: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
        256: ''.join([chr(x) for x in range(256)])
    }

    
### Hex to bin converter and vice versa for objects
    
    def json_is_base(obj, base):
        if not is_python2 and isinstance(obj, bytes):
            return False
        alpha = get_code_string(base)
        if isinstance(obj, string_types):
            for i in range(len(obj)):
                if alpha.find(obj[i]) == -1:
                    return False
            return True
        elif isinstance(obj, int_types) or obj is None:
            return True
        elif isinstance(obj, list):
            for i in range(len(obj)):
                if not json_is_base(obj[i], base):
                    return False
            return True
        else:
            for x in obj:
                if not json_is_base(obj[x], base):
                    return False
            return True


    def json_changebase(obj, changer):
        if isinstance(obj, string_types):
            return changer(obj)
        elif isinstance(obj, int_types) or obj is None:
            return obj
        elif isinstance(obj, list):
            return [json_changebase(x, changer) for x in obj]
        return dict((x, json_changebase(obj[x], changer)) for x in obj)


    def json_hexlify(obj):
        return json_changebase(obj, lambda x: binascii.hexlify(x))
        

    def json_unhexlify(obj):
        return json_changebase(obj, lambda x: binascii.unhexlify(x))


    def bin_dbl_sha256(s):
        bytes_to_hash = from_str_to_bytes(s)
        return hashlib.sha256(hashlib.sha256(bytes_to_hash).digest()).digest()


    def lpad(msg, symbol, length):
        if len(msg) >= length:
            return msg
        return symbol * (length - len(msg)) + msg


    def get_code_string(base):
        if int(base) in code_strings:
            return code_strings[int(base)]
        else: raise ValueError("Invalid base!")


    def changebase(string, frm, to, minlen=0):
        if frm == to:
            return lpad(string, get_code_string(frm)[0], minlen)
        return encode(decode(string, frm), to, minlen)


    def bin_to_b58check(inp, magicbyte=0):
        if magicbyte == 0:
            inp = '\x00' + inp
        while magicbyte > 0:
            inp = chr(int(magicbyte % 256)) + inp
            magicbyte //= 256
        leadingzbytes = len(re.match('^\x00*', inp).group(0))
        checksum = bin_dbl_sha256(inp)[:4]
        return '1' * leadingzbytes + changebase(inp+checksum, 256, 58)


    def safe_hexlify(b):
        """Hexlify bytestring or a json dict/list of bytestrings"""
        if isinstance(b, string_or_bytes_types):
            return binascii.hexlify(b)
        elif isinstance(b, dict):    # FINDOUT: ok to accept (int_types, None) also??
            return json_hexlify(b)
        else:
            raise TypeError("%s must be str/bytes or a dict of bytes" % type(b))


    def safe_unhexlify(s):
        """Unhexlify bytestring or a json dict/list of bytestrings"""
        if isinstance(s, string_or_bytes_types):
            return binascii.unhexlify(s)
        elif isinstance(s, dict):    # FINDOUT: ok to accept (int_types, None) also??
            return json_unhexlify(s)
        else:
            raise TypeError("%s must be str/bytes or a dict of bytes" % type(s))

    safe_from_hex = safe_unhexlify

#    def bytes_to_hex_string(b):
#        return b.encode('hex')
#
#    def safe_from_hex(s):
#        return s.decode('hex')

    def from_int_representation_to_bytes(a):
        return str(a)

    def from_int_to_byte(a):
        return chr(a)

    def from_byte_to_int(a):
        return ord(a)

    def from_bytes_to_string(s):
        return s

    def from_string_to_bytes(a):
        return a
    
    from_str_to_bytes = from_string_to_bytes
    from_bytes_to_str = from_bytes_to_string
    
    def encode(val, base, minlen=0):
        base, minlen = int(base), int(minlen)
        code_string = get_code_string(base)
        result = ""
        while val > 0:
            result = code_string[val % base] + result
            val //= base
        return code_string[0] * max(minlen - len(result), 0) + result

    def decode(string, base):
        base = int(base)
        code_string = get_code_string(base)
        result = 0
        if base == 16:
            string = string.lower()
        while len(string) > 0:
            result *= base
            result += code_string.find(string[0])
            string = string[1:]
        return result

    def random_string(x):
        return os.urandom(x)
        
if __name__ == '__main__':
    assert safe_unhexlify({"test_str": "deadbeef"}) == {'test_str': '\xde\xad\xbe\xef'}
    assert safe_hexlify({'test_str': '\xde\xad\xbe\xef\x12\x34\x56\x78\x90'}) == {"test_str": "deadbeef1234567890"}
    assert json_hexlify({"str": '\1\2', 'int': 4, 'list': ["\ab\cd\ef", None], 'dict': {'s': '\x12\x34\x56\x78\x90\x90\x78\x56\x34\x12'}}) == {'int': 4, 'list': ['07625c63645c6566', None], 'dict': {'s': '12345678909078563412'}, 'str': '0102'}
    assert json_unhexlify(None) == None
    assert json_hexlify(42.42) == 42.42
