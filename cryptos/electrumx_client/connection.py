import os
import ssl
import requests
import socket
import re

ca_path = requests.certs.where()

class TCPConnection:

    def __init__(self, protocol_class, host, port, use_ssl, loop, config_path):
        self.config_path = config_path
        self.loop = loop
        self.protocol_class = protocol_class
        self.host = str(host)
        self.port = int(port)
        self.use_ssl = use_ssl
        self.daemon = True

    def check_host_name(self, peercert, name):
        """Simple certificate/host name checker.  Returns True if the
        certificate matches, False otherwise.  Does not support
        wildcards."""
        # Check that the peer has supplied a certificate.
        # None/{} is not acceptable.
        if not peercert:
            return False
        if 'subjectAltName' in peercert:
            for typ, val in peercert["subjectAltName"]:
                if typ == "DNS" and val == name:
                    return True
        else:
            # Only check the subject DN if there is no subject alternative
            # name.
            cn = None
            for attr, val in peercert["subject"]:
                # Use most-specific (last) commonName attribute.
                if attr == "commonName":
                    cn = val
            if cn is not None:
                return cn == name
        return False

    @staticmethod
    def get_ssl_context(cert_reqs, ca_certs):
        context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_certs)
        context.check_hostname = False
        context.verify_mode = cert_reqs

        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1

        return context

    def get_simple_socket(self):
        try:
            l = socket.getaddrinfo(self.host, self.port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror:
            return
        for res in l:
            try:
                s = socket.socket(res[0], socket.SOCK_STREAM)
                s.settimeout(10)
                s.connect(res[4])
                s.settimeout(2)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                return s
            except BaseException as _e:
                continue

    def create_tcp_connection(self, **kwargs):
        coro = self.loop.create_connection(self.protocol_class, host=self.host, port=self.port, **kwargs)
        return self.loop.run_until_complete(coro)

    def create_ssl_connection(self):
        base_cert_path = os.path.join(self.config_path, 'certs')
        if not os.path.exists(base_cert_path):
            os.makedirs(base_cert_path)
        cert_path = os.path.join(base_cert_path, self.host)
        if not os.path.exists(cert_path):
            is_new = True
            # try with CA first
            try:
                context = self.get_ssl_context(cert_reqs=ssl.CERT_REQUIRED, ca_certs=ca_path)
                transport, client = self.create_tcp_connection(ssl=context)
            except ssl.SSLError as e:
                transport = None
                client = None

            if transport:
                cert = transport.get_extra_info('peercert')
                self.check_host_name(cert, self.host)
                return (transport, client)

            # get server certificate.
            # Do not use ssl.get_server_certificate because it does not work with proxy
            try:
                context = self.get_ssl_context(cert_reqs=ssl.CERT_NONE, ca_certs=None)
                socket = self.get_simple_socket()
                if not socket:
                    return None, None
                socket = context.wrap_socket(socket)
            except ssl.SSLError as e:
                return None, None

            dercert = socket.getpeercert(True)

            socket.close()

            if not dercert:
                return None, None

            cert = ssl.DER_cert_to_PEM_cert(dercert)
            # workaround android bug
            cert = re.sub("([^\n])-----END CERTIFICATE-----", "\\1\n-----END CERTIFICATE-----", cert)
            temporary_path = cert_path + '.temp'
            with open(temporary_path, "w") as f:
                f.write(cert)
        else:
            temporary_path = None
            is_new = False

        context = self.get_ssl_context(cert_reqs=ssl.CERT_REQUIRED,
                                       ca_certs=(temporary_path if is_new else cert_path))
        try:
            transport, client = self.create_tcp_connection(ssl=context)
        except ssl.SSLError:
            return None, None

        if is_new:
            os.rename(temporary_path, cert_path)

        return (transport, client)

    def create_connection(self):
        if self.use_ssl:
            return self.create_ssl_connection()
        return self.create_tcp_connection()