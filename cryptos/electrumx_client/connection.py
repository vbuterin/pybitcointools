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
        self.host, = host
        self.port = port
        self.host = str(self.host)
        self.port = int(self.port)
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

    def create_tcp_connection(self, **kwargs):
        try:
            coro = self.loop.create_tcp_connection(self.protocol_class, host=self.host, port=self.port, **kwargs)
            return self.loop.run_until_complete(coro)
        except:
            return None, None

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
                transport, client = self.create_tcp_connection(ssl=context, do_handshake_on_connect=True)
            except ssl.SSLError as e:
                transport = None
                client = None
            except:
                return None, None

            cert = transport.get_extra_info('peercert')
            if transport and self.check_host_name(cert, self.host):
                return (transport, client)

            # get server certificate.
            # Do not use ssl.get_server_certificate because it does not work with proxy
            try:
                context = self.get_ssl_context(cert_reqs=ssl.CERT_NONE, ca_certs=None)
                transport, client = self.create_tcp_connection(ssl=context, do_handshake_on_connect=True)
            except ssl.SSLError as e:
                return None, None
            except:
                return None, None

            dercert = transport.get_extra_info('socket').get_peercert(True)
            transport.close()

            cert = ssl.DER_cert_to_PEM_cert(dercert)
            # workaround android bug
            cert = re.sub("([^\n])-----END CERTIFICATE-----", "\\1\n-----END CERTIFICATE-----", cert)
            temporary_path = cert_path + '.temp'
            with open(temporary_path, "w") as f:
                f.write(cert)
        else:
            temporary_path = None
            is_new = False

        try:
            context = self.get_ssl_context(cert_reqs=ssl.CERT_REQUIRED,
                                           ca_certs=(temporary_path if is_new else cert_path))
            transport, client = self.create_tcp_connection(ssl=context)
        except socket.timeout:
            return None, None
        except ssl.SSLError as e:
            return None, None
        except BaseException as e:
            return None, None

        if is_new:
            os.rename(temporary_path, cert_path)

        return (transport, client)

    def create_connection(self):
        if self.use_ssl:
            return self.create_ssl_connection()
        return self.create_tcp_connection()