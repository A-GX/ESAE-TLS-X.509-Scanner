import ssl
import socket
from pprint import pprint
from OpenSSL import crypto # to check certificates
from datetime import datetime

hname = "212.48.95.53"
ca ='/home/antoine/Documenti/Education/Master2/TLS-X.509-Scanner/Scanner/root_store/week3-roots.pem'


"""sock = socket.socket(socket.AF_INET)
sock.settimeout(10)
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
#context.load_verify_locations(ca)
context.check_hostname = False
context.verify_mode = ssl.CERT_REQUIRED
s = context.wrap_socket(sock, do_handshake_on_connect=True, server_hostname=hname)
s.connect((hname,443))
x509 = s.getpeercert()
pprint(x509)
print(s.version())"""

#cert = ssl.get_server_certificate((hname,443), ssl.PROTOCOL_TLS_CLIENT, ca)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations(ca)
context.check_hostname = False
s = context.wrap_socket(socket.socket())
s.settimeout(10)
s.connect((hname,443))
cert=s.getpeercert()
pprint(cert)
"""x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
result = {
    'subject': dict(x509.get_subject().get_components()),
    'issuer': dict(x509.get_issuer().get_components()),
    'serialNumber': x509.get_serial_number(),
    'version': x509.get_version(),
    'notBefore': datetime.strptime((x509.get_notBefore()).decode("utf-8"), '%Y%m%d%H%M%SZ'),
    'notAfter': datetime.strptime(x509.get_notAfter().decode("utf-8"), '%Y%m%d%H%M%SZ')
}
extensions = (x509.get_extension(i) for i in range(x509.get_extension_count()))
extension_data = {e.get_short_name(): str(e) for e in extensions}
result.update(extension_data)
pprint(result)"""
print(s.version())

"""context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations("/home/antoine/Documenti/Education/Master2/TLS-X.509-Scanner/Scanner/root_store/week3-roots.pem")
sock = socket.socket
ssock = context.wrap_socket(sock, server_hostname="google.com")
ssock.connect(("google.com", 443))
print(ssock.version())"""
