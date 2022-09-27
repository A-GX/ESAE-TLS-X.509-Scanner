import ssl
import socket
import OpenSSL
from pprint import pprint
from datetime import datetime
import os


def get_certificate(host, port=443, timeout=10):
    #
    #/!\ We want to use ssl.PROTOCOL_TLS_CLIENT in context to be able to /!\
    #/!\ scan TLS1.3 => we need to provide client certificate for that ! /!\
    # (not the case with PROTOCOL_TLSv1...)
    # ==> test with a self signed certificate ?
    #
    context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.load_default_certs()
    # print(context.get_ciphers())  -> ciphers are already managed
    # keys + cert are in ../keysANDcert/[cert.pem OR key.pem]
    conn = socket.create_connection((host, port))
    sock = context.wrap_socket(conn, server_hostname=host)
    sock.settimeout(timeout)
    try:
        der_cert = sock.getpeercert(True)
    finally:
        sock.close()
    return ssl.DER_cert_to_PEM_cert(der_cert)


certificate = get_certificate('google.com')
x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)
print(type(x509))
result = {
    'subject': dict(x509.get_subject().get_components()),
    'issuer': dict(x509.get_issuer().get_components()),
    'serialNumber': x509.get_serial_number(),
    'version': x509.get_version(),
    'notBefore': datetime.strptime((x509.get_notBefore()).decode("utf-8"), '%Y%m%d%H%M%SZ'),
    'notAfter': datetime.strptime(x509.get_notAfter().decode("utf-8"), '%Y%m%d%H%M%SZ'),
}

extensions = (x509.get_extension(i) for i in range(x509.get_extension_count()))
extension_data = {e.get_short_name(): str(e) for e in extensions}
result.update(extension_data)
print(type(result))