import ssl
import socket
from pprint import pprint
from time import sleep
from OpenSSL import SSL
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


# set context so that client and server negotiate TLS protocol
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
#  set root store to verify certif
context.load_verify_locations(ca)
# It never worked with check_hostname = True
context.check_hostname = False
#hname = socket.gethostbyaddr(hname)
s = context.wrap_socket(socket.socket())
# timeout = 10 to not spend 3+ minutes to get a [connection time out]
s.settimeout(10)
try: # try to do the connection
    s.connect((hname,443)) # connect to the host
    pprint(context.session_stats())
    cert=s.getpeercert() # get its cert
    pprint(cert)
    '''while not(cert is None):
        cert=s.getpeercert()
        pprint(cert)
        sleep(2)
        print("done")'''
except Exception as e:
    # log the error
    print(str(e))




"""s.settimeout(10)

s.connect((hname,443))
cert=s.get_peer_cert_chain()
pprint(cert)
"""

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
