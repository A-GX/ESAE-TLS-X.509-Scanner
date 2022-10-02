from pprint import pprint
from ssl import PROTOCOL_TLS_CLIENT
from OpenSSL import SSL # to create connection
from OpenSSL import crypto # to check certificates
from datetime import datetime
import socket
import json


hostname = "google.com"
ca ='/home/antoine/Documenti/Education/Master2/TLS-X.509-Scanner/Scanner/root_store/week3-roots.pem'


context = SSL.Context(SSL.TLS_CLIENT_METHOD)
context.load_verify_locations(ca)

print('Getting certificate chain for {0}'.format(hostname))
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock = SSL.Connection(context=context, socket=sock)
sock.settimeout(5)
sock.connect((hostname, 443))
sock.setblocking(1)
sock.do_handshake()
for (idx, cert) in enumerate(sock.get_peer_cert_chain()):
    print(' {0} s:{1}'.format(idx, cert.get_subject()))
    print(' {0} i:{1}'.format(' ', cert.get_issuer()))
sock.shutdown()
sock.close()


'''
"""
Set up local store of trusted root certificate
    -> in order to verify the server cert chain later on
"""
trustedCA = crypto.X509Store()
trustedCA.load_locations("Scanner/root_store/week3-roots.pem", None)
    #/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\
    # TODO
    #   -> enter the truster root CA
    #/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\/!\


"""
set up coonection
    -> create the conn
    -> connect to host and port
    -> do hand-shake
"""
s = socket.socket() #socket.AF_INET, socket.SOCK_STREAM
conn = SSL.Connection(ctxt, s)
conn.connect(("google.com",443))
conn.do_handshake()

"""
Manage cert PART 1/2: /!\ mainly for testing purposes /!\ 
    -> get cert chain
    -> print it
"""

cert_chain = conn.get_peer_cert_chain()
print(conn.get_protocol_version_name())
final = {}
i=0
for x509 in cert_chain:
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
    i=i+1
    final["Certificate {}".format(i)] = result
pprint(final)


"""
Manage cert PART 2/2:
 ->
"""
store_ctxt = crypto.X509StoreContext(trustedCA, cert_chain[0], cert_chain[1:])
try:                                                 
    # try to verify the certificate
    checked_chn = store_ctxt.verify_certificate()
except crypto.X509StoreContextError as e:            
    # intercepet the error that may be raised
    print(e)
else:                                               
    # celebrate
    print("yay")'''