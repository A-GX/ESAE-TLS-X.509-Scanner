from pprint import pprint
from OpenSSL import SSL # to create connection
from OpenSSL import crypto # to check certificates
from datetime import datetime
import socket


"""
Set up the context :
    -> TLS method (in header)
    -> TLS version
"""
ctxt = SSL.Context(SSL.TLSv1_2_METHOD) # start handshake with TLSv1.2 id (for TLSv1.2 and TLSv1.3)
ctxt.set_min_proto_version(SSL.TLS1_3_VERSION) # set TLSv1.3 as only accepted version

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
conn = SSL.Connection(ctxt, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
conn.connect(("google.com",443))
conn.do_handshake()

"""
Manage cert PART 1/2: /!\ mainly for testing purposes /!\ 
    -> get cert chain
    -> print it
"""
cert_chain = conn.get_peer_cert_chain()
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
    pprint(result)

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
    print("yay")