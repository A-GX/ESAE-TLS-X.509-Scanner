from pprint import pprint
import re
from OpenSSL import SSL # to create connection
from OpenSSL import crypto # to check certificates
from datetime import datetime
from retry import retry
import socket
import json
import ast

ip = socket.gethostbyname("google.com")
hostname = b"google.com"
ca ='/home/antoine/Documenti/Education/Master2/TLS-X.509-Scanner/Scanner/root_store/week3-roots.pem'


@retry((SSL.WantReadError), tries=300, delay=0.1)
def handshake(sock):
    sock.do_handshake()

context = SSL.Context(SSL.TLS_CLIENT_METHOD)
context.load_verify_locations(ca)
context.set_verify(SSL.VERIFY_PEER)

print('Getting certificate chain for {0}'.format(hostname))
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(30)
ssock = SSL.Connection(context=context, socket=sock)
ssock.set_tlsext_host_name(hostname)
ssock.connect_ex((ip, 443))
handshake(ssock)
cert_chain = ssock.get_peer_cert_chain()
print(ssock.get_protocol_version_name())
final = []
i=0
for x509 in cert_chain:
    tempo2 = {
        'subject': dict(x509.get_subject().get_components()),
        'issuer': dict(x509.get_issuer().get_components())
       # 'serialNumber': x509.get_serial_number(),
       # 'version': x509.get_version(),
       # 'notBefore': datetime.strptime((x509.get_notBefore()).decode("utf-8"), '%Y%m%d%H%M%SZ'),
       # 'notAfter': datetime.strptime(x509.get_notAfter().decode("utf-8"), '%Y%m%d%H%M%SZ')
    }
    """tempo2={}
    for k in tempo.keys():
        tempo2[k]={}
        for b in tempo[k].keys():
            tempo2[k][str(b)[2:-1]] = str(tempo[k][b])[2:-1]
"""

    extensions = (x509.get_extension(i) for i in range(x509.get_extension_count()))
    extension_data = {e.get_short_name(): str(e) for e in extensions}
    tempo2.update(extension_data)
    result={}
    for k in tempo2.keys():
        if not(k=='subject' or k=='issuer'):
            if k == b'ct_precert_scts' :
                res =  re.findall('Log ID.*\n.*', tempo2[k])
                f=[]
                to_match = '[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:?'
                for id in res :
                    r=re.findall(to_match,id)
                    f.append(r[0]+r[1])
                result[str(k)[2:-1]] = f
            else:
                result[str(k)[2:-1]] = tempo2[k]
        else :
            result[k]={}
            for b in tempo2[k].keys():
                result[k][str(b)[2:-1]] = str(tempo2[k][b])[2:-1]
    i=i+1
    final.append(result)
pprint(final)
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