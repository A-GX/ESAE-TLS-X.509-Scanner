#################################################
#                libraries import               #
#################################################
### Public Libraries
# OpenSSL version 22.0.0
import ssl
from OpenSSL import SSL # create connection
from OpenSSL import crypto # to check certificates
import socket
### Project defined
import LOG

    
def tls(tls:int, ip:str, host:str, trustedCA:str, logs:LOG.Log):
    """
    ----Function----
    Name :      ini ()
    type :      class constructor
    Args :      bject tls) the current object
                tls(int) -> the tls version to use for the connection
    Effect :    manages the connection until the end
    """
    logs = logs
    context = set_context(tls, trustedCA)
    (connection, ERR_CONNECT_FAILED)= set_connection(context, ip, host)
    if ERR_CONNECT_FAILED is None:
        (certificate_chain, ERR_CERTIF_FAILED) = get_certif(connection, ip)
        if ERR_CERTIF_FAILED is None:
#            #trustedCA = set_trustedCA(trustedCA)
#            #store_ctxt = crypto.X509StoreContext(trustedCA, certificate_chain[0], certificate_chain[1:])
#            ERR_CHECK_CERT = check_cert(store_ctxt)
#            if ERR_CHECK_CERT is None:
#                print("SUCCESS")
            # Need to do the logs
            logs.x509_write(certificate_chain, connection.get_protocol_version_name()) # log the cert
        else :
            logs.errors_write(ERR_CERTIF_FAILED)
    else :
        logs.errors_write(ERR_CONNECT_FAILED)


#    # set context so that client and server negotiate TLS protocol
#    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
#    #  set root store to verify certif
#    context.load_verify_locations(trustedCA)
#    # It never worked with check_hostname = True
#    context.check_hostname = True
#    s = context.wrap_socket(socket.socket(), server_hostname=name) # /!\/!\host name should be first column/!\/!\
#    # timeout = 10 to not spend 3+ minutes to get a [connection time out]
#    s.settimeout(10)
#    try: # try to do the connection
#        s.connect((host,443)) # connect to the host
#        # get cert, but not the chain. ssl does not support it, and OpenSSL never
#        # worked correctly (error No SNI provided; please fix your client.
#        # and [('SSL routines', '', 'internal error')] with lower version than 1.2)
#        cert=s.getpeercert() # get its cert, but no chain. 
#        logs.x509_write(cert) # log the cert
#        logs.errors_write(str(s.version())) # log the version in a separate log  
#    except Exception as e:
#        # log the error
#        logs.errors_write(str(e))

def set_context(tls:int, ca:str):
    """
    ----Function----
    Name :      set_context()
                tls(int) -> the tls version to use for the connection
    Effect :    set up the context to use in the upcomming connection
    Return:     context(SSL.Context)
    """
    context = SSL.Context(SSL.TLS_CLIENT_METHOD)
    context.load_verify_locations(ca)
    context.set_verify(SSL.VERIFY_PEER)
    context.set_timeout(1)
    return context

#    if tls == 0: # version = TLS 1.0
#        context = SSL.Context(SSL.TLSv1_METHOD) # specify TLS 1.0 in header
#        context.set_min_proto_version(SSL.TLS1_VERSION)  # version to use = TLS 1.0
#        context.set_max_proto_version(SSL.TLS1_VERSION)
#    elif tls == 1: # version = TLS 1.1
#        context = SSL.Context(SSL.TLSv1_1_METHOD) # specify TLS 1.1 in header
#        context.set_min_proto_version(SSL.TLS1_1_VERSION) # version to use = TLS 1.1
#        context.set_max_proto_version(SSL.TLS1_1_VERSION)
#    else : # version = TLS 1.2 or 1.3
#        context = SSL.Context(SSL.TLSv1_2_METHOD) # specify TLS 1.2 in header
#        if tls == 2 : # version = TLS 1.2
#            context.set_min_proto_version(SSL.TLS1_2_VERSION) # version to use = TLS 1.2
#            #context.set_max_proto_version(SSL.TLS1_2_VERSION)
#        if tls == 3 : # version = TLS 1.2
#            context.set_min_proto_version(SSL.TLS1_3_VERSION) # version to use = TLS 1.3
#            #context.set_max_proto_version(SSL.TLS1_3_VERSION)
#    return context


def set_connection(ctxt:SSL.Context, ip:str, host:str):
    """
    ----Function----
    Name :      set_connection()t
                ctxt(SSL.Context) -> The context to use for the connection
                host(str) -> the host to which we want to connect
    Effect :    set up the connection to use for thge handshake
    Return:     connection(SSl.Connection)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock = SSL.Connection(context=ctxt, socket=sock)
    sock.set_tlsext_host_name(host.encode("utf-8"))
    sock.settimeout(1) # does not seem to work, time out still painfully long
    sock.setblocking(1) # do not block the connection, not that useful
    try :
        sock.connect((ip, 443))
        sock.do_handshake()
        return (sock, None)
    except Exception as e:
        return (None, str(e))


#    conn = SSL.Connection(ctxt, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
#    try:
#        # cann't find how to set timeout, can take up to 5min (300s)
#        conn.connect((host,443))
#    except Exception as e:
#        return(None,e)name
#    return (conn,None)

def get_certif(conn:SSL.Connection, ip:str):
    """
    ----Function----
    Name :      get_certif()
                conn(SSL.Connection) -> 
    Effect :    try to establish connection with the host and get its
                certificate chain.
    Return:     tupple (certif_chain,Error)
                    -> certif_chain(X509) : the chain of certificate returned
                        by the host
                    -> Error(Exception) : the exception that occured while trying
                        to connect
    """
    try : 
        cert = conn.get_peer_cert_chain()
        conn.shutdown()
        conn.close()
        return (cert, None)
    except Exception as e:
        conn.close()
        return(None, str(e))

 #   try :
 #       conn.do_handshake()
 #       certif_chain = conn.get_peer_cert_chain()
 #       conn.shutdown()
 #       conn.close()
 #       return(certif_chain,None)
 #   except Exception as e:
 #       conn.close()
 #       return (None,e)

#def set_trustedCA(path:str):
#    """
#    ----Function----
#    Name :      set_trustedCA()
#                path -> path towards the trustedCA
#    Effect :    create the root store to verify certificates later on
#    Return:     return the root store initialised
#    """
#    trustedCA = crypto.X509Store()
#    trustedCA.load_locations(path, None)
#    return trustedCA
#        
#def check_cert(ctxt):
#    """
#    ----Function----
#    Name :      check_cert()
#                ctxt -> context in xhich to check the cert chain
#    Effect :    try to verify the certificates
#    Return:     return the error
#    """
#    try:                                                 
#        # try to verify the certificate
#        ctxt.verify_certificate()
#    except crypto.X509StoreContextError as e:            
#        # intercepet the error that may be raised
#        return e
#    return None


if __name__  ==  "__main__":
    #exit()
    
    l= LOG.Log(None, None, None)
    path="/home/antoine/Documenti/Education/Master2/TLS-X.509-Scanner/Scanner/root_store/week3-roots.pem"
    tls = tls(tls=3,ip='172.67.179.52',host="myorganicbuds.me",trustedCA=path,logs=l)