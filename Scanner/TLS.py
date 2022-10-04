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
            logs.x509_write(certificate_chain, connection.get_protocol_version_name()) # log the cert
        else :
            logs.errors_write(ERR_CERTIF_FAILED)
    else :
        logs.errors_write(ERR_CONNECT_FAILED)



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


if __name__  ==  "__main__":
    #exit()
    
    l= LOG.Log(None, None, None)
    path="/home/antoine/Documenti/Education/Master2/TLS-X.509-Scanner/Scanner/root_store/week3-roots.pem"
    tls = tls(tls=3,ip='172.67.179.52',host="myorganicbuds.me",trustedCA=path,logs=l)