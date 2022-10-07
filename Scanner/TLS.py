#################################################
#                libraries import               #
#################################################
### Public Libraries
# OpenSSL version 22.0.0
import ssl
from OpenSSL import SSL # create connection
from OpenSSL import crypto # to check certificates
import socket
from retry import retry
### Project defined
import LOG

    
def tls(ctxt, ip:str, host:str, logs:LOG.Log, i:int):
    """
    ----Function----
    Name :      ini ()
    type :      class constructor
    Effect :    manages the connection until the end
    """
    logs = logs
    context = ctxt
    (connection, ERR_CONNECT_FAILED)= set_connection(context, ip, host)
    if ERR_CONNECT_FAILED is None:
        (certificate_chain, ERR_CERTIF_FAILED) = get_certif(connection, ip)
        if ERR_CERTIF_FAILED is None:
            logs.x509_write(certificate_chain, connection.get_protocol_version_name()) # log the cert
        else :
            logs.errors_write(ERR_CERTIF_FAILED)
    else :
        logs.errors_write(ERR_CONNECT_FAILED)
    print(i)


def set_context(ca:str):
    """
    ----Function----
    Name :      set_context()
    Effect :    set up the context to use in the upcomming connection
    Return:     context(SSL.Context)
    """
    context = SSL.Context(SSL.TLS_CLIENT_METHOD)
    context.load_verify_locations(ca)
    context.set_verify(SSL.VERIFY_PEER)
    #context.set_timeout(1)
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
    sock.settimeout(30)
    ssock = SSL.Connection(context=ctxt, socket=sock)
    ssock.set_tlsext_host_name(host.encode("utf-8"))
    try :
        ssock.connect((ip, 443))
        handShake(ssock)
        return (ssock, None)
    except Exception as e:
        e = str(e)
        if len(e) < 2 :
            return (None, "WantedReedError")
        return (None, e)


@retry((SSL.WantReadError), tries=100, delay=0.1)
def handShake(ssock):
    ssock.do_handshake()

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