#################################################
#                libraries import               #
#################################################
from OpenSSL import SSL # create connection
import socket

class tls:
    """
    ----Class----
    Name :  tls
    Use :   something
    """
    def __init__(self, tls:int, host:str, ):
        """
        ----Function----
        Name :      __init__()
        type :      class constructor
        Args :      self(object tls) the current object
                    tls(int) -> the tls version to use for the connection
        Effect :    Initialise the newly created object
        """
        self.__context = self.__set_context(tls)
        self.__connection = self.__set_connection(self.__context, host)
        (self.__certificate_chain, self.__ERR_CONNECTION_FAILED) = self.__get_certif(self.__connection)


    #################################################
    #                Private methods                #
    #################################################
    def __set_context(tls:int):
        """
        ----Function----
        Name :      __set_context()
        Args :      tls(int) -> the tls version to use for the connection
        Effect :    set up the context to use in the upcomming connection
        Return:     context(SSL.Context)
        """
        if tls == 0: # version = TLS 1.0
            context = SSL.Context(SSL.TLSv1_METHOD) # specify TLS 1.0 in header
            context.set_min_proto_version(SSL.TLS1_VERSION)  # version to use = TLS 1.0
            context.set_max_proto_version(SSL.TLS1_VERSION)
        elif tls == 1: # version = TLS 1.1
            context = SSL.Context(SSL.TLSv1_1_METHOD) # specify TLS 1.1 in header
            context.set_min_proto_version(SSL.TLS1_1_VERSION) # version to use = TLS 1.1
            context.set_max_proto_version(SSL.TLS1_1_VERSION)
        else : # version = TLS 1.2 or 1.3
            context = SSL.Context(SSL.TLSv1_2_METHOD) # specify TLS 1.2 in header
            if tls == 2 : # version = TLS 1.2
                context.set_min_proto_version(SSL.TLS1_2_VERSION) # version to use = TLS 1.2
                context.set_max_proto_version(SSL.TLS1_2_VERSION)
            if tls == 3 : # version = TLS 1.2
                context.set_min_proto_version(SSL.TLS1_3_VERSION) # version to use = TLS 1.3
                context.set_max_proto_version(SSL.TLS1_3_VERSION)
        return context
    
    
    def __set_connection(ctxt:SSL.Context, host:str):
        """
        ----Function----
        Name :      __set_connection()
        Args :      ctxt(SSL.Context) -> The context to use for the connection
                    host(str) -> the host to which we want to connect
        Effect :    set up the connection to use for the handshake
        Return:     connection(SSl.Connection)
        """
        conn = SSL.Connection(ctxt, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        conn.connect((host,443))
        return conn

    def __get_certif(conn:SSL.Connection):
        """
        ----Function----
        Name :      __get_certif()
        Args :      conn(SSL.Connection) -> 
        Effect :    try to establish connection with the host and get its
                    certificate chain.
        Return:     tupple (certif_chain,Error)
                        -> certif_chain(X509) : the chain of certificate returned
                            by the host
                        -> Error(Exception) : the exception that occured while trying
                            to connect
        """
        try :
            conn.do_handshake()
            certif_chain = conn.conn.get_peer_cert_chain()
            return(certif_chain,None)
        except Exception as e:
            return (None,e)
            
    #################################################
    #                 Public methods                #
    #################################################