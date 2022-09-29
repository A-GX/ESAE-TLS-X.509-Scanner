#################################################
#                libraries import               #
#################################################
### Public Libraries
from OpenSSL import SSL # create connection
from OpenSSL import crypto # to check certificates
import socket
### Project defined
import log

class Tls:
    """
    ----Class----
    Name :  Tls
    Use :   todo
    """

    
    def __init__(self, tls:int, host:str, trustedCA:str, logs:log.Log):
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
        if self.__ERR_CONNECTION_FAILED is None:
            self.__trustedCA = self.__set_trustedCA(trustedCA)
            self.__store_ctxt = crypto.X509StoreContext(self.__trustedCA, self.__certificate_chain[0], self.__certificate_chain[1:])
            self.__ERR_CHECK_CERT = self.__check_cert(self.__store_ctxt)
            if self.__ERR_CHECK_CERT is None:
                print("SUCCESS")
            self.__logs = logs
        # Need to do the logs


    #################################################
    #                Private methods                #
    #################################################
    def __set_context(self, tls:int):
        """
        ----Function----
        Name :      __set_context()
        Args :      self -> instance of the object
                    tls(int) -> the tls version to use for the connection
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
    
    
    def __set_connection(self, ctxt:SSL.Context, host:str):
        """
        ----Function----
        Name :      __set_connection()
        Args :      self -> instance of the object
                    ctxt(SSL.Context) -> The context to use for the connection
                    host(str) -> the host to which we want to connect
        Effect :    set up the connection to use for the handshake
        Return:     connection(SSl.Connection)
        """
        conn = SSL.Connection(ctxt, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        conn.connect((host,443))
        return conn

    def __get_certif(self, conn:SSL.Connection):
        """
        ----Function----
        Name :      __get_certif()
        Args :      self -> instance of the object
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
            conn.do_handshake()
            certif_chain = conn.get_peer_cert_chain()
            return(certif_chain,None)
        except Exception as e:
            return (None,e)

    def __set_trustedCA(self, path:str):
        """
        ----Function----
        Name :      __set_trustedCA()
        Args :      self -> instance of the object
                    path -> path towards the trustedCA
        Effect :    create the root store to verify certificates later on
        Return:     return the root store initialised
        """
        trustedCA = crypto.X509Store()
        trustedCA.load_locations(path, None)
        return trustedCA
            
    def __check_cert(self,ctxt):
        """
        ----Function----
        Name :      __check_cert()
        Args :      self -> instance of the object
                    ctxt -> context in xhich to check the cert chain
        Effect :    try to verify the certificates
        Return:     return the error
        """
        try:                                                 
            # try to verify the certificate
            ctxt.verify_certificate()
        except crypto.X509StoreContextError as e:            
            # intercepet the error that may be raised
            return e
        return None
    #################################################
    #                 Public methods                #
    #################################################


if __name__ == "__main__":
    l= log.Log(None, None)
    path="/home/antoine/Documenti/Education/Master2/TLS-X.509-Scanner/Scanner/root_store/week3-roots.pem"
    tls = Tls(tls=2,host="google.com",trustedCA=path,logs=l)