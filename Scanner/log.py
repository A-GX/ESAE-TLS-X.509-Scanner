#################################################
#                libraries import               #
#################################################
from OpenSSL import crypto # to check certificates
import json


class Log:
    """
    ----Class----
    Name :  log
    Use :   todo
    """
    def __init__(self, log_tls, log_x509):
        """
        ----Function----
        Name :      __init__()
        type :      class constructor
        Args :      
        Effect :    Initialise the newly created object
        """
        self.__log_tls = log_tls
        self.__log_x509 = log_x509

    #################################################
    #                Private methods                #
    #################################################
     
    #################################################
    #                 Public methods                #
    #################################################
    def x509_write(self, certif_chain):
        """
        ----Function----
        Name :      __x509_write()
        Args :      self -> instance of the object
                    certif_chain -> a chain of certificate to write in
                        the log 
        Effect :    set up the connection to use for the handshake
        Return:     None
        """
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

        self.__log_x509.write(json.dumps(result, indent=2))
    
    def TLS_write(self, smth):
        """
        todo
        """