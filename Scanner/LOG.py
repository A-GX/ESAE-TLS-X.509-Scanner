#################################################
#                libraries import               #
#################################################
# OpenSSL version 22.0.0
from OpenSSL import crypto # to check certificates
import json


class Log:
    """
    ----Class----
    Name :  log
    Use :   todo
    """
    def __init__(self, log_tls, log_x509, log_errors = None):
        """
        ----Function----
        Name :      __init__()
        type :      class constructor
        Args :      
        Effect :    Initialise the newly created object
        """
        self.__log_tls = log_tls
        self.__log_x509 = log_x509
        self.__log_errors =  log_errors

    #################################################
    #                Private methods                #
    #################################################
     
    #################################################
    #                 Public methods                #
    #################################################
    def errors_write(self,error):
        """
        ----Function----
        Name :      errors_write()
        Args :      self -> instance of the object
                    errors -> a chain of certificate to write in
                        the log 
        Effect :    if a file has been specified for log_errors, write in it.
                    else, print in stdout. The name error is a bit much, it is actually warnings
        Return:     None
        """
        if self.__log_errors is None:
            print("\033[93m" + str(error)+"\033[0m")
        else :
            self.__log_errors.write(str(error))

            
    def x509_write(self, certif_chain):
        """
        ----Function----
        Name :      x509_write()
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