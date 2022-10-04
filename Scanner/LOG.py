#################################################
#                libraries import               #
#################################################
# OpenSSL version 22.0.0
from OpenSSL import crypto # to check certificates
from datetime import datetime
import json
import re
from pprint import pprint


class Log:
    """
    ----Class----
    Name :  log
    Use :   todo
    """
    def __init__(self, log_x509, log_errors):
        """
        ----Function----
        Name :      __init__()
        type :      class constructor
        Args :      
        Effect :    Initialise the newly created object
        """
        self.__log_x509 = log_x509
        self.__log_errors =  log_errors


    #################################################
    #                Private methods                #
    #################################################
     
    #################################################
    #                 Public methods                #
    #################################################
    def errors_write(self,error:str):
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
            print("\033[93m" + error +"\033[0m")
        else :
            self.__log_errors.write((str(error)+"\n").encode('ascii'))


    def x509_write(self, certif_chain, version):
        """
        ----Function----
        Name :      x509_write()
        Args :      self -> instance of the object
                    certif_chain -> a chain of certificate to write in
                        the log 
        Effect :    set up the connection to use for the handshake
        Return:     None
        """
        #
        # this is really  ugly, but it is just to try  to have an output not to 
        # horrible to work with
        #
                
        final = [] # result to  store in log
        final.append(version) # add tls version to result
        for x509 in certif_chain: 
            tempo2 = { # get subject and issuer field of cert
                'subject': dict(x509.get_subject().get_components()),
                'issuer': dict(x509.get_issuer().get_components())
            }
            # get other field of cert (of xwhich field on ct logs)
            extensions = (x509.get_extension(i) for i in range(x509.get_extension_count()))
            extension_data = {}

            for e in extensions:
                try : # not all the extensions support the "str" operator, it can cause errors
                    value = str(e)
                except :
                    value = "not supported"
                # add to the dict
                extension_data[str(e.get_short_name())[2:-1]] = value 

            tempo2.update(extension_data)
            result={}
            for k in tempo2.keys():
                # "subject" and "issuer" have dict of bytes, that are not supported by json.dumps
                if not(k=='subject' or k=='issuer'):
                    if k == 'ct_precert_scts' : # extract a list of oll  the ct log it of certificate
                        res =  re.findall('Log ID.*\n.*', tempo2[k]) # get list of all LOG ID : ...\n...(stop at \n here)
                        f=[]
                        #pattern that match the two half of the ID from the ugly string extracted above
                        to_match = '[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:?'
                        for id in res : # create a nice string of the ID
                            r=re.findall(to_match,id)
                            f.append(r[0]+r[1])
                        result[k] = f # the above  part add really big complexity, but as it is threaded it should be bearable
                    else:
                        result[k] = tempo2[k]
                else : #put in a str format
                    result[k]={}
                    for b in tempo2[k].keys():
                        # we convert the bytes in str
                        result[k][str(b)[2:-1]] = str(tempo2[k][b])[2:-1]
            final.append(result)
        
        
            if self.__log_x509 is None:
                pprint(final)
            else :
                self.__log_x509.write(json.dumps(final, indent=2)+"\n")