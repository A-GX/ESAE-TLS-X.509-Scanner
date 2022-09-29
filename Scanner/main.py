#################################################
#                libraries import               #
#################################################
from sre_constants import SUCCESS
import sys

#################################################
#                Global Variables               #
#################################################
MIN_ARG = 3 # argv[0] = path to executable
ERR_MISSING_ARG = "[Missing Arguments]: You need to provide at least {} paramaters !".format(MIN_ARG)
ERR_MISSING_OPTION = "[Missing Option]: missing option in front of the file, plese see -help"
ERR_SHOULD_BE_FILE = "[Should Be a File]: the slot after command -{} should be a file name, not another command."
OUT = None
IN = None
BLOCK_LIST = None

def analyse_options():
    """
    Name :      Analyse_options()
    Args :      None
    Effect :    Analyse option given during the call to the scanner 
                (like -help, -out output.txt, etc...)
    Return:      None
    """
    i = 1
    while i <= argc-1 :
        arg = sys.argv[i]
        if arg[0] == '-':
            print("Checking if is option")
            #################################################
            #              Option to give file              #
            #################################################
            if arg[1:] == "out":
                i += 1 # next arg = output file
                f_name = sys.argv[i]
                if f_name[0] == '-': # if following call parameter is a command, rais error
                    raise ValueError(ERR_SHOULD_BE_FILE.format(arg[1:]))
                
                OUT = open(f_name, "w") # Need to check if we are allowed to read the file !!
            
            if arg[1:] == "in":
                i += 1 # next arg = input file
                f_name = sys.argv[i]
                if f_name[0] == '-': # if following call parameter is a command, rais error
                    raise ValueError(ERR_SHOULD_BE_FILE.format(arg[1:]))
                ok = False
                while not ok : # don't stop while file not valid
                    try:
                        IN = open(f_name, "r")
                        ok = True
                    except Exception as e:
                        print(e)
                        f_name = input("Correct file name :\n> ")

            if arg[1:] == "block-list":
                i += 1 # next arg = input file
                f_name = sys.argv[i]
                if f_name[0] == '-': # if following call parameter is a command, rais error
                    raise ValueError(ERR_SHOULD_BE_FILE.format(arg[1:]))
                ok = False
                while not ok : # don't stop while file not valid
                    try:
                        BLOCK_LIST = open(f_name, "r")
                        ok = True
                    except Exception as e:
                        print(e)
                        f_name = input("Correct file name :\n> ")
                
                
                

            #################################################
            #                 Other options                 #
            #################################################
            if arg[1:] == "help":
                print("help")

        else :
            raise ValueError(ERR_MISSING_OPTION)
        
        i += 1 # increment


def close_files():
    """
    Name :      close_files()
    Args :      None
    Effect :    close all files opened by the user arguments
                while calling the scanner
    Return:     None
    """
    if not (OUT is None) :
        OUT.close()
    if not (BLOCK_LIST is None) :
        BLOCK_LIST.close()
    if not (IN is None):
        IN.close()
    """else :
        raise ValueError("Should not be empty") #To modify
        """

if __name__ == "__main__":
    argc = len(sys.argv)
    if (argc < MIN_ARG):
        raise ValueError(ERR_MISSING_ARG)
    analyse_options()
    close_files()