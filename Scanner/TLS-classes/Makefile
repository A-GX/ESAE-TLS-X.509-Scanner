#####################################################################
#																	#
#	   <Project>TLS-classes/Makefile :: to test compute classes		#
#																  	#
#####################################################################
# Usage :
# 	| make   		// compile all binaries
#	| make clean	// clean all binaries

CC = g++
FLAGS = -Wall -g

BINS =

all: $(BINS)

###########################################################
# 				Compile binaries from .o				  #
###########################################################
%: %.o
	${CC} ${FLAGS} $< -o $@


###########################################################
# 			 Compile .o from the .c and the .h			  #
###########################################################
%.o: test-tls.cpp tls-1.h
	$(CC) -o $@ $< $(CFLAGS)