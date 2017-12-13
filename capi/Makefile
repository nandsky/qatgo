
# 在libqatgo.so被编译出的基础上，编译出server app

OBJS =
CC = gcc
DEBUG = -g
CFLAGS = -Wall $(DEBUG)
LFLAGS = -Wall $(DEBUG)


OUTPUT_DIR = ../output
INCLUDE = -I. -I../lib/qat -I.
LIBS = -L. -L../$(OUTPUT_DIR) -licp_qa_al_s -lqatgo

CMN_SRC :=

qatgo_SRC = qat.c utils.c mem_utils.c \
		callback.c cipher.c dh.c polling.c qae_mem_utils.c \
		rsa.c ecdh.c ecdsa.c \
		ec.c


test: test_md5 test_dh
all: libqatgo

libqatgo:
	$(CC) $(LFLAGS) $(INCLUDE) $(qatgo_SRC) -fPIC -shared -o $(OUTPUT_DIR)/libqatgo.so

.PHONY : clean
clean :
	-rm $(OUTPUT_DIR)/*


