# 在libqatgo.so被编译出的基础上，编译出server app

OBJS =
CC = gcc
DEBUG = -g
CFLAGS = -Wall $(DEBUG)
LFLAGS = -Wall $(DEBUG)


OUTPUT_DIR = .
INCLUDE = -I/usr/local/ssl/include -I/usr/local/include/ -I/usr/local/Cellar/openssl@1.1/1.1.0f/include
LIBS = -L/usr/local/ssl/lib -lcrypto

CMN_SRC :=

qatgo_SRC = e_jc.c jc_rsa.c net.c prot.c packet.c utils.c

test_rpc_SRC = client.c job.pb-c.c

all: cry $(test)

cry:
	$(CC) $(LFLAGS) $(INCLUDE)  $(LIBS) $(qatgo_SRC) -fPIC -shared -o $(OUTPUT_DIR)/cry.so

test_rpc:
	$(CC) $(CFLAGS) $(INCLUDE) $(LIBS) $(test_rpc_SRC) -o $(OUTPUT_DIR)/client

.PHONY : clean
clean :
	-rm $(OUTPUT_DIR)/*
