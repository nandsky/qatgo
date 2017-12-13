
OBJS =
CC = gcc
DEBUG = -g
CFLAGS = -Wall $(DEBUG)
LFLAGS = -Wall $(DEBUG)


OUTPUT_DIR = ../../output
INCLUDE = -I. -I../../lib/qat
LIBS = -L. -L./$(OUTPUT_DIR) -licp_qa_al_s
LIBS_WITH_CAPI = -L. -L./$(OUTPUT_DIR) -licp_qa_al_s -lqatgo


test_md5_SRC = test_md5.c
test_dh_SRC = test_dh.c
test_qat_SRC = test_qat.c

all: test_qat test_md5 test_dh

test_qat:
	$(CC) $(CFLAGS) $(INCLUDE) $(LIBS) $(test_qat_SRC) -o $(OUTPUT_DIR)/test_qat

test_md5:
	$(CC) $(CFLAGS) $(INCLUDE) $(LIBS_WITH_CAPI) $(test_md5_SRC) -o $(OUTPUT_DIR)/test_md5
	
test_dh:
	$(CC) $(CFLAGS) $(INCLUDE) $(LIBS_WITH_CAPI) $(test_dh_SRC)  -o $(OUTPUT_DIR)/test_dh
