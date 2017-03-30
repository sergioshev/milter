LIBS_SENDMAIL=/usr/lib/libmilter/libmilter.a
LDFLAGS=-pthread
CFLAGS=
CC=cc
MILTER_NAME=mailforward
OBJ_TARGETS=eval_node.o linked_list.o str_utils.o

%.o : %.c
	$(CC) -c -o $@ $<

.PHONY: all
all: $(MILTER_NAME).c $(OBJ_TARGETS)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $(MILTER_NAME) $< $(LIBS_SENDMAIL) $(OBJ_TARGETS)

.PHONY: clean
clean:
	rm -f *.o $(MILTER_NAME)


