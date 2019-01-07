#OBJS=pcap.o analyze.o print.o checksum.o
OBJS=analyze.o print.o checksum.o
PCAP=pcap.o
TEST=test.o
#SRCS=$(OBJS:%.o=%.c)

CFLAGS=-g -Wall
LDLIBS=
TARGET=pcap
$(TARGET):$(OBJS) $(PCAP)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS) $(PCAP) $(LDLIBS)

test: $(OBJS) $(TEST)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(TEST) $(LDLIBS)
.c.o:
	$(CC) -c $(CFLAGS) $*.c

clean:
	rm -rf $(OBJS) $(PCAP) $(TEST) $(TARGET) *~
