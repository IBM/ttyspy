CFLAGS=-std=gnu11 -D_GNU_SOURCE=1 -Wall -Wextra -g

%.o: %.c
	$(CC) $(CFLAGS) -c $<

ttyspy: ttyspy.o
	$(CC) $(CFLAGS) -o $@ $^ -lutil -lcurl
