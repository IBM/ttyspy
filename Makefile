

%.o: %.c
	gcc -Wall -Wextra -c $<

ttyspy: ttyspy.o
	gcc -Wall -Wextra -o $@ $^ -lutil
