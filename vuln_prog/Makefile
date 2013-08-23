# Paul Haas <phaas AT redspin DOT com>
# Makefile for automatic format string exploitation tool
CC=gcc
CFLAGS=-w -O0 -ggdb -std=c99
LDFLAGS=-static -D_FORTIFY_SOURCE=0 -fno-pie -Wno-format -Wno-format-security -fno-stack-protector -z norelro -z execstack 
SOURCES=printf.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=./printf

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJECTS) $(EXECUTABLE)

options:
	@grep -o "^[^ ]*:" Makefile | tr -d ':'

secure:
	@if [ `sysctl -n kernel.randomize_va_space` -ne 2 ]; then sudo sysctl -w kernel.randomize_va_space=2; fi
	@#ulimit -c 0
	rm -f $(OBJECTS) $(EXECUTABLE)

env:
	@if [ `sysctl -n kernel.randomize_va_space` -ne 0 ]; then sudo sysctl -w kernel.randomize_va_space=0; fi
	@#ulimit -c unlimited

root: $(EXECUTABLE) env
	sudo chown root:root $(EXECUTABLE)
	sudo chmod +s $(EXECUTABLE)

