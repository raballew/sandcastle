CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lcap

TARGET = sandcastle
SRC = sandcastle.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

install:
	install -m 755 $(TARGET) /usr/local/bin/
