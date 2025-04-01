CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lcap

BUILD_DIR = build
TARGET = $(BUILD_DIR)/sandcastle
SRC = sandcastle.c config.c server.c sandbox.c utils.c
OBJ = $(patsubst %.c,$(BUILD_DIR)/%.o,$(SRC))
HEADERS = sandcastle.h config.h server.h sandbox.h utils.h

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(OBJ) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: %.c $(HEADERS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)

install:
	install -m 755 $(TARGET) /usr/local/bin/
