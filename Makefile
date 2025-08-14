CC = gcc
CFLAGS = -O2 -Wall -I/usr/local/include
LDFLAGS = -L/usr/local/lib -loqs -lm
TARGET = ct-checker

all: $(TARGET)

$(TARGET): harness.c
	$(CC) $(CFLAGS) -o $(TARGET) harness.c $(LDFLAGS)

clean:
	rm -f $(TARGET)
