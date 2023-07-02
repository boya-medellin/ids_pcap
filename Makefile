# the compiler: gcc for C program, define as g++ for C++
CC = gcc
CFLAGS  = -lpcap
TARGET = IDS

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) -o $(TARGET) $(TARGET).c $(TARGET).h $(CFLAGS)

clean:
	$(RM) $(TARGET)

