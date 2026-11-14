# Простой компилятор и базовые флаги для чистого Си
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -Isrc

# Имя конечного исполняемого файла
TARGET = cslr

# Список всех объектных файлов, которые нужно собрать
OBJS = src/main.o \
       src/algo/stribog.o \
       src/algo/kuznyechik.o \
       src/algo/rsa.o \
       src/key_parser/key_parser.o

# Главное правило по умолчанию — собираем нашу утилиту
all: $(TARGET)

# Линковка: собираем бинарник из всех объектников + подключаем libinih
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) -linih

# Правило для очистки проекта от временных файлов компиляции
clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean

