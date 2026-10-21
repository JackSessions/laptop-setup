# make        build with warnings + AddressSanitizer/UBSan (catches most C mistakes)
# make run    build and run
# make debug  build with -g -O0 for gdb / nvim-dap (F5 in LazyVim)
# make leaks  run under valgrind
# make lint   cppcheck + clang-format check
CC      = gcc
CFLAGS  = -std=c17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -g -fsanitize=address,undefined
SRC     = $(wildcard *.c)
BIN     = app

$(BIN): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(BIN)

run: $(BIN)
	./$(BIN)

debug: CFLAGS = -std=c17 -Wall -Wextra -g -O0
debug: clean $(BIN)

leaks: CFLAGS = -std=c17 -Wall -Wextra -g -O0
leaks: clean $(BIN)
	valgrind --leak-check=full --show-leak-kinds=all ./$(BIN)

lint:
	cppcheck --enable=all --inconclusive --quiet $(SRC)
	clang-format --dry-run -Werror $(SRC)

clean:
	rm -f $(BIN)

.PHONY: run debug leaks lint clean
