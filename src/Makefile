UNIQUE ?= 2
TOTAL ?= 10

.PHONY: all change run clean clean_all

# Запустить программу со стандартными данными
all: run

# Поменять данные в файле и запустить заново в формате make change UNIQUE=3 TOTAL=13
change: clean run

input.txt:
	python3 generate_data.py input.txt $(UNIQUE) $(TOTAL)

unique_ipv6:
	g++ -O3 -pthread -std=c++17 count_unique_ipv6.cc -o unique_ipv6

run: unique_ipv6 input.txt
	./unique_ipv6 input.txt output.txt

clean:
	rm -f input.txt output.txt

clean_all:
	rm -f input.txt output.txt unique_ipv6
