CC = clang
CXX = clang++

all:
	$(CXX) -pg  -O3 -march=native -std=c++17 -flto -g -I ../include -I ../fuzzers/include -c ../fuzzers/libFuzzer/main.cc
	$(CC) -pg  -O3 -march=native -flto -g -I ../include -c ../instrumentation/SanitizerCoverage/Runtime.c
	$(CC) -O0 -g -fsanitize-coverage=trace-pc-guard -c test.c
	$(CXX) -pg  -O3 -march=native -std=c++17 -flto -g -fsanitize-coverage=trace-pc-guard main.o Runtime.o test.o ../build/libFFF_static.a -o test.out -lstdc++fs

multi:
	$(CXX)  -O3 -march=native -std=c++17 -flto -g -I ../include -I ../fuzzers/include -c ../fuzzers/multicore/main.cc
	$(CC) -O3 -march=native -flto -g -I ../include -c ../instrumentation/SanitizerCoverage/Runtime.c
	$(CC) -O0 -g -fsanitize-coverage=trace-pc-guard -c test.c
	$(CXX) -O3 -march=native -std=c++17 -flto -g -fsanitize-coverage=trace-pc-guard,trace-cmp main.o Runtime.o test.o ../build/libFFF_static.a -o test.out -lstdc++fs
