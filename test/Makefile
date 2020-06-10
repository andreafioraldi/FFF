all:
	clang++ -std=c++17 -flto -g -I ../include -I ../instrumentation -I ../fuzzers/include -c ../fuzzers/libFuzzer/main.cc
	clang -flto -g -I ../instrumentation -c ../instrumentation/SanitizerCoverage/Runtime.c
	clang -flto -g -fsanitize-coverage=trace-pc-guard,trace-cmp -fsanitize=address -c test.c
	clang++ -std=c++17 -flto -g -fsanitize=address -fsanitize-coverage=trace-pc-guard,trace-cmp main.o Runtime.o test.o -L ../build -lFFF -Wl,-rpath=`pwd`/../build -o test.out
