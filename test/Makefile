all:
	clang++ -pg  -O3 -march=native -std=c++17 -flto -g -I ../include -I ../fuzzers/include -c ../fuzzers/libFuzzer/main.cc
	clang -pg  -O3 -march=native -flto -g -I ../include -c ../instrumentation/SanitizerCoverage/Runtime.c
	clang -O0 -g -fsanitize-coverage=trace-pc-guard,trace-cmp -fsanitize=address -c test.c
	clang++ -pg  -O3 -march=native -std=c++17 -flto -g -fsanitize=address -fsanitize-coverage=trace-pc-guard,trace-cmp main.o Runtime.o test.o ../build/libFFF_static.a -o test.out

multi:
	clang++  -O3 -march=native -std=c++17 -flto -g -I ../include -I ../fuzzers/include -c ../fuzzers/multicore/main.cc
	clang -O3 -march=native -flto -g -I ../include -c ../instrumentation/SanitizerCoverage/Runtime.c
	clang -O0 -g -fsanitize-coverage=trace-pc-guard -c test.c
	clang++ -O3 -march=native -std=c++17 -flto -g -fsanitize-coverage=trace-pc-guard,trace-cmp main.o Runtime.o test.o ../build/libFFF_static.a -o test.out -fsanitize=address
