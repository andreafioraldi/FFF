all:
	clang++ -std=c++17 -flto -g -fPIC -shared -I include src/*.cc -o libFFF.so
	clang++ -std=c++17 -flto -g -I include -I instrumentation -c fuzzers/libFuzzer.cc
	clang -flto -g -I instrumentation -c instrumentation/SanitizerCoverage/Runtime.c
	clang -flto -g -fsanitize-coverage=trace-pc-guard,trace-cmp -c test/test.c
	clang++ -std=c++17 -flto -g -fsanitize-coverage=trace-pc-guard,trace-cmp libFuzzer.o Runtime.o test.o -L . -lFFF -Wl,-rpath=. -o test.out
