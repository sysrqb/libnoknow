GTEST_DIR=ext/googletest/googletest
SRCS= src/statemachine.c src/noknow.c
TESTS= test/statemachine_test.cc test/noknow_test.cc
SRCS_OBJ= statemachine.o noknow.o


.PHONY: test clean

libgtest.a:
	g++ -g -isystem ${GTEST_DIR}/include -I${GTEST_DIR} -pthread -c \
		${GTEST_DIR}/src/gtest-all.cc -o gtest_all_gcc.o
	clang++ -g -isystem ${GTEST_DIR}/include -I${GTEST_DIR} -pthread -c \
		${GTEST_DIR}/src/gtest-all.cc -o gtest_all_clang.o
	ar -rv libgtest_gcc.a gtest_all_gcc.o
	ar -rv libgtest_clang.a gtest_all_clang.o

test:  libgtest.a ${SRCS} ${TESTS}
	g++ -g -fstack-protector-all -isystem ${GTEST_DIR}/include -I src/ \
		-lgcov -pthread -fprofile-arcs -ftest-coverage ${SRCS} ${TESTS} \
		${GTEST_DIR}/src/gtest_main.cc libgtest_gcc.a \
		-o nok_tests

	# clang deprecated implicitly using a C file as C++, so we make it
	# explicit.
	# "clang: warning: treating 'c' input as 'c++' when in C++ mode, this behavior is deprecated"
	# Unfortunately, clang throws weird format warnings and errors when linking
	# with libgtest.a and specifying '-x c++', so we split the steps.
	clang++ -x c++ -g -isystem ${GTEST_DIR}/include -I src/ -pthread \
		-fstack-protector-all -c ${SRCS}
	clang++ -g -isystem ${GTEST_DIR}/include -I src/ -pthread \
		${SRCS_OBJ} ${TESTS} ${GTEST_DIR}/src/gtest_main.cc \
		libgtest_clang.a -o nok_tests_clang

nok:
	gcc -Wall -g -fstack-protector-all -I src/ -o nok_c main.c src/statemachine.c src/noknow.c
	g++ -Wall -g -fstack-protector-all -I src/ -o nok_cpp main.c src/statemachine.c src/noknow.c
	clang -Wall -g -fstack-protector-all -I src/ -o nok_c_clang main.c src/statemachine.c src/noknow.c
	clang++ -x c++ -Wall -g -fstack-protector-all -I src/ -o nok_cpp_clang main.c src/statemachine.c src/noknow.c

clean:
	rm *.o
