GTEST_DIR=ext/googletest/googletest
SRCS= src/statemachine.c src/noknow.c
TESTS= test/statemachine_test.cc test/noknow_test.cc
SRCS_OBJ= statemachine.o noknow.o


.PHONY: test clean

nok: src/statemachine.c src/noknow.c
	gcc -Wall -g -shared -Wl,-soname,libnoknow.so.0 -fstack-protector-all \
		-fPIC -I src/ -o libnoknow.so.0 src/statemachine.c src/noknow.c
	g++ -Wall -g -shared -Wl,-soname,libnoknow.so.0 -fstack-protector-all \
		-fPIC -I src/ -o libnoknow.so.0cpp src/statemachine.c \
		src/noknow.c
	clang -Wall -g -shared -Wl,-soname,libnoknow.so.0 \
		-fstack-protector-all -fPIC -I src/ -o libnoknow.so.0cc \
		src/statemachine.c src/noknow.c
	clang++ -x c++ -Wall -g -shared -Wl,-soname,libnoknow.so.0 \
		-fstack-protector-all -fPIC -I src/ -o libnoknow.so.0ccpp \
		src/statemachine.c src/noknow.c
	gcc -o nok_bin src/empty_main.c libnoknow.so.0


libgtest_gcc.a: ${GTEST_DIR}/src/gtest-all.cc
	g++ -g -isystem ${GTEST_DIR}/include -I${GTEST_DIR} -pthread -c \
		${GTEST_DIR}/src/gtest-all.cc -o gtest_all_gcc.o
	ar -rv libgtest_gcc.a gtest_all_gcc.o

libgtest_clang.a: ${GTEST_DIR}/src/gtest-all.cc
	clang++ -g -isystem ${GTEST_DIR}/include -I${GTEST_DIR} -pthread -c \
		${GTEST_DIR}/src/gtest-all.cc -o gtest_all_clang.o
	ar -rv libgtest_clang.a gtest_all_clang.o

test:  libgtest_gcc.a libgtest_clang.a ${SRCS} ${TESTS}
	g++ -Wall -g -fstack-protector-all -isystem ${GTEST_DIR}/include \
		-I src/ -lgcov -pthread -fprofile-arcs -ftest-coverage \
		${SRCS} ${TESTS} ${GTEST_DIR}/src/gtest_main.cc \
		libgtest_gcc.a -o nok_tests
	#
	# clang deprecated implicitly using a C file as C++, so we make it
	# explicit.
	# "clang: warning: treating 'c' input as 'c++' when in C++ mode, this behavior is deprecated"
	# Unfortunately, clang throws weird format warnings and errors when linking
	# with libgtest.a and specifying '-x c++', so we split the steps.
	#
	clang++ -Wall -x c++ -g -isystem ${GTEST_DIR}/include -I src/ \
		-pthread -fstack-protector-all -c ${SRCS}
	clang++ -Wall -g -isystem ${GTEST_DIR}/include -I src/ -pthread \
		${SRCS_OBJ} ${TESTS} ${GTEST_DIR}/src/gtest_main.cc \
		libgtest_clang.a -o nok_tests_clang
clean:
	rm -f *.o *.a *.gc* nok_* libnok_* libnoknow*
