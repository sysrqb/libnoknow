GTEST_DIR=ext/googletest/googletest
SRCS= src/statemachine.c src/noknow.c
TESTS= test/statemachine_test.cc test/noknow_test.cc
SRCS_OBJ= statemachine.o noknow.o


.PHONY: test clean nok gxx clang clangxx

nok: ${SRCS} libnoknow.a libnoknow.so
	gcc -o nok_bin src/empty_main.c libnoknow.so.0

libnoknow.a: ${SRCS}
	gcc -Wall -g -fPIC -fstack-protector-all -isystem -L. -Iinclude -pthread -c ${SRCS}
	ar -rv libnoknow.a ${SRCS_OBJ}

libnoknow.so: ${SRCS}
	gcc -Wall -g -shared -Wl,-soname,libnoknow.so.0 \
		-fPIC -I. -Iinclude -o libnoknow.so.0 ${SRCS}

gxx: libnoknow_gxx.a libnoknow_gxx.so

clang: libnoknow_clang.a libnoknow_clang.so

clangxx: libnoknow_clangxx.a libnoknow_clangxx.so

libnoknow_gxx.a: ${SRCS}
	g++ -Wall -g -isystem -L. -I. -Iinclude -pthread -c ${SRCS}
	ar -rv libnoknow_gxx.a ${SRCS_OBJ}

libnoknow_gxx.so: ${SRCS}
	gcc -Wall -g -shared -Wl,-soname,libnoknow.so.0 \
		-fPIC -I. -Iinclude -o libnoknow_gxx.so.0 ${SRCS}

libnoknow_clang.a: ${SRCS}
	clang -Wall -g -isystem -L. -I. -Iinclude -pthread -c ${SRCS}
	ar -rv libnoknow_clang.a ${SRCS_OBJ}

libnoknow_clang.so: ${SRCS}
	gcc -Wall -g -shared -Wl,-soname,libnoknow.so.0 \
		-fPIC -I. -Iinclude -o libnoknow_clang.so.0 ${SRCS}

libnoknow_clangxx.a: ${SRCS}
	clang++ -Wall -x c++ -g -isystem -L. -I. -Iinclude -pthread -c \
		${SRCS}
	ar -rv libnoknow_clangxx.a ${SRCS_OBJ}

libnoknow_clangxx.so: ${SRCS}
	gcc -Wall -g -shared -Wl,-soname,libnoknow.so.0 \
		-fPIC -I. -Iinclude -o libnoknow_clangxx.so.0 ${SRCS}

libgtest.a: ${GTEST_DIR}/src/gtest-all.cc
	g++ -g -isystem ${GTEST_DIR}/include -I${GTEST_DIR} -pthread -c \
		${GTEST_DIR}/src/gtest-all.cc -o gtest_all.o
	ar -rv libgtest.a gtest_all.o

libgtest_clang.a: ${GTEST_DIR}/src/gtest-all.cc
	clang++ -g -isystem ${GTEST_DIR}/include -I${GTEST_DIR} -pthread -c \
		${GTEST_DIR}/src/gtest-all.cc -o gtest_all_clang.o
	ar -rv libgtest_clang.a gtest_all_clang.o

test:  libgtest.a libgtest_clang.a ${SRCS} ${TESTS} nok clang clangxx
	g++ -Wall -fstack-protector-all -g -isystem ${GTEST_DIR}/include \
		-L. -I. -Iinclude -lgcov -pthread -fprofile-arcs -ftest-coverage \
		${TESTS} ${GTEST_DIR}/src/gtest_main.cc \
		libgtest.a -lnoknow -o nok_tests
	clang++ -Wall -fstack-protector-all -g -isystem ${GTEST_DIR}/include \
		-L. -I. -Iinclude -lgcov -pthread -fprofile-arcs -ftest-coverage \
		${TESTS} ${GTEST_DIR}/src/gtest_main.cc \
		libgtest_clang.a -lnoknow_clang -o nok_tests_clang
clean:
	rm -f *.o *.a *.gc* nok_* libnok_* libnoknow* *.gc*
