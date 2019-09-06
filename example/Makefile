all:
	g++ -std=c++11 -I/usr/include/postgresql -I../include -fPIC \
	main.cpp \
	../src/params.cpp \
	../src/result.cpp \
	../src/connection.cpp \
	../src/query.cpp -o pgpp_example -L. -lpq -lev
