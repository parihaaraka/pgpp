all:
	g++ -std=c++17 -I/usr/include/postgresql -I.. -I../include -fPIC \
	main.cpp \
	../src/params.cpp \
	../src/result.cpp \
	../src/connection.cpp \
	../src/query.cpp -o pgpp_example -L. -lpq -lev
