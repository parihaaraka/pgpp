all:
	g++ -std=c++11 -I/usr/include/postgresql -fPIC \
	main.cpp \
	../pg_params.cpp \
	../pg_result.cpp \
	../pg_connection.cpp \
	../pg_query.cpp -o pgpp_example -L. -lpq -lev
