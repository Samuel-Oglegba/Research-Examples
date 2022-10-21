#build CPP abstraction file
g++ -m32 -static -o cpp_abstraction xt_table_info.cpp
	./cpp_abstraction

#build C file
gcc -m32 -static -o c_file xt_table_info.c
	./c_file

gcc -m32 -static -o c_file test_case1.c
	./c_file

gcc -m32 -static -o c_file test_case2.c
	./c_file