libs_for_gcc = -lgnu
normal_libs =
CC = gcc
CFLAGS = -m32 -static

#TEST #1 PARAMETERS
# make replace_size=176 num_entries=1 num_counters=1 n_offset=176 t_offset=144 m_size=32 m_revision=0 t_size=32 t_revision=1 test1
#Arg 1 - Defualt replace_size (176) = (sizeof(data.entry) + sizeof(data.match) + sizeof(data.target))
ifdef replace_size
	THE_REPLACE_SIZE = $(replace_size)
else
	THE_REPLACE_SIZE = 176
endif
#Arg2 - setting replace.number_entries
ifdef num_entries
	NUMBER_ENTRIES = $(num_entries)
else
	NUMBER_ENTRIES = 1
endif
#Arg3 - setting replace.number_counters
ifdef num_counters
	NUMBER_COUNTERS = $(num_counters)
else
	NUMBER_COUNTERS = 1
endif
#Arg4 - setting entry.next_offset
#Defualt next_offset (176) = (sizeof(data.entry) + sizeof(data.match) + sizeof(data.target))
ifdef n_offset
	NEXT_OFFSET = $(n_offset)
else
	NEXT_OFFSET = 176
endif
#Arg5 - setting entry.target_offset
#Defualt target_offset (144) = (sizeof(data.entry) + sizeof(data.match))
ifdef t_offset
	TARGET_OFFSET = $(t_offset)
else
	TARGET_OFFSET = 144
endif
#Arg6 - setting match.size
ifdef m_size
	MATCH_SIZE = $(m_size)
else
	MATCH_SIZE = 32
endif
#Arg7 - setting match.revision
ifdef m_revision
	MATCH_REVISION = $(m_revision)
else
	MATCH_REVISION = 0
endif
#Arg8 - setting target.size
ifdef t_size
	TARGET_SIZE = $(t_size)
else
	TARGET_SIZE = 32
endif
#Arg9 - setting target.size
ifdef t_revision
	TARGET_REVISION = $(t_revision)
else
	TARGET_REVISION = 1
endif


#TEST #2 PARAMETERS
# make rm_replace=1 rm_entry=1 rm_match=1 rm_target=1 test2
#Arg1 - remove replace
ifdef rm_replace
	REMOVE_REPLACE = 1
else
	REMOVE_REPLACE = 0
endif
#Arg2 - remove entry
ifdef rm_entry
	REMOVE_ENTRY = 1
else
	REMOVE_ENTRY = 0
endif
#Arg3 - remove match
ifdef rm_match
	REMOVE_MATCH = 1
else
	REMOVE_MATCH = 0
endif
#Arg4 - remove target
ifdef rm_target
	REMOVE_TARGET = 1
else
	REMOVE_TARGET = 0
endif

####Test 1 -- all the input user can provide
test1: test1.o
	$(CC) $(CFLAGS) -o test1.o test1_new.c
	./test1.o $(THE_REPLACE_SIZE) $(NUMBER_ENTRIES) $(NUMBER_COUNTERS) $(NEXT_OFFSET) $(TARGET_OFFSET) $(MATCH_SIZE) $(MATCH_REVISION) $(TARGET_SIZE) $(TARGET_REVISION)

run_test1:
	./test1.o $(THE_REPLACE_SIZE) $(NUMBER_ENTRIES) $(NUMBER_COUNTERS) $(NEXT_OFFSET) $(TARGET_OFFSET) $(MATCH_SIZE) $(MATCH_REVISION) $(TARGET_SIZE) $(TARGET_REVISION)

####Test 2 -- remove replace, entry, match, or target
test2: test2.o
	$(CC) $(CFLAGS) -o test2.o test2_new.c
	./test2.o $(REMOVE_REPLACE) $(REMOVE_ENTRY) $(REMOVE_MATCH) $(REMOVE_TARGET)

run_test2:
	./test2.o $(REMOVE_REPLACE) $(REMOVE_ENTRY) $(REMOVE_MATCH) $(REMOVE_TARGET)


clean:
	rm -f core *.o test1.o test2.o
