### Array: 

**** Operations
 add(), insert(index,valueToAdd)
 update(index,newValue)
 delete(index)

**** States
empty : array { top }
working : array { top 1,...N-1}
full : array { top 1,...,N }
error : { null }

**** Data Structures:
[data3] int ss[NUM_SOCKETS][2];
[data5] int msqid[NUM_MSQIDS];
[data6] char secondary_buf[SECONDARY_SIZE - SKB_SHARED_INFO_SIZE];

**** Transition:


### LinkedList (sequencial access)
**** Operations
 add(itemToAdd)
 remove()

**** States
empty : linkedList { top }
working : linkedList { top root,...N-1}
full : linkedList { top root,...,N }
error : { null }

**** Data Structures:
[data6] char secondary_buf[SECONDARY_SIZE - SKB_SHARED_INFO_SIZE]; —--- build_msg_msg() threats this data structure as a list
[data7] struct msg_msg *msg;
[data9] struct pipe_buffer *buf;


