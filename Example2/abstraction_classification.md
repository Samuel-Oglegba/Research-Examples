### =============================================================================== ###
### Note: 1,...,N ==> .n.
### 1,...,N-1 ==> .n-1.

### Array: 
**** Operations
 add(), insert(index,valueToAdd)
 update(index,newValue)
 delete(index)
**** States
empty : array { top }
working : array { top .n-1.}
full : array { top .n.}
error : { null }

### LinkedList (sequencial access)
**** Operations
 add(itemToAdd)
 set(index,newValue)
 remove()
**** States
empty : linkedList { head }
working : linkedList { head .n-1.}
full : linkedList { head .n. }
error : { null }

### Program =============================================================================== ###
### Socket level abstraction
### Compound Type (Message)
### Pipe
== Program
      == Array[size1][size2] ( top, elem … ) {
      top -> ss,
      elem -> Socket ( id ) {
                  id -> s
      },
      size1 -> NUM_SOCKETS,
      size2 -> 2
      }

      *** And here define the operations/states of data abstractions ***

      == Array[size1][size2] ( top, elem … ) {
      top -> pipefd,
      elem -> Pipe ( id ) {
                  id -> fd
      },
      size1 -> NUM_PIPEFDS,
      size2 -> 2
      }

      == Array[size1] ( top, elem … ) {
      top -> msqid,
      elem -> Compound (MessageQueueID) ( id ) {
                  id -> { fake_idx, real_idx }
      },
      size1 -> NUM_MSQIDS
      }

      == Array[size1] ( top, elem … ) {
      top -> secondary_buf,
      elem -> Compound(DoublyLinkedList Message) ( id ) {
                  id -> [data7] msg
      },
      size1 -> SECONDARY_SIZE - SKB_SHARED_INFO_SIZE
      }

      == DoublyLinkedList (head, elem, elem.next, elem.prev) {
            head -> msg
      elem -> LinkedList ( head, elem elem.next ) {
            head -> msg***
            elem -> Compound<T> {
                  T -> struct msg_msg
            },
            elem.next -> struct msg_msg::next
      },
      elem.next-> struct msg_msg::m_list_next,
      elem.prev-> struct msg_msg::m_list_prev,
      }
      
      == LinkedList ( head, elem elem.next ) {
      head -> ops,
      elem -> Compound<T>{
                  T -> struct pipe_buf_operations
            },
            elem.next -> ??   
      }
      
      == LinkedList ( head, elem elem.next ) {
      head -> buf,
      elem -> Compound<T>{
                  T -> struct pipe_buffer
            },
            elem.next -> ??   
      }

### Compound =============================================================================== ###
 == Compound {
      replace -> Compound <T> {
            T -> struct ipt_replace
      },
      entry -> Compound <T> {
            T -> struct ipt_entry
      },

}




