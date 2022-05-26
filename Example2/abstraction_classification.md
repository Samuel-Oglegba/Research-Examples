### Note: 1,...,N ==> .n.
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


**** Transition:


### LinkedList (sequencial access)
**** Operations
 add(itemToAdd)
 remove()

**** States
empty : linkedList { root }
working : linkedList { root .n-1.}
full : linkedList { root .n. }
error : { null }



