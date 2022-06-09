### The vulnerable function on the Linux Kernel 2.6.19 < 5.9

###### ================== Description ====================
### When IPT_SO_SET_REPLACE or IP6T_SO_SET_REPLACE is passed as an argument in compat mode, kernel structures need to be converted from 32bit to 64bit. Unfortunately, the allocation size for the conversion is not properly calculated, leading to a few bytes of zero written out-of-bounds in xt_compat_target_from_user()

### target->targetsize is not taken into account for the allocation size - only the difference between the alignments. The check carried out is the pad = XT_ALIGN(target->targetsize) - target->targetsize

#### ======= xt_compat_target_from_user(struct xt_entry_target *t, void **dstptr, unsigned int *size) function

[data1] const struct xt_target *target; 
[data2] compat_xt_entry_target *ct; 
[data3] int pad; 
[data4] int off; 
[data5] u_int16_t tsize; 
###### ========================== function inputs ==========
[data6] struct xt_entry_target *t; 
[data7] void **dstptr; 
[data8] unsigned int *size; 
### ============================= end function inputs =============
[data8] char name[sizeof(t->u.user.name)]; 
===================================================================

[flow] data6.0 --- memcpy(data6.0, data2.0,const) ---> data6.1
#### === Todo:: how to represent the if condition on [data6.1]???
[flow] data6.1 --- [data1]->compat_from_user(data6.1, data2.0) ---> data6.2 
[flow] data6.1 --- memcpy(data6.1, data2.0,const)---> data6.2 


[flow] data6.2 --- memset(data6.2 + data1.0, "0",data3.0)---> data6.3  -------------(Vulnerable State)

[flow] data8.0 --- strlcpy(data6.1, data1.0,const)---> data8.1 
[flow] data1.0 --- module_put(data1.0)---> data1.0
[flow] data1.0 --- strncpy(data1.0, data8.1,const)---> data1.1 

== Program
      == Compound<T>(var){
            T -> struct xt_target,
            var -> *target
         } Compound_Target
          
     

      == LinkedList ( head, elem elem.next ) {
            head -> ct,
            elem -> Compound<T>{
                        T -> compat_xt_entry_target *ct
                  },
            elem.next -> ??   
      }


      == Array[size1][size2] ( top, elem … ) {
            top -> ss,
            elem -> Socket ( id ) {
                        id -> s
            },
            size1 -> NUM_SOCKETS,
            size2 -> 2
      }