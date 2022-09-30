========= Function compat_do_replace() =====================
      ========== Input Parameters =====================
      [data1.0] struct net *net ==> DoubleLikedList {empty, non-empty, full, error}                          
      
      [object1.0] User

      ========== Local Parameters =====================
      [data2.0] struct compat_ipt_replace tmp ==> {empty, non-empty, full, error}
            name = Array[32]                        
            hook_entry = Array[5]                        
            underflow = Array[5]                        


      ========== Heap Variables (Output Parameters) =====================
      [data3.0] struct xt_table_info *newinfo ==> Stack {empty, non-empty, full, error}                         
            
            [position3.1] void *loc_cpu_entry ==> maps to [data3.0]->entries, which are the rows of the routing table
            [position3.2] struct ipt_entry *iter ==> maps to the starting position of the routing table for iteration through the table                    
      
      ToDo: data state missing - define the state before and the state after each transition
      ToDo: Edges should be labled with statements that causes modification to the data structures. Statements may include: assignments, function calls, etc
      
      ========== Transition Graph =====================
      // The copy_from_user call verifies the access to the memory and works similar to memset function      
      
      [flow] [data2.0] empty : Stack {top} * (object1.0) ——copy_from_user—> [data2.1] full : {top,...,N} //N = sizeof(data2.0)         
                  name = Array {top,...,???}
      [flow] [data2.1] full : Stack {top,...,N} * '0' ——assignment @line 51—> [data2.2] full : {top,...,N}
                  name = Array {top,...,0}
      
      // The function xt_alloc_table_info dynamically allocate memory using kmalloc or vmalloc
      [flow][data3.0] empty : Stack {top}  ——set-memory-size—> [data3.1] non-empty : Stack {top,...,N} // N = (sizeof(data3.0) + ([data2.2].size))
      
      // The function xt_alloc_table_info sets the value to 0 using meset       
      [flow][data3.1] non-empty : Stack {top,...,N} * '0' ——memset—> [data3.2] full : Stack {top,...,0} 
            
            [flow] position3.1 * object1.0 ——copy_from_user()—> [position3.1.1]
            [flow] position3.2 * position3.1.1 ——xt_entry_foreach()—> [position3.2]
            [flow] position3.2 * data1.0 ——cleanup_entry()—> [position3.2]

      [flow] data3.1 * (data1.0, position3.1.1, & conts) ——translate_compat_table()—> [data3.2] non-empty : Stack {top,...}

      [flow] data3.2 * (data1.0 & consts) ——__do_replace()—> [data3.3] non-empty : Stack {top,...}


========= Function translate_compat_table() =====================
      ========== Input Parameters =====================
      [data4.0] struct net *net
                        {non-empty, full, error} ==> DoubleLikedList 
      
      ========== Heap Variables (Input & Output Parameters) =====================
      [data5.0] struct xt_table_info **pinfo 
                        {non-empty, full, error} ==> Stack

            [position5.1] void **pentry0 

      ========== Local Parameters =====================
      [data6.0] struct xt_table_info *newinfo 
                        {empty, non-empty, full, error} ==> Stack 

      [alias1.0] struct xt_table_info *info {} ==> [data5.0]
      [alias2.0] void *pos {} ==> [alias4.0]
      [alias3.0] void *entry0{} ==> [position5.1]
            [position5.2] struct compat_ipt_entry *iter0 {} ==> LinkedList
            
      [alias4.0] void *entry1{} ==> [data6.0]->entries 
            [position6.1] struct ipt_entry *iter1 {} ==> LinkedList    
     
      ========== Transition Graph =====================
      [flow] data6.0 non-empty : Stack {top,...} * const —for...—> [data6.1] non-empty : Stack {top,...}
      [flow] data6.1 non-empty : Stack {top,...} * data8.0 * const —check_compat_entry_size_and_hooks—> [data6.2] non-empty : Stack {top,...}


========= Function check_compat_entry_size_and_hooks() =====================
      ========== Input Parameters =====================
      [data7.0] struct compat_ipt_entry *e {} ==> LinkedList 
            [position7.1] struct xt_entry_match *ematch {} ==> lLinkedList, ocal parameter

      ========== Heap Variables (Input & Output Parameters) =====================
      [data8.0] struct xt_table_info *newinfo {} ==> Stack 

      ========== Local Parameters =====================
      [data9.0] struct xt_entry_target *t {} ==> 
      [data10.0] struct xt_target *target {} ==> 
      
      ========== Transition Graph =====================


========= Function compat_copy_entry_from_user() =====================
      ========== Input Parameters =====================
      [data11.0] struct compat_ipt_entry *e {} ==> LinkedList 
            [position11.1] struct xt_entry_match *ematch {} ==> LinkedList, local parameter
      
      [data12.0] void **dstptr {} ==> Output Parameter (table entries)

      [data13.0] struct xt_table_info *newinfo {} ==> Stack 

      ========== Local Parameters =====================
      [data14.0] struct xt_entry_target *t {} ==> 

      [alias5.0] struct xt_target *target {} ==> [data14.0]->u.kernel.target
      
      [alias6.0] struct ipt_entry *de {} ==> [data12.0], LinkedList

      ========== Transition Graph =====================
      

========= Function xt_compat_target_from_user() =====================
      ========== Input Parameters =====================
      [data15.0] void **dstptr {} ==> Output Parameter (table entries pointer)
      [alias7.0] struct xt_entry_target *t {} ==> [data15.0], Output Parameter 

      ========== Local Parameters =====================
      [alias8.0] struct xt_target *target {} ==> [alias7.0]->u.kernel.target -- LinkedList, local parameter
      [alias8.0] struct compat_xt_entry_target *ct {} ==> [alias7.0]->u.kernel.target -- LinkedList, local parameter

      ========== Transition Graph  =====================