### ======== Original Structure in the Software ===================###
struct xt_entry_target {
	union {
		struct {
			__u16 target_size;

			/* Used by userspace */
			char name[XT_EXTENSION_MAXNAMELEN];
			__u8 revision;
		} user;
		struct {
			__u16 target_size;

			/* Used inside the kernel */
			struct xt_target *target;
		} kernel;

		/* Total length */
		__u16 target_size;
	} u;

	unsigned char data[0];
};

### ============ Abstraction Classification =====================
### /* for additional comments */
### Target is divided into standard and custom (user-defined) targets
### Structures need to be converted from user to kernel as well as 32bit to 64bit in order to be processed by the native functions.

Target<T>(){
      T -> struct xt_entry_target<E>(label, values, states,relationship){
		E( U, D){
			U -> Union(User,Kernel,target_size){	
                        User<t> -> struct(){
                              t(size, name, revision){
                                    size ->  __u16 target_size,
                                    name -> Array[XT_EXTENSION_MAXNAMELEN](top, elem…){...},
                                    revision -> __u8 revision,
                              },
                              label -> {"The elements in the User struct are defined in the userspace"},

                              values -> {name{empty, TCPMSS, TTL or NFQUEUE}, revision{1}, target_size{?}}, /* the user sets the values of User.target_size=sizeof(data.target), User.name ="NFQUEUE"  and User.revision=1 in the exploit code */

                              states -> {empty, working, full}, /* The state transitioned from empty (user declaration) to working & full state (user assignment),the error state is not reached because the name determines the size and it doesn't exceed the allocated size */

                              relationship -> {UsedTogether} /* - If name is empty, it is the standard target, else  Non-empty names are user-defined targets */
                        },
                        Kernel<t> -> struct(){
                              t(size, target){
                                    size -> __u16 target_size,
                                    target -> struct xt_target *target,  /* A target represents the action to be executed after the **rule matching** */
                              },
                                    label -> {"The elements in the Kernel struct are defined by the kernel, the user can indirectly set the size"},

                                    values -> { target{NULL, NF_ACCEPT,NF_DROP}, target_size{?}},/* target_sized is defined by the size of the name the user sets */

                                    states -> {null, working}, /* the state transitions from NULL to the working based on **matching result**. The error state of exceeding momory is not reached because the size of name (largest data) is used */

                                    relationship -> {UsedTogether } /* -  A target represents the action to be executed after the rule matching is successful, such as dropping the data packet NF_DROP, letting NF_ACCEPT, etc. when standard target is NULL, it means the standard target is executed */
                        },
                        target_size -> __u16,
                  },
                        label -> {"This the Union of User, Kernel, and target_size elements"},

                        values -> {NULL, User, Kernel, target_size}, /* the possible values of NULL (not initialized), User, Kernal and target_size */

                        states -> {null, working, full}, /* null state when not initialized, working state (initialized), full state when user sets the name  */

                        relationship -> {
                              GroupedTogether,
                              sharedMemory /*- they share same mem pos because of union U */,
                              target_size /*- the size of memory used for U */,                 
                              accessing /*- one element at a time (User, kernel, or target_size) */,
                        }	
                  },
                  D -> Array[size1] (top, elem…){
                        top -> data,
                        elem -> unsigned char
                              size1 -> ?? /* defined in the newinfo = xt_alloc_table_info(size) function -- **further study required** */
                  },
                        label -> {"This is the data that goes into the vulnerable state when strcpy is called"},
                        values -> {empty,"0"},
                        states -> {empty, working, full, error}, /* it goes to the error state when offset target->targetsize that is not accounted for during the allocation (newinfo = xt_alloc_table_info(size)) is used */
                        relationship -> {UsedTogether} /* - A case when data is in the **match data structrue**, this means that the target executes the function data  */
            },

            label -> {"Structures need to be converted from user to kernel as well as 32bit to 64bit in order to be processed by the native functions"},
            values -> {NULL,},
            states -> {empty, working, full, error},
            relationship -> {UsedTogether} /* -  */   
      } 
