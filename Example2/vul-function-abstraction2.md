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

Target<T>(){
      T -> struct xt_entry_target<E>(label, values, states,relationship){
		E( U, D){
			U -> Union(User,Kernel,target_size){	
                        User<t> -> struct(head, elem...,label,values,states,relationship){                              
                              t(size, name, revision){
                                    size ->  __u16 target_size,
                                    name -> Array[size1](top, elem…){...},
                                    revision -> __u8 revision,
                              },
                              head -> ??,
                              elem-> ??,
                              label -> {"Focus on **User Element** - target_size is determined by the name from userspace"},
                              values -> {name{empty, TCPMSS, TTL or NFQUEUE},revision{1,...},...},
                              states -> {empty, working, full, error},
                              relationship -> {UsedTogether} /* - target_size is determined by the name from userspace. If name is empty, it is the standard target, else  Non-empty names are user-defined targets */
                        },
                        Kernel<t> -> struct(head, elem...,label,values,states,relationship){
                              t(size, target){
                                    size -> __u16 target_size,
                                    target -> struct xt_target *target,
                              },
                              head -> ??,
                              elem-> ??,
                              label -> {"Focus on **Kernel Element** - A target represents the action to be executed after the rule matching"},
                              values -> {target{NULL, NF_ACCEPT,NF_DROP,…},target_size{??}},
                              states -> {empty, working, full, error},
                              relationship -> {UsedTogether } /* -  A target represents the action to be executed after the rule matching is successful, such as dropping the data packet NF_DROP, letting NF_ACCEPT, etc. when standard target is NULL, it means the standard target is executed */
                        },
                        target_size -> __u16,
                  },
                        label -> {"Focus on **Union 'U' Element** - Holds the "},
                        values -> {NULL, User, Kernel, target_size},
                        states -> {empty, working, full, error},
                        relationship -> {
                              GroupedTogether,
                              sharedMemory /*- they share same mem pos because of union U */,
                              target_size /*- the size of memory used for U */,                 
                              accessing /*- one element at a time (User, kernel,...)*/,
                        }	
                  },
                  D -> Array[size1] (top, elem…,label,values,states,relationship){
                        top -> data,
                        elem -> unsigned char
                        size1 -> ??,
                        label -> {"Focus on **'D' Element**"},
                        values -> {empty,},
                        states -> {empty, working, full, error},
                        relationship -> {UsedTogether} /* - A case when data is in the **match data structrue**, this means that the target executes the function data or it is called a parameter */
                  },
                       
            },

            label -> {"Focus on **'E' Element**"},
            values -> {NULL,},
            states -> {empty, working, full, error},
            relationship -> {UsedTogether} /* -  */   
      } 
