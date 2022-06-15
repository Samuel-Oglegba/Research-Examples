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
      T -> struct xt_entry_target<E>(usage, label, values, states,relationship){
		E( U, D){
			U -> Union(User,Kernel,target_size){	
                        User<t> -> struct(){
                              t(size, name, revision){
                                    size ->  __u16 target_size,
                                    name -> Array[XT_EXTENSION_MAXNAMELEN](top, elem…){...},
                                    revision -> __u8 revision,
                              },
                              usage -> {
                                    0 -> 
                                    1 -> 
                              },
                        Kernel<t> -> struct(){
                              t(size, target){
                                    size -> __u16 target_size,
                                    target<t>() {
                                      t -> struct xt_target *target,
                                      usage -> {
                                          0 -> struct xt_target *target = t->u.kernel.target,
                                          1 -> 
                                      }
                                    }                                         
                              },                                   
                        },
                        target_size -> __u16,
                  },
                        usage -> {
                              }	
                  },
                  D -> Array[size1] (top, elem…){
                        top -> data,
                        elem -> unsigned char
                              size1 -> ?? /* defined in the newinfo = xt_alloc_table_info(size) function -- **further study required** */
                  },
                        used -> {
                              0 -> ??,
                              }
            },

            usage -> {
                  0 -> struct compat_xt_entry_target *ct = (struct compat_xt_entry_target *)t,
                  
                  } 
      } 
