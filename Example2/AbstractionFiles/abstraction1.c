//=== Data Structures =====
struct socket;

/**
 * @brief {
 * modified =>{}, 
 * read =>{socket}, 
 * used =>{"socket:: used to convert data `socket` to data `net` via  sock_net operation"}
 * }
 * 
 * @param fd 
 * @param level 
 * @param optname 
 * @param optval 
 * @param optlen 
 * @return int 
 */
/** Mock setsockopt call **/
int setsockopt(int fd, int level, int optname, const void * optval, socklen_t optlen)
{
	int ret, err, fput_needed;
	struct socket *sock;

	if (optlen < 0)
		return -EINVAL;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (sock != NULL) {
		ret = compat_do_replace(sock_net(sock), optval, optlen);
	}
	return ret;
}
/** End Mock socket setup Call **/
