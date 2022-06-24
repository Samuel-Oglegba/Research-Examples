### Runing the exploit code
gcc -m32 -static -o exploit exploit.c
     ./exploit

### Running The SingleFile that contains the exploit and vulnerable software
gcc -m32 -static -o signlefile single_file_edited.c
   ./signlefile


############# Description and References ########################
######### Examples 2 - Linux Kernel 2.6.19 < 5.9 - 'Netfilter Local Privilege Escalation ########
A heap out-of-bounds write affecting Linux since v2.6.19-rc1 was discovered in net/netfilter/x_tables.c. This allows an attacker to gain privileges or cause a DoS (via heap memory corruption) through user name space.

When IPT_SO_SET_REPLACE or IP6T_SO_SET_REPLACE is called in compat mode, kernel structures need to be converted from 32bit to 64bit. Unfortunately, the allocation size for the conversion is not properly calculated, leading to a few bytes of zero written out-of-bounds in xt_compat_target_from_user(). By pushing the structure size to the boundary, adjacent objects on the slab can be corrupted.

https://www.exploit-db.com/exploits/50135
https://www.cvedetails.com/cve-details.php?t=1&cve_id=CVE-2021-22555

#### the exploit ####
https://github.com/google/security-research/security/advisories/GHSA-xxx5-8mvq-3528

