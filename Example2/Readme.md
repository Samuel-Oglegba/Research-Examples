### How to Download and Use Example 2
1. To download the repo, run the following command.

   git clone https://github.com/Samuel-Oglegba/Research-Examples.git

2. cd Research-Examples/Example2

3. To run the vulnerable functions and exploits

   gcc -m32 -static -o singlefile single_file_edited.c
    ./singlefile

4. if on a linux OS, runing the exploit alone:

    gcc -m32 -static -o exploit exploit.c
     ./exploit


### Description and References 
######### Examples 2 - Linux Kernel 2.6.19 < 5.9 - 'Netfilter Local Privilege Escalation ########
A heap out-of-bounds write affecting Linux since v2.6.19-rc1 was discovered in net/netfilter/x_tables.c. This allows an attacker to gain privileges or cause a DoS (via heap memory corruption) through user name space.

When IPT_SO_SET_REPLACE or IP6T_SO_SET_REPLACE is invoked in compat mode, kernel structures need to be converted from 32bit to 64bit. Unfortunately, the allocation size for the conversion is not properly calculated, leading to a few bytes of zero written out-of-bounds in xt_compat_target_from_user(). By pushing the structure size to the boundary, adjacent objects on the slab can be corrupted.

https://www.exploit-db.com/exploits/50135
https://www.cvedetails.com/cve-details.php?t=1&cve_id=CVE-2021-22555

#### the exploit ####
https://github.com/google/security-research/security/advisories/GHSA-xxx5-8mvq-3528

#### explanations of netfilter ###
https://programmer.ink/think/netfilter-analysis-2-table-initialization.html


