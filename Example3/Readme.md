****************
Buffer overflows were discovered in Contiki-NG 4.4 through 4.5, in the SNMP agent. Functions parsing the OIDs in SNMP requests lack sufficient allocated target-buffer capacity verification when writing parsed OID values. The function snmp_oid_decode_oid() may overwrite memory areas beyond the provided target buffer, when called from snmp_message_decode() upon an SNMP request reception. Because the content of the write operations is externally provided in the SNMP requests, it enables a remote overwrite of an IoT device's memory regions beyond the allocated buffer. This overflow may allow remote overwrite of stack and statically allocated variables memory regions by sending a crafted SNMP request.

https://www.cvedetails.com/cve/CVE-2020-14936/


****************** References 
https://github.com/contiki-ng/contiki-ng/issues/1351
https://www.cvedetails.com/cve/CVE-2020-14936/
https://github.com/contiki-ng/contiki-ng/blob/release/v4.5/os/net/app-layer/snmp/snmp-oid.c
https://github.com/mjurczak/contiki-ng/tree/bugfix/snmp-engine

