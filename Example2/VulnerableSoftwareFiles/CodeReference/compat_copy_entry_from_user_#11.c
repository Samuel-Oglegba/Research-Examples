
static int
compat_copy_entry_from_user(struct compat_arpt_entry *e, void **dstptr,
			    unsigned int *size, const char *name,
			    struct xt_table_info *newinfo, unsigned char *base)
{
	struct xt_entry_target *t;
	struct xt_target *target;
	struct arpt_entry *de;
	unsigned int origsize;
	int ret, h;

	ret = 0;
	origsize = *size;
	de = (struct arpt_entry *)*dstptr;
	memcpy(de, e, sizeof(struct arpt_entry));
	memcpy(&de->counters, &e->counters, sizeof(e->counters));

	*dstptr += sizeof(struct arpt_entry);
	*size += sizeof(struct arpt_entry) - sizeof(struct compat_arpt_entry);

	de->target_offset = e->target_offset - (origsize - *size);
	t = compat_arpt_get_target(e);
	target = t->u.kernel.target;
	xt_compat_target_from_user(t, dstptr, size);

	de->next_offset = e->next_offset - (origsize - *size);
	for (h = 0; h < NF_ARP_NUMHOOKS; h++) {
		if ((unsigned char *)de - base < newinfo->hook_entry[h])
			newinfo->hook_entry[h] -= origsize - *size;
		if ((unsigned char *)de - base < newinfo->underflow[h])
			newinfo->underflow[h] -= origsize - *size;
	}
	return ret;
}