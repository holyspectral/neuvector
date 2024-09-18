#pragma once

#define EPERM 1
#define ENOMEM 12

#define SIGKILL 9

#define MAX_BUF_SIZE 256
#define MAX_BUF_SIZE_MASK (MAX_BUF_SIZE - 1)
#define MAX_ENTRIES 64

#define MAX_PATH_DEPTH 4

#define PROC_FORK_EVENT_TYPE 0
#define PROC_EXEC_EVENT_TYPE 1
#define PROC_EXIT_EVENT_TYPE 2
#define PROC_UID_EVENT_TYPE 3
#define PROC_GID_EVENT_TYPE 4

/*
// This function checks prefix using BPF_MAP_TYPE_LPM_TRIE
static inline __attribute__((always_inline)) int MatchPrefix(char cid[64], const char *str, uint len)
{
    int zero = 0;
    void *lpm = bpf_map_lookup_elem(&filename_maps, cid);
    if (!lpm)
    {
        bpf_printk("no policy is available for this container: %.64s", cid);
        return 0;
    }

    // Get per-cpu array
    struct string_lpm_trie *buf = (struct string_lpm_trie *)bpf_map_lookup_elem(&filename_heap, &zero);
    if (!buf)
        return 0;

    buf->prefixlen = len * 8; // bits
    copy(buf->data, len, (__u8 *)str);

    bpf_printk("[Trace] filename: %s", buf->data);

    __u8 *pass = bpf_map_lookup_elem(lpm, buf);

    if (pass)
    {
        bpf_printk("prefix is found: %s", buf->data);
        return 1;
    }
    else
    {
        bpf_printk("prefix is not found: %s", buf->data);
        return 0;
    }
}
*/

static inline __attribute__((always_inline)) int
write_reverse(char *buf, int off, int len, const unsigned char *data, int datalen)
{
    u32 index = (off - datalen) & ((len >> 1) - 1);
    if (index > len)
    {
        return 0;
    }
    bpf_probe_read_kernel(&(buf[index]), datalen, data);
    return index;
}

static inline __attribute__((always_inline)) void
copy_reverse(__u8 *dest, uint len, __u8 *src)
{
    uint i;

    len &= MAX_BUF_SIZE_MASK;

    for (i = 0; i < (MAX_BUF_SIZE - 1); i++)
    {
        dest[i & MAX_BUF_SIZE_MASK] = src[(len - 1 - i) & MAX_BUF_SIZE_MASK];
        if (len == (i + 1))
            return;
    }
}

static inline __attribute__((always_inline)) void
copy(__u8 *dest, uint len, __u8 *src)
{
    uint i;

    len &= MAX_BUF_SIZE_MASK;

    for (i = 0; i < MAX_BUF_SIZE; i++)
    {
        dest[i] = src[i];
    }
}

static inline __attribute__((always_inline)) int
__d_path(const struct dentry *dentry, char *buf, int datalen)
{
    int size;
    u32 off = ((datalen >> 1) - 1);
    buf[off & ((datalen >> 1) - 1)] = '\0';

#pragma unroll
    for (int i = 0; i < MAX_PATH_DEPTH; i++)
    {
        const unsigned char slash = '/';
        struct dentry *parent = BPF_CORE_READ(dentry, d_parent);

        if (dentry == NULL || dentry == parent)
        {
            break;
        }
        const unsigned char *str = BPF_CORE_READ(dentry, d_name.name);
        u32 len = BPF_CORE_READ(dentry, d_name.len) & ((datalen >> 1) - 1);

        off = write_reverse(buf, off, datalen, str, len);
        if (off > datalen)
        {
            // Too long
            break;
        }

        off = write_reverse(buf, off, datalen, &slash, 1);
        if (off > datalen)
        {
            // Too long
            break;
        }

        dentry = parent;
        // bpf_printk("__d_path: off: %d len: %d str: %s", off, len, str);
    }
    // bpf_printk("dentry_path: %s", &buf[off]);
    return off;
}