// go:build ignore

// TODO: Add error handling...

// #include "common.h"
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"
#include "utils.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_CGROUP_TRAVERSAL_DEPTH 32
const int CONTAINERID_SIZE = 64;

#define NO_LSM
#define NO_KPROBE_ENFORCEMENT
#define CGROUP_V1

struct string_lpm_trie
{
	__u32 prefixlen;
	__u8 data[MAX_BUF_SIZE];
};

struct local_cpu_data
{
	__u32 type;
	struct pt_regs *ctx;
	__u32 lastIndex;
};

#define MAX_EVENT_BUFFER 1024
#define MAX_EVENT_BUFFER_HALF (1024 >> 1)
#define MAX_EVENT_BUFFER_HALF_MASK (MAX_EVENT_BUFFER_HALF - 1)
struct process_event
{
	__u32 type;
	__u32 pid;
	__u32 tgid;
	__u32 uid;
	__u32 euid;
	__u32 gid;
	__u32 egid;

	// Parent process
	__u32 ppid;
	__u32 ptgid;
	__u32 puid;
	__u32 peuid;
	__u32 pgid;
	__u32 pegid;

	__u32 processgroupid;
	__u32 sid;

	__u32 currIndex;
	__u32 commIndex;
	__u32 execIndex;
	__u32 containerIDIndex;
	__u32 cmdLineIndex;
	__u32 lastIndex;
	__u8 buffer[MAX_EVENT_BUFFER]; // comm, and more
};

struct string_lpm_trie *unused_lpm_trie __attribute__((unused));
struct process_event *unused_process_event __attribute__((unused));

struct ContainerID
{
	char cid[64];
};

struct
{
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} programs_map SEC(".maps");

// Key: container ID
// Value: LPM TRIE map
struct
{
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, MAX_ENTRIES);
	__uint(key_size, sizeof(struct ContainerID));
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_LPM_TRIE);
			__uint(max_entries, 1);
			__type(key, __u8[sizeof(struct string_lpm_trie)]);
			__type(value, __u16);
			__uint(map_flags, BPF_F_NO_PREALLOC);
		});
} filename_maps SEC(".maps");

// TODO: Too many heaps...
struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct string_lpm_trie));
} filename_heap SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, MAX_BUF_SIZE);
} tmp_heap SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct local_cpu_data));
} local_cpu_data_map SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, CONTAINERID_SIZE);
} cid_heap SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, MAX_BUF_SIZE);
} buffer_heap SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} ringbuf_events SEC(".maps");

static inline __attribute__((always_inline)) u32 PushEventData(struct process_event *event, char *data, u32 *lastIndex)
{
	if (event->currIndex >= MAX_EVENT_BUFFER_HALF)
	{
		return -1;
	}
	if (lastIndex == NULL)
	{
		return -1;
	}

	// sz includes line endings.
	u8 sz = bpf_probe_read_kernel_str(&event->buffer[event->currIndex & MAX_EVENT_BUFFER_HALF_MASK], (MAX_EVENT_BUFFER_HALF - event->currIndex - 1) & MAX_EVENT_BUFFER_HALF_MASK, data);

	// Treat empty string as error too.
	if (sz > 1)
	{
		// Remove null character by moving currIndex.
		u32 oldIndex = event->currIndex;
		event->currIndex = (event->currIndex + (sz - 1)) & MAX_EVENT_BUFFER_HALF_MASK;
		*lastIndex = event->currIndex;

		return oldIndex;
	}

	return event->currIndex;

	// bpf_printk("[fork]: buffer: %d \"%s\" %d", sz, event->buffer, (MAX_EVENT_BUFFER_HALF - event->currIndex));
}

static inline __attribute__((always_inline)) u32 PushEventData2(struct process_event *event, char *data, u32 len, u32 *lastIndex)
{
	if (event->currIndex >= MAX_EVENT_BUFFER_HALF)
	{
		return -1;
	}
	if (lastIndex == NULL)
	{
		return -1;
	}

	// TODO: Not efficient.
	bpf_probe_read_kernel(&event->buffer[event->currIndex & MAX_EVENT_BUFFER_HALF_MASK], (MAX_EVENT_BUFFER_HALF - event->currIndex - 1) & MAX_EVENT_BUFFER_HALF_MASK, data);

	u8 sz = len;
	// Treat empty string as error too.
	if (sz > 1)
	{
		// Remove null character by moving currIndex.
		u32 oldIndex = event->currIndex;
		event->currIndex = (event->currIndex + (sz - 1)) & MAX_EVENT_BUFFER_HALF_MASK;
		*lastIndex = event->currIndex;

		return oldIndex;
	}

	return event->currIndex;

	// bpf_printk("[fork]: buffer: %d \"%s\" %d", sz, event->buffer, (MAX_EVENT_BUFFER_HALF - event->currIndex));
}

static inline __attribute__((always_inline)) bool
isSeperator(char c)
{
	return (c == '\0' || c == '.' || c == '-' || c == '=');
}

// This function gets potential container ID by enumerating the cgroup path of the current task, i.e., /proc/self/cgroup.
// TODO: CORE
// TODO: We can get container ID from its parent PID to speed up when we want more examination.
// TODO: Test cgroup v1.
static inline __attribute__((always_inline)) int
GetContainerID(int cidlen, char *buf, int len)
{
	// NOTE: A container is normally created following this order:
	// 1. Fork
	// 2. Create cgroup.
	// 3. Write the process ID into cgroup.
	// 4. Execve(), which will triggers bprm_creds_for_exec.

	// How to parse cgroupfs:
	// proc_cgroup_show(): https://elixir.bootlin.com/linux/v6.8/source/kernel/cgroup/cgroup.c#L6246
	// cgroup_path_ns_locked(): https://elixir.bootlin.com/linux/v6.8/source/kernel/cgroup/cgroup.c#L2363
	// While kernfs_path_from_node() requires root->kn to generate its path,
	// we want to traverse the whole path to find container ID, so we don't have to care about root.
	//
	// To find cgroup root, we have to take care about cgroup v1 and v2, e.g.:
	// A few possibilities are here.  Check __cset_cgroup_from_root()
	// 1. cset == init_css_set => The process is still being initialized(TODO)
	// 2. root == cgrp_dfl_root => cgroup v2 = Get cset->dfl_cgrp.
	// 3. Non default cgroup root => cgroup v1 => Check each of cset->cgrp_links and see if it's the root.

	// Overall flow:
	// task_struct => cgroup via task_cgroup_from_root(() => path via cgroup_path_ns_locked()
	// Note: cur->cgroups is not reliable when the process is moved between cgroup, but it's normally fine.

	struct task_struct *cur = bpf_get_current_task_btf();
	struct kernfs_node *kn;

	struct cgroup *cg;

	// TODO: Automatically fallback.

#ifdef CGROUP_V1

	if (cur->cgroups != NULL && cur->cgroups->subsys[cpu_cgrp_id] != NULL && cur->cgroups->subsys[cpu_cgrp_id]->cgroup != NULL && cur->cgroups->subsys[cpu_cgrp_id]->cgroup->kn != NULL)
	{
		kn = cur->cgroups->subsys[cpu_cgrp_id]->cgroup->kn;
#else
	if (cur->cgroups != NULL && cur->cgroups->dfl_cgrp != NULL && cur->cgroups->dfl_cgrp->kn != NULL)
	{
		kn = cur->cgroups->dfl_cgrp->kn;
#endif
		for (int i = 0; i < MAX_CGROUP_TRAVERSAL_DEPTH && kn != NULL; i++)
		{

#pragma unroll
			for (int i = 0; i < MAX_BUF_SIZE; i++)
			{
				buf[i] = 0;
			}

			u32 len = bpf_core_read_str(buf, MAX_BUF_SIZE, kn->name);
			bpf_printk("path: %s, len: %d", buf, len);

			//__builtin_memcpy(buf, kn->name, MAX_BUF_SIZE);
			// NOTE: back-edge from insn 60 to 61 means that you have a loop. Use #pragma unroll.

			// Find valid container ID
			//
			u32 from = 0, to = 0;

			// Note: If the for loop seems to expand unlimitedly, make sure you use a macro instead of a integer used in for loop boundary.
			// For example, for (i = 0; i < 1; i++) will fail.
			// Similarly, you can't use break inside a loop.
			bool finished = false;
#pragma unroll
			for (i = 0; i < MAX_BUF_SIZE - CONTAINERID_SIZE; i++)
			{
				if (i + CONTAINERID_SIZE > len)
				{
					finished = true;
				}
				if (buf[i] == '\0')
				{
					finished = true;
				}
				if (finished)
				{
					continue;
				}

				if ((i == 0 || isSeperator(buf[i - 1])) &&
					isSeperator(buf[i + CONTAINERID_SIZE]))
				{
					// TODO: Let userspace to parse it?
					/*
					// A potential container ID
					bool bContainerID = true;
					for (int j = 0; j < CONTAINERID_SIZE; j++)
					{
						char c = buf[i + j];
						if ((c > '9' || c < '0') && (c > 'f' || c < 'a'))
						{
							bContainerID = false;
							break;
						}
					}
					if (!bContainerID)
						continue;
					*/

					buf[i + CONTAINERID_SIZE] = '\0';
					return i;
				}
			}

			kn = kn->parent;
		}
	}
	return 0;
}

static inline __attribute__((always_inline)) int
GetTaskCmdline(struct task_struct *task, char *buf, int len)
{

	struct mm_struct *mm = NULL;
	mm = BPF_CORE_READ(task, mm);

	if (mm != NULL)
	{
		unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
		unsigned long arg_end = BPF_CORE_READ(mm, arg_end);

		if (arg_end < arg_start)
		{
			return 0;
		}

		bpf_probe_read_user(buf, len, arg_start);

		// TODO: For debugging
		/*
		for (int i = 0; i < len; i++)
		{
			if (buf[i] == '\0')
			{
				buf[i] = '*';
			}
		}
		bpf_printk("[fork]: cmdline: %s, length: %d", buf, arg_end - arg_start);
		*/
		return arg_end - arg_start;
	}
	return 0;
}

SEC("kprobe/tail_call_0")
int create_event(struct pt_regs *ctx)
{
	int zero = 0;
	char *tmp = (char *)bpf_map_lookup_elem(&tmp_heap, &zero);
	if (tmp == NULL)
	{
		return -1;
	}

	struct local_cpu_data *data = (struct local_cpu_data *)bpf_map_lookup_elem(&local_cpu_data_map, &zero);
	if (data == NULL)
	{
		return -1;
	}

	struct process_event *process_event;
	process_event = bpf_ringbuf_reserve(&ringbuf_events, sizeof(struct process_event), 0);
	if (!process_event)
	{
		return -1;
	}

	struct task_struct *task = (struct task_struct *)PT_REGS_PARM1_CORE(ctx);
	struct task_struct *parent = BPF_CORE_READ(task, parent);

	process_event->type = data->type;
	process_event->pid = BPF_CORE_READ(task, pid);
	process_event->tgid = BPF_CORE_READ(task, tgid);
	process_event->uid = BPF_CORE_READ(task, cred, uid.val);
	process_event->euid = BPF_CORE_READ(task, cred, euid.val);
	process_event->gid = BPF_CORE_READ(task, cred, gid.val);
	process_event->egid = BPF_CORE_READ(task, cred, egid.val);

	// bpf_core_read_str(process_event->comm, sizeof(process_event->comm), &task->comm);
	// BPF_CORE_READ_STR_INTO(&process_event->comm, task, comm);
	process_event->commIndex = PushEventData(process_event, (const void *)__builtin_preserve_access_index(&((typeof((task)))((task)))->comm), &data->lastIndex);
	// bpf_printk("[fork]: buffer: %s", process_event->buffer);

	// TODO: Maybe we don't need these.
	process_event->ppid = BPF_CORE_READ(parent, pid);
	process_event->ptgid = BPF_CORE_READ(parent, tgid);
	process_event->puid = BPF_CORE_READ(parent, cred, uid.val);
	process_event->peuid = BPF_CORE_READ(parent, cred, euid.val);
	process_event->pgid = BPF_CORE_READ(parent, cred, gid.val);
	process_event->pegid = BPF_CORE_READ(parent, cred, egid.val);

	process_event->processgroupid = BPF_CORE_READ(task, signal, pids[PIDTYPE_PGID], numbers[0].nr);
	process_event->sid = BPF_CORE_READ(task, signal, pids[PIDTYPE_SID], numbers[0].nr);

	// Basic information
	bpf_printk("[fork]: current pid: %d, tgid: %d, comm: %s", process_event->pid, process_event->tgid, task->comm);

	bpf_printk("[fork]: parent pid: %d, tgid: %d, comm: %s", process_event->ppid, process_event->ptgid, parent->comm);

	// Basic information#2
	bpf_printk("[fork]: uid: %d, euid: %d", process_event->uid, process_event->euid);
	bpf_printk("[fork]: puid: %d, peuid: %d", process_event->puid, process_event->peuid);

	// Command line & executable path
	struct dentry *dentry = BPF_CORE_READ(task, mm, exe_file, f_path.dentry);

	int off = __d_path(dentry, tmp, MAX_BUF_SIZE);
	if (off <= 0)
	{
		// failed to extract path.
		bpf_ringbuf_discard(process_event, 0);
		return -1;
	}

	process_event->execIndex = PushEventData(process_event, &tmp[off], &data->lastIndex);

	// Get Container ID.

	int index = GetContainerID(CONTAINERID_SIZE, tmp, MAX_BUF_SIZE);
	if (index != 0)
	{
		process_event->containerIDIndex = PushEventData(process_event, &tmp[index], &data->lastIndex);
	}
	else
	{
		process_event->containerIDIndex = data->lastIndex;
	}

	// Get command line
#define MAX_CMDLINE 256

	int len = GetTaskCmdline(task, tmp, MAX_CMDLINE);
	bpf_printk("[fork]: cmdline length: %d", len);
	process_event->cmdLineIndex = PushEventData2(process_event, tmp, len, &data->lastIndex);

	bpf_printk("[fork]: cmdline length: %d %d", process_event->cmdLineIndex, data->lastIndex);

	process_event->lastIndex = data->lastIndex;

	bpf_printk("[fork]: exec: %s", &tmp[off]);
	//  bpf_probe_read_kernel_str(process_event->buffer, sizeof(struct process_event), &(tmp[off]));
	bpf_ringbuf_submit(process_event, 0);
	return 0;
}

static inline __attribute__((always_inline)) int MatchString(char *prefix, char *str)
{
	for (int i = 0; i < MAX_BUF_SIZE; i++)
	{
		char ch1 = prefix[i];
		char ch2 = str[i];

		if (ch1 == '\0' && ch2 == '\0')
		{
			return 0;
		}
		if (ch1 == '\0')
		{
			return -1;
		}
		if (ch2 == '\0')
		{
			return -2;
		}
		if (ch1 != ch2)
		{
			return -3;
		}
	}
	return (-4);
}

static inline __attribute__((always_inline)) int SendEvent(int eventId, const char *msg)
{
	struct process_event *process_event;
	bpf_printk("generating event: %d: %s", eventId, msg);
	process_event = bpf_ringbuf_reserve(&ringbuf_events, sizeof(struct process_event), 0);
	if (!process_event)
	{
		return -ENOMEM;
	}
	struct task_struct *cur = bpf_get_current_task_btf();

	process_event->pid = bpf_get_current_pid_tgid() >> 32;
	process_event->ppid = cur->parent->tgid;
	process_event->uid = cur->cred->uid.val;
	process_event->euid = cur->cred->euid.val;
	process_event->gid = cur->cred->gid.val;
	process_event->egid = cur->cred->egid.val;

	bpf_get_current_comm(process_event->buffer, sizeof(process_event->buffer));
	// copy(process_event->buffer, sizeof(process_event->buffer), cur->comm);

	bpf_ringbuf_submit(process_event, 0);
	return 0;
}

#ifndef NO_LSM

// TODO: add bprm_committed_creds or related hooks
SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file)
{
	u32 key = 0;
	u64 initval = 1, *valp;

	char buf[MAX_BUF_SIZE];
	bpf_get_current_comm(buf, sizeof(buf));

	// TODO: string comparision & find real path.
	// TODO: simple policy engine
	// TODO: feature check
	if (file != NULL)
	{
		// Only allows in sleepable ebpf program, e.g., LSM & tracepoint because this could cause page fault.
		bpf_d_path(&file->f_path, buf, sizeof(buf));
	}

	// NOTE: This would cause issue:
	// program lsm_file_open: Call at insn 35: symbol "memcmp": unsatisfied program reference
	// This is because of its alignment and clang chooses to use memcmp instead.
	// if (__builtin_memcmp(buf, "/tmp/data", sizeof(buf)) == 0 ) {

	/*
		if (MatchPrefix("/tmp/data", buf) == 0)
		{
			SendEvent(-EPERM, buf);
			return -EPERM;
		}
	*/
	return 0;
}

#endif

/*
// This function checks if the process executed would comply the policy specified.
// Note: len shouldn't include trailing null character.
// Note: The original process event logic for fanotify:
// 1. Get parent PGID.  Get parent process's path via /proc/<pid>/exe , which is used for parent exception.
// 2. Get executable path.
// 3. Get parent PID  and execute user ID.
// 4. White list
// 5. ProfileZeroDrift mode (check learned rules) vs ProfileBasic mode.
//    If the previous check doesn't have a solid result and it's zero drift mode, check if it's from container root.
// TODO pgid vs pid, userspace vs kernel space.
// TODO: netlink => evaluateApplication() => procProfileEval() => MatchProfileProcess() => kill process.
//       vs
//       fanotify => FileAccessCtrl->processEvent() => block new process?
//       (policy) HandleProcessPolicyChange() => ... => AddContainerControlByPolicyOrder() => mergeMonitorRuleList() => addToMonitorList()
// DONE: no black list? => we have black/white list.  Just naming.
// TODO: Should we refactor the existing functions?
//       1. Event handling.
//
// TODO: make the policy into a series of ops? For example:
// Name=mkdir, Path=/usr/local/bin/mkdir => andOp(postfixOp(mkdir), prefixOp(/usr/local/bin/mkdir)).
// Format: [op, len][op, len][op, len].
// Example: [and, 0][postfix, 5, "mkdir"][prefix, 20, "/usr/local/bin/mkdir"]
// TODO: Do I need a stack?

static inline __attribute__((always_inline)) int
CheckRuntimePolicy(const char *executable, int len, int *verdict)
{
	bpf_printk("executable: %s", executable);

	struct task_struct *cur = bpf_get_current_task_btf();

	bpf_printk("ruid: %d", cur->cred->uid.val);
	bpf_printk("euid: %d", cur->cred->euid.val);
	bpf_printk("rgid: %d", cur->cred->gid.val);
	bpf_printk("egid: %d", cur->cred->egid.val);

	int zero = 0;
	char *cid = (char *)bpf_map_lookup_elem(&cid_heap, &zero);
	if (cid == NULL)
	{
		return 0;
	}

	bpf_printk("container ID: %s", cid); // TODO: null termination

	char *buf = (char *)bpf_map_lookup_elem(&buffer_heap, &zero);
	if (buf == NULL)
	{
		return 0;
	}

	if (GetContainerID(cid, CONTAINERID_SIZE, buf, MAX_BUF_SIZE) != 0)
	{
		return 0;
	}

	// Proposal: Get the first match of allow and block and compare its priority.
	if (MatchPrefix(cid, executable, len) == 1)
	{
		SendEvent(-EPERM, executable);
		*verdict = -EPERM;
	}

	return 0;
}
*/

// Using percpu array is generally fine if no hardware interrupt is involved.
// If we handle those higher priority interrupts, we should revisit this to make sure that no race condition would happen.
// TODO: Read these functions, which can be used to enforce security policies.
// bpf_override_return(): 4.16+ (symlink is a problem.)
// LSM: 5.10+
// bpf_probe_write_user(): 4.8+
// BTF: https://github.com/aquasecurity/btfhub/blob/main/docs/supported-distros.md
// Required capabilities:
// 1. BTF (/sys/kernel/btf/vmlinux)
// 2. LSM BPF
// 3.

// TODO: sleepable

#ifndef NO_LSM
SEC("lsm.s/bprm_creds_for_exec")
int BPF_PROG(lsm_bprm_creds_for_exec, struct linux_binprm *bprm)
{
	int verdict = 0;
	int zero = 0;
	char *buf = (char *)bpf_map_lookup_elem(&tmp_heap, &zero);
	if (buf == NULL)
	{
		return 0;
	}

	// char buf[MAX_BUF_SIZE] = {0};
	if (bprm->executable != NULL)
	{
		bpf_printk("bprm executable is available");
	}

	// This needs 5.18 and needs to be sleepable.
	if (bprm->file != NULL)
	{
		bpf_printk("bprm file is available");
		if (bprm->file->f_inode != NULL)
		{
			u8 ima_hash[20] = {0};
			bpf_printk("bprm inode is available");
			u32 ret = bpf_ima_file_hash(bprm->file, &ima_hash, sizeof(ima_hash));

			// ret means hash algo.  2: SHA1.
			bpf_printk("ima hash: %d, %x %x %x %x", ret, ima_hash[0], ima_hash[1], ima_hash[2], ima_hash[3]);
		}
	}

	if (bprm->interpreter != NULL)
	{
		bpf_printk("bprm interpreter is available");
	}

	u32 len = bpf_core_read_str(buf, MAX_BUF_SIZE, bprm->filename);

	if (CheckRuntimePolicy(buf, len - 1, &verdict) != 0)
	{
		// something is wrong. fail open.
		return 0;
	}

	return verdict;
}

#endif

//
// Kprobe
//
#ifndef NO_KPROBE_ENFORCEMENT

struct bpf_map_def SEC("maps") kprobe_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u64),
	.max_entries = 1,
};

// int execve(const char *pathname, char *const _Nullable argv[], char *const _Nullable envp[]);
// Kprobe is not ideal because it's subject to TOCTOU race.
// We should report violation, so TOCTOU can be responded.
SEC("kprobe/sys_execve")
int kprobe_execve(struct pt_regs *ctx)
{
	int verdict = 0;
	int zero = 0;
	char *buf = (char *)bpf_map_lookup_elem(&tmp_heap, &zero);
	if (buf == NULL)
	{
		bpf_printk("failed to find heap map.  Will fail open.");
		return 0;
	}

	// TODO:
	// NOTE: When CONFIG_ARCH_HAS_SYSCALL_WRAPPER is enabled, we need to get __ctx.
	// This is at least enabled on Ubuntu 22.04. See https://github.com/cilium/ebpf/issues/1016
	struct pt_regs *__ctx = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx);
	if (!__ctx)
	{
		bpf_printk("failed to read pt_regs.  Will fail open.");
		return 0;
	}

	char *filename = (char *)PT_REGS_PARM1_CORE(__ctx);
	// void *arg2 = PT_REGS_PARM2(ctx);
	// void *arg3 = PT_REGS_PARM3(ctx);

	int ret = bpf_probe_read_user_str(buf, MAX_BUF_SIZE, filename);
	if (ret <= 1)
	{
		bpf_printk("failed to read executable name from userspace: %d, will fail open.", ret);
		return 0;
	}

	ret = CheckRuntimePolicy(buf, ret - 1, &verdict);
	if (ret != 0)
	{
		bpf_printk("failed to check runtime policy: %d, will fail open.", ret);
		return 0;
	}

	if (verdict != 0)
	{
		bpf_printk("updating syscall return value to : %d", verdict);
		bpf_override_return(ctx, verdict);
		return 0;
	}

	return 0;
}

SEC("kprobe/exec_binprm")
int kprobe_exec_binprm(struct pt_regs *ctx)
{
	// void *arg2 = PT_REGS_PARM2(ctx);
	// void *arg3 = PT_REGS_PARM3(ctx);

	// unsigned long ino = BPF_CORE_READ(bprm, file, f_inode, i_ino);

	// err = BPF_CORE_READ_INTO(&name, t, mm, binfmt, executable, fpath.dentry, d_name.name);

	// 	u32 len = bpf_core_read_str(buf, MAX_BUF_SIZE, bprm->filename);

	// char *p = (char *)BPF_CORE_READ(bprm, filename);

	// bpf_printk("executable bprm: 0x%p", bprm);
	// char *filename = (char *);
	// void *arg2 = PT_REGS_PARM2(ctx);
	// void *arg3 = PT_REGS_PARM3(ctx);

	struct linux_binprm *bprm = (struct linux_binprm *)PT_REGS_PARM1_CORE(ctx);
	unsigned long ino = BPF_CORE_READ(bprm, file, f_inode, i_ino);

	bpf_printk("filepath: %s", BPF_CORE_READ(bprm, filename));
	bpf_printk("inode no: %d", ino);

	/*
		int ret = bpf_probe_read_user_str(buf, MAX_BUF_SIZE, filename);
		if (ret <= 1)
		{
			bpf_printk("failed to read executable name from userspace: %d, will fail open.", ret);
			return 0;
		}

		ret = CheckRuntimePolicy(buf, ret - 1, &verdict);
		if (ret != 0)
		{
			bpf_printk("failed to check runtime policy: %d, will fail open.", ret);
			return 0;
		}

		if (verdict != 0)
		{
			bpf_printk("updating syscall return value to : %d", verdict);
			bpf_override_return(ctx, verdict);
			return 0;
		}
	*/

	if (ino == 15207140)
	{
		bpf_printk("updating syscall return value to : %d", -EPERM);
		// bpf_override_return(ctx, -EPERM); // Not supported in functions other than syscall.
		bpf_send_signal_thread(SIGKILL);
		// TODO: task storage or a map to block the syscall?
	}

	return 0;
}

#endif

#ifndef NO_KPROBE

SEC("kprobe/proc_fork_connector")
int kprobe_proc_fork_connector(struct pt_regs *ctx)
{
	int zero = 0;
	char *tmp = (char *)bpf_map_lookup_elem(&tmp_heap, &zero);
	if (tmp == NULL)
	{
		return -1;
	}

	struct local_cpu_data *data = (struct local_cpu_data *)bpf_map_lookup_elem(&local_cpu_data_map, &zero);
	if (data == NULL)
	{
		return -1;
	}
	data->type = PROC_FORK_EVENT_TYPE;

	bpf_tail_call(ctx, &programs_map, 0);
	return 0;
}

SEC("kprobe/proc_exec_connector")
int kprobe_proc_exec_connector(struct pt_regs *ctx)
{
	int zero = 0;
	char *tmp = (char *)bpf_map_lookup_elem(&tmp_heap, &zero);
	if (tmp == NULL)
	{
		return -1;
	}

	struct local_cpu_data *data = (struct local_cpu_data *)bpf_map_lookup_elem(&local_cpu_data_map, &zero);
	if (data == NULL)
	{
		return -1;
	}
	data->type = PROC_EXEC_EVENT_TYPE;

	bpf_tail_call(ctx, &programs_map, 0);
	return 0;
}

SEC("kprobe/proc_exit_connector")
int kprobe_proc_exit_connector(struct pt_regs *ctx)
{
	int zero = 0;
	char *tmp = (char *)bpf_map_lookup_elem(&tmp_heap, &zero);
	if (tmp == NULL)
	{
		return -1;
	}

	struct local_cpu_data *data = (struct local_cpu_data *)bpf_map_lookup_elem(&local_cpu_data_map, &zero);
	if (data == NULL)
	{
		return -1;
	}
	data->type = PROC_EXIT_EVENT_TYPE;

	bpf_tail_call(ctx, &programs_map, 0);
	return 0;
}

#endif
