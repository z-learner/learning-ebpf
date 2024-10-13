#!/usr/bin/python3  
from bcc import BPF

program = r"""
int hello(void *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid =  bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    bpf_trace_printk("Hello World! PID: %d, TID: %d\n", pid, tid);
    
    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

b.trace_print()
