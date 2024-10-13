#!/usr/bin/python3  
from bcc import BPF
from time import sleep

program = r"""


struct data_t {
   u64 counter;
   char comm[16];
};

BPF_HASH(counter_table, u32, struct data_t);



int hello(void *ctx) {
   u32 pid;
   struct data_t data = {};

   pid = bpf_get_current_pid_tgid() >> 32;

   bpf_get_current_comm(&data.comm, sizeof(data.comm));

   struct data_t *p = counter_table.lookup(&pid);
   if (p != 0) {
      data.counter = p->counter;
   }
   
   data.counter++;
   
   counter_table.update(&pid, &data);
   return 0;
}
"""

b = BPF(text=program)

syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

while True:
    sleep(2)
    s = ""
    for k, v in b["counter_table"].items():
        s += f"PID {k.value}: Comm: {v.comm.decode('utf-8', 'replace')}, Count: {v.counter}\n"
    print(s)
