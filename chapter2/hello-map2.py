#!/usr/bin/python3  
from bcc import BPF
import time


program = """

  BPF_HASH(hello_map, u64, u64);
  
  int hello(void *ctx) { 
    u64 uid;
    u64 counter = 0;
    
    u64* p;
    
    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    p = hello_map.lookup(&uid);
    
    if (p != 0) {
      counter = *p;
    }
    
    counter++;
    hello_map.update(&uid, &counter);
    return 0;
  }

"""


b = BPF(text=program)

syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")


while True:
  time.sleep(2)
  s = ""
  for k, v in b["hello_map"].items():
    s += f"ID {k.value}: {v.value}\t"
  print(s)