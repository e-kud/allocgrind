#!/usr/bin/python3

import string
import re
import sys

mmapmax = {}
mmap = {}
brkmin = {}
brkmax = {}

class Event:
    def __init__(self, pid, timestamp, syscall, args, ret):
        self.pid = int(pid)
        self.timestamp = timestamp
        self.syscall = syscall
        self.args = args
        self.ret = ret
        self.bt = []

    def append_trace(self, trace_element):
        self.bt.append(trace_element)

def handle_event(event):
    if not event:
        return
    pid = event.pid
    # 26277 01:11:15.512823 brk(0x55a08e186000) = 0x55a08e186000
    if event.syscall == 'brk':
        addr = int(event.ret, 16)
        brkmin[pid] = min(brkmin.get(pid, addr + 1), addr)
        brkmax[pid] = max(brkmax.get(pid, addr - 1), addr)
    # 7277 01:27:22.130417 mmap(0x7f8f22506000, 163840, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x6d000) = 0x7f8f22506000
    elif event.syscall == 'mmap':
        farg = event.args.index(',') + 1
        sarg = event.args.index(',', farg)
        mmap[pid] = mmap.get(pid, 0) + int(event.args[farg:sarg])
        mmapmax[pid] = max(mmapmax.get(pid, 0), mmap[pid])
    # 9125 01:36:43.907874 munmap(0x7fee2f6cd000, 66971) = 0
    elif event.syscall == 'munmap':
        farg = event.args.index(',') + 1
        mmap[pid] = mmap.get(pid, 0) - int(event.args[farg:])
    # 2111 01:51:36.604570 mremap(0x7fa87b9ad000, 4096, 4096, MREMAP_MAYMOVE|MREMAP_FIXED, 0x7fa87b9e7000) = 0x7fa87b9e7000
    elif event.syscall == 'mremap':
        farg = event.args.index(',')
        sarg = event.args.index(',', farg + 1)
        targ = event.args.index(',', sarg + 1)
        old_size = int(event.args[farg + 1:sarg])
        new_size = int(event.args[sarg + 1:targ])
        mmap[pid] = mmap.get(pid, 0) - old_size + new_size
        mmapmax[pid] = max(mmapmax.get(pid, 0), mmap[pid])

# pid timestamp syscall(args...) = ret
generic_pattern = re.compile(r'([0-9]+) ([0-9:\.]+) (brk|sbrk|mmap|munmap|mremap)\((.*)\)\s*=\s*([0-9a-fx]+)')

event = None
for line in sys.stdin:
    if line.startswith(' >'):
        print(line)
        event.append_trace(line);
    else:
        handle_event(event)
        print(line)
        syscall = generic_pattern.match(line)
        if not syscall:
            assert '+++' in line or '---' in line
            continue
        event = Event(syscall.group(1), syscall.group(2), syscall.group(3), syscall.group(4), syscall.group(5))

ovrallmmap = 0
for pid, val in mmapmax.items():
    if val > ovrallmmap:
        ovrallmmap = val

ovrallbrk = 0
for pid, val in brkmax.items():
    use = val - brkmin[pid]
    if use > ovrallbrk:
        ovrallbrk = use

print("total: %u kB" % ((ovrallmmap + ovrallbrk)/1024))
