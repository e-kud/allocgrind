#!/usr/bin/python3

import re
import sys
import collections
from dataclasses import dataclass, field

mmapmax = {}
mmap = {}
brkmin = {}
brkmax = {}
interrupted = {}
stacks = collections.defaultdict(lambda: 0)

@dataclass
class Event:
    pid: int
    timestamp: str
    syscall: str
    args: str
    ret: str
    stack: list[str] = field(default_factory=list)

    def append_stack_element(self, stack_element):
        self.stack.append(stack_element.strip())

    def get_stack(self):
        return f'{self.pid};{";".join(self.stack)}'

def handle_event(event):
    if not event:
        return
    pid = event.pid
    new = 0
    # 26277 01:11:15.512823 brk(0x55a08e186000) = 0x55a08e186000
    if event.syscall == 'brk':
        addr = int(event.ret, 16)
        brkmin[pid] = min(brkmin.get(pid, addr + 1), addr)
        brkmax[pid] = max(brkmax.get(pid, addr - 1), addr)
    # 7277 01:27:22.130417 mmap(0x7f8f22506000, 163840, PROT_READ, ..., 3, 0x6d000) = 0x7f8f22506000
    elif event.syscall == 'mmap':
        farg = event.args.index(',') + 1
        sarg = event.args.index(',', farg)
        new = int(event.args[farg:sarg])
        mmap[pid] = mmap.get(pid, 0) + new
        mmapmax[pid] = max(mmapmax.get(pid, 0), mmap[pid])
    # 9125 01:36:43.907874 munmap(0x7fee2f6cd000, 66971) = 0
    elif event.syscall == 'munmap':
        farg = event.args.index(',') + 1
        mmap[pid] = mmap.get(pid, 0) - int(event.args[farg:])
    # 2111 01:51:36.604570 mremap(0x7fa87b9ad000, 4096, 4096, ..., 0x7fa87b9e7000) = 0x7fa87b9e7000
    elif event.syscall == 'mremap':
        farg = event.args.index(',')
        sarg = event.args.index(',', farg + 1)
        targ = event.args.index(',', sarg + 1)
        old_size = int(event.args[farg + 1:sarg])
        new_size = int(event.args[sarg + 1:targ])
        new = max(0, new_size - old_size)
        mmap[pid] = mmap.get(pid, 0) - old_size + new_size
        mmapmax[pid] = max(mmapmax.get(pid, 0), mmap[pid])
    else:
        print(event.__dict__)
        assert False

    if new > 0:
        stack = event.get_stack()
        stacks[stack] += new

# pid timestamp syscall(args...) = ret
# group 0 - whole string
# group 1 - pid
# group 2 - timestamp
# group 3 - <...
# group 4 - brk|sbrk|mmap|munmap|mremap
# group 5
#         - group 6 = group 7
#         - (... <unfinished ...>
#         - resumed>)
# group 6 - (arg, arg, arg)
# group 7 - hex or decimal number
generic_pattern = re.compile(r'([0-9]+) '
                             r'([0-9:\.]+) '
                             r'(<\.\.\. )*(brk|sbrk|mmap|munmap|mremap)'
                             r'(\((.*)\)\s*=\s*([0-9a-fx]+)|.*unfinished.*|.*resumed.*)')

def main():
    event = None
    for line in sys.stdin:
        if line.startswith(' >'):
            if not event:
                continue
            print(line)
            event.append_stack_element(line[len(' > '):])
        else:
            handle_event(event)
            event = None
            print(line)
            syscall = generic_pattern.match(line)
            if not syscall:
                assert '+++' in line or '---' in line
                continue
            pid = int(syscall.group(1))
            if 'unfinished' in syscall.group(5):
                interrupted[pid] = line
                continue

            if 'resumed' in syscall.group(5):
                line = interrupted[pid][:-len(' <unfinished ...>')] + line[line.index('>') + 1:]
                print('Concatenated call:', line)
                syscall = generic_pattern.match(line)
                assert syscall

            event = Event(pid, syscall.group(2), syscall.group(4), syscall.group(6),
                          syscall.group(7))

    ovrallmmap = 0
    for pid, val in mmapmax.items():
        if val > ovrallmmap:
            ovrallmmap = val

    ovrallbrk = 0
    for pid, val in brkmax.items():
        use = val - brkmin[pid]
        if use > ovrallbrk:
            ovrallbrk = use

    print(f'total: {(ovrallmmap + ovrallbrk)/1024} kB')

    with open('out.stacks', 'w', encoding='UTF-8') as fstacks:
        for stack, mem in stacks.items():
            fstacks.write(f'{stack} {mem}\n')

if __name__ == "__main__":
    main()
