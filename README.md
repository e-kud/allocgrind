# allocgrind

Inspired by `maxmem2.sh` and `maxmem-pipe2.py` scripts from https://gcc.gnu.org/wiki/PerformanceTesting

# How-to

```sh
$ strace -e brk,mremap,munmap,mmap,mmap2 -f -tt -k -o "|./allocgrind.py" yourapp
$ /path/to/FlameGraph/flamegraph.pl out.stacks > out.svg
```
