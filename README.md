ChaCha20
========

A homemade ChaCha20 implementation in x86_64 nasm ASM

Note that this code is NOT optimized, has NOT been thoroughly checked, and breaks all calling conventions ever made.<br/>
It Works On My Machine, but please use an official implementation for any serious project.

An example test file is provided, it can be compiled and run like this :

```
nasm chacha20.asm -f elf64 -g -F dwarf
nasm test.asm -f elf64 -g -F dwarf
ld chacha20.o test.o -o test
./test | xxd
```

The output should match the all-zero test vector provided <a href="http://tools.ietf.org/html/draft-strombergson-chacha-test-vectors-00#section-3">here</a>
