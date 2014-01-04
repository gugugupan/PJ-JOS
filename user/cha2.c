#include <inc/lib.h>

void umain(int argc, char **argv) {
	cprintf("before int 3\n");
	asm volatile("int $3");
	cprintf("after int3\n");
}
