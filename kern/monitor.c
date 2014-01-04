// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/trap.h>
#include <kern/pmap.h>
#include <kern/env.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "backtrace", "Display stack", mon_backtrace },
	{ "map", "Display mapping", mon_map },
	{ "set", "Set mapping", mon_set },
	{ "xp", "Dump physical memory", mon_xp },
	{ "xv", "Dump virtual memory", mon_xv },
	{ "c", "Continue process", mon_c },
	{ "si", "Step", mon_si },
};
#define NCOMMANDS (sizeof(commands)/sizeof(commands[0]))

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < NCOMMANDS; i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	uint32_t* cur = (uint32_t*)read_ebp();
	struct Eipdebuginfo info;
	cprintf("Stack backtrace:\n");
	do {
		cprintf("  ebp %08x  eip %08x  args %08x %08x %08x %08x %08x\n", (uint32_t)cur, cur[1], cur[2], cur[3], cur[4], cur[5], cur[6]);
		debuginfo_eip((uintptr_t)cur[1], &info);
		cprintf("         %s:%d: %.*s+%d\n", info.eip_file, info.eip_line, info.eip_fn_namelen, info.eip_fn_name, (uintptr_t)cur[1] - info.eip_fn_addr);
		cur = (uint32_t*)*cur;

	} while (cur);
	return 0;
}

int
mon_map(int argc, char **argv, struct Trapframe *tf)
{
	size_t start;
	size_t end;
	size_t i;
	char status[10];
	start = strtol(argv[1], NULL, 0);
	end = strtol(argv[2], NULL, 0);
	pte_t* pgtable;
	if (start < 0 || start > end) {
		cprintf("Invalid parameters[start=%08x, end=%08x]\n", start, end);
		return 0;
	}
	strcpy(status, "---------");
	start = ROUNDDOWN(start, PGSIZE);
	for (i = start; i < end; i += PGSIZE) {
		pgtable = pgdir_walk(kern_pgdir, (const void*)i, true);
		status[0] = (*pgtable & PTE_G)   ? 'G' : '-';
		status[1] = (*pgtable & PTE_PS)  ? 'S' : '-';
		status[2] = (*pgtable & PTE_D)   ? 'D' : '-';
		status[3] = (*pgtable & PTE_A)   ? 'A' : '-';
		status[4] = (*pgtable & PTE_PCD) ? 'C' : '-';
		status[5] = (*pgtable & PTE_PWT) ? 'T' : '-';
		status[6] = (*pgtable & PTE_U)   ? 'U' : '-';
		status[7] = (*pgtable & PTE_W)   ? 'W' : '-';
		status[8] = (*pgtable & PTE_P)   ? 'P' : '-';
		cprintf("[%5x-%5x] %s %5x\n", PGNUM(i), PGNUM(i)+1, status, PGNUM(*pgtable));
	}
	return 0;
}

int
mon_set(int argc, char **argv, struct Trapframe *tf)
{
	size_t page;
	size_t flag;
	char status[10];
	pte_t* pgtable;
	page = strtol(argv[1], NULL, 0);
	flag = strtol(argv[2], NULL, 0);
	if (page < 0 || page > KERNBASE) {
		cprintf("Invalid parameters[page=%08x]\n", page);
		return 0;
	}
	strcpy(status, "---------");
	page = ROUNDDOWN(page, PGSIZE);
	pgtable = pgdir_walk(kern_pgdir, (const void*)page, true);
	*pgtable = PTE_ADDR(*pgtable) | flag;
	status[0] = (*pgtable & PTE_G)   ? 'G' : '-';
	status[1] = (*pgtable & PTE_PS)  ? 'S' : '-';
	status[2] = (*pgtable & PTE_D)   ? 'D' : '-';
	status[3] = (*pgtable & PTE_A)   ? 'A' : '-';
	status[4] = (*pgtable & PTE_PCD) ? 'C' : '-';
	status[5] = (*pgtable & PTE_PWT) ? 'T' : '-';
	status[6] = (*pgtable & PTE_U)   ? 'U' : '-';
	status[7] = (*pgtable & PTE_W)   ? 'W' : '-';
	status[8] = (*pgtable & PTE_P)   ? 'P' : '-';
	cprintf("[%5x-%5x] %s %5x\n", PGNUM(page), PGNUM(page)+1, status, PGNUM(*pgtable));
	return 0;
}

int
mon_xp(int argc, char **argv, struct Trapframe *tf)
{
	size_t start;
	size_t length;
	size_t i;
	start = strtol(argv[1], NULL, 0);
	length = strtol(argv[2], NULL, 0);
	for (i = 0; i < length; i+=4, start+=16) {
		cprintf("[%08x]: 0x%08x 0x%08x 0x%08x 0x%08x\n", 
			start, 
			*((uint32_t*)KADDR(start)),
			*((uint32_t*)KADDR(start+4)),
			*((uint32_t*)KADDR(start+8)),
			*((uint32_t*)KADDR(start+12))
		);
	}
	return 0;
}

int
mon_xv(int argc, char **argv, struct Trapframe *tf)
{
	size_t start;
	size_t length;
	size_t i;
	start = strtol(argv[1], NULL, 0);
	length = strtol(argv[2], NULL, 0);
	for (i = 0; i < length; i+=4, start+=16) {
		cprintf("[%08x]: 0x%08x 0x%08x 0x%08x 0x%08x\n", 
			start, 
			*((uint32_t*)(start)),
			*((uint32_t*)(start+4)),
			*((uint32_t*)(start+8)),
			*((uint32_t*)(start+12))
		);
	}
	return 0;
}

int mon_c(int argc, char **argv, struct Trapframe *tf) {
	if (tf == NULL || (tf->tf_trapno != T_BRKPT && tf->tf_trapno != T_DEBUG)) {
		cprintf("Invalid Trapframe\n");
		return -1;
	}
	tf->tf_eflags &= ~FL_TF;
	env_run(curenv);
	return 0;
}

int mon_si(int argc, char **argv, struct Trapframe *tf) {
	struct Eipdebuginfo info;
	if (tf == NULL || (tf->tf_trapno != T_BRKPT && tf->tf_trapno != T_DEBUG)) {
		cprintf("Invalid Trapframe\n");
		return -1;
	}
	debuginfo_eip(tf->tf_eip, &info);
	cprintf("0x%08x %s:%d: %.*s+%d\n", tf->tf_eip, info.eip_file, info.eip_line, info.eip_fn_namelen, info.eip_fn_name, tf->tf_eip-info.eip_fn_addr);
	tf->tf_eflags |= FL_TF;
	env_run(curenv);
	return 0;
}


/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < NCOMMANDS; i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("%<RWelcome to the JOS kernel monitor!\n");
	cprintf("%<GType 'help' for a list of commands.\n");

	if (tf != NULL)
		print_trapframe(tf);

	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}
