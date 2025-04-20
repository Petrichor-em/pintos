#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"
#include "threads/vaddr.h"
#include "pagedir.h"
#include "devices/shutdown.h"
#include <stdio.h>
#include "lib/user/syscall.h"
#include <console.h>
#include <string.h>

static void syscall_handler (struct intr_frame *);
static void parse_stack(void *stack_ptr, void **stack_frame_ptrs, int cnt);
static void validate_addr(void *addr);
static void validate_string_addr(char *addr);
static void handle_illegal_memory_access(void);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void parse_stack(void *stack_ptr, void **stack_frame_ptrs, int cnt)
{
  for (int i = 0; i < cnt; ++i) {
    stack_frame_ptrs[i] = stack_ptr;
    stack_ptr += 4;
  }
}

static void validate_addr(void *addr)
{
  if (!is_user_vaddr(addr) || !pagedir_get_page(thread_current()->pagedir, pg_round_down(addr))) {
    handle_illegal_memory_access();
  }
}

static void validate_args_addr(void *start, int cnt)
{
  // START points to the first argument's address.
  while (cnt > 0) {
    validate_addr(start);
    validate_addr(start + 4);
    start += 4;
    --cnt;
  }
}

static void validate_string_addr(char *addr)
{
  char *s = addr;
  validate_addr(s);
  while (*s) {
    ++s;
    validate_addr(s);
  }
}

static void validate_buffer_addr(void *addr, unsigned buffer_size)
{
  validate_addr(addr);
  validate_addr(addr + buffer_size);
}

static void handle_illegal_memory_access(void)
{
// exit_status is initally -1, so this can be comment out.
// thread_current()->exit_status = -1;
//  printf("ILLEGAL MEMORY ACCESS\n");
  thread_exit();
}


static void
syscall_handler (struct intr_frame *f UNUSED) 
{
//  printf ("system call!\n");
  validate_addr(f->esp);
  validate_addr(f->esp + 4);
  validate_addr(f->eip);
  void *stack_frame_ptrs[3];
  void *esp = f->esp;
  uint32_t syscall_no = *(uint32_t *)esp;
  esp += 4; // Now esp points to ARG0.
  struct thread *cur = thread_current();
//  printf("SYSCALL_NO: %d\n", syscall_no);

  switch (syscall_no) {
    case SYS_CHDIR:
      printf("chdir() called\n");
      parse_stack(esp, stack_frame_ptrs, 1);
      validate_args_addr(esp, 1);
      validate_string_addr(*(char **)stack_frame_ptrs[0]);
      break;
    case SYS_CLOSE:
      printf("close() called\n");
      validate_args_addr(esp, 1);
      break;
    case SYS_CREATE:
      printf("create() called\n");
      parse_stack(esp, stack_frame_ptrs, 2);
      validate_args_addr(esp, 2);
      validate_string_addr(*(char **)stack_frame_ptrs[0]);
      break;
    case SYS_EXEC:
//      printf("exec() called\n");
      parse_stack(esp, stack_frame_ptrs, 1);
      validate_args_addr(esp, 1);
      validate_string_addr(*(char **)stack_frame_ptrs[0]);
      f->eax = process_execute(*(char **)stack_frame_ptrs[0]);
      break;
    case SYS_EXIT:
//      printf("exit() called\n");
      parse_stack(esp, stack_frame_ptrs, 1);
      validate_args_addr(esp, 1);
      validate_addr(stack_frame_ptrs[0] + 4);
      cur->exit_status = *(int *)stack_frame_ptrs[0];
      thread_exit();
      break;
    case SYS_FILESIZE:
      printf("filesize() called\n");
      validate_args_addr(esp, 1);
      break;
    case SYS_HALT:
//      printf("halt() called\n");
      shutdown_power_off();
      break;
    case SYS_INUMBER:
      printf("inumber() called\n");
      validate_args_addr(esp, 1);
      break;
    case SYS_ISDIR:
      printf("isdir() called\n");
      validate_args_addr(esp, 1);
      break;
    case SYS_MKDIR:
      printf("mkdir() called\n");
      parse_stack(esp, stack_frame_ptrs, 1);
      validate_args_addr(esp, 1);
      validate_string_addr(*(char **)stack_frame_ptrs[0]);
      break;
    case SYS_MMAP:
      printf("mmap() called\n");
      parse_stack(esp, stack_frame_ptrs, 2);
      validate_args_addr(esp, 2);
      validate_addr(*(void **)stack_frame_ptrs[1]);
      break;
    case SYS_MUNMAP:
      printf("munmap() called\n");
      validate_args_addr(esp, 1);
      break;
    case SYS_OPEN:
      printf("open() called\n");
      parse_stack(esp, stack_frame_ptrs, 1);
      validate_args_addr(esp, 1);
      validate_string_addr(*(char **)stack_frame_ptrs[0]);
      break;
    case SYS_READ:
      printf("read() called\n");
      parse_stack(esp, stack_frame_ptrs, 3);
      validate_args_addr(esp, 3);
      validate_buffer_addr(*(void **)stack_frame_ptrs[1], *(unsigned *)stack_frame_ptrs[2]);
      break;
    case SYS_READDIR:
      printf("readdir() called\n");
      parse_stack(esp, stack_frame_ptrs, 2);
      validate_args_addr(esp, 2);
      validate_addr(*(char **)stack_frame_ptrs[1]);
      break;
    case SYS_REMOVE:
      printf("remove() called\n");
      parse_stack(esp, stack_frame_ptrs, 1);
      validate_args_addr(esp, 1);
      validate_string_addr(*(char **)stack_frame_ptrs[0]);
      break;
    case SYS_SEEK:
      printf("seek() called\n");
      validate_args_addr(esp, 2);
      break;
    case SYS_TELL:
      printf("tell() called\n");
      validate_args_addr(esp, 1);
      break;
    case SYS_WAIT:
//      printf("wait() called\n");
      parse_stack(esp, stack_frame_ptrs, 1);
      validate_args_addr(esp, 1);
      f->eax = process_wait(*(pid_t *)stack_frame_ptrs[0]);
      break;
    case SYS_WRITE:
//      printf("write() called\n");
      parse_stack(esp, stack_frame_ptrs, 3);
      validate_args_addr(esp, 3);
      validate_buffer_addr(*(void **)stack_frame_ptrs[1], *(unsigned *)stack_frame_ptrs[2]);
      if (*(int *)stack_frame_ptrs[0] == 1) {
        printf("%s", *(char **)stack_frame_ptrs[1]);
      }
      break;
    default:
      printf("UNKNOWN SYSCALL NUMBER\n");
      cur->exit_status = -1;
      thread_exit();
  }
}
