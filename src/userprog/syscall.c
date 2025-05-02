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
#include "lib/kernel/console.h"
#include <string.h>
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/serial.h"
#include "devices/input.h"

static void syscall_handler (struct intr_frame *);
static void validate_addr(const void *addr);
static void validate_string_addr(const char *addr);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}

// After implementing demand paging, we only need to check if ADDR is a user address.
// If the page is not in memory, it is likely that we haven't load it from disk into memory.
// page_fault() will take care of that.
static void validate_addr(const void *addr)
{
//  if (!is_user_vaddr(addr) || !pagedir_get_page(thread_current()->pagedir, pg_round_down(addr))) {
//    handle_illegal_memory_access();
//  }
  if (is_kernel_vaddr(addr)) {
    thread_exit();
  }
}

static void validate_args_addr(const uint32_t *argv, int cnt)
{
  for (int i = 0; i < cnt; ++i) {
    validate_addr(&argv[i]);
    validate_addr(&argv[i] + 1);
  }
}

// This function may trigger page_fault(), and introduce unloaded virtual page into memory.
static void validate_string_addr(const char *addr)
{
  const char *s = addr;
  validate_addr(s);
  while (*s) {
    ++s;
    validate_addr(s);
  }
}

// For demand paging, if the buffer address is in user space, we don't have to check
// whether the buffer is mapped in the page directory, because page_fault() will page on demand.
static void validate_buffer_addr(const void *addr, unsigned buffer_size)
{
//  validate_addr(addr);
//  validate_addr(addr + buffer_size);
  if (is_kernel_vaddr(addr) || is_kernel_vaddr(addr + buffer_size)) {
    thread_exit();
  }
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
//  printf ("system call!\n");
  void *esp = f->esp;
  validate_addr(esp);
  validate_addr(esp + 4);
  validate_addr(f->eip);
  uint32_t syscall_no = *(uint32_t *)esp;
  uint32_t *argv = esp + 4;
  struct thread *cur = thread_current();
  struct file *file;
  int fd = -1; // Assume that the file fd can't be open.
  int cnt = 0;
  void *buffer_addr = NULL;
  uint8_t byte = 0;
  int bytes_read = 0;
//  printf("SYSCALL_NO: %d\n", syscall_no);

  switch (syscall_no) {
    case SYS_CHDIR:
      printf("chdir() called\n");
      validate_args_addr(argv, 1);
      validate_string_addr((const char *)argv[0]);
      break;
    case SYS_CLOSE:
//      printf("close() called\n");
      validate_args_addr(argv, 1);
      fd = (int)argv[0];
      if (fd > 2 && fd < FDT_SIZE && cur->fdt[fd]) {
        lock_acquire(&filesys_lock);
        file_close(cur->fdt[fd]);
        lock_release(&filesys_lock);
        cur->fdt[fd] = NULL;
      }
      break;
    case SYS_CREATE:
//      printf("create() called\n");
      validate_args_addr(argv, 2);
      validate_string_addr((const char *)argv[0]);
      lock_acquire(&filesys_lock);
      f->eax = filesys_create((const char *)argv[0], (off_t)argv[1]);
      lock_release(&filesys_lock);
      break;
    case SYS_EXEC:
//      printf("exec() called\n");
      validate_args_addr(argv, 1);
      validate_string_addr((const char *)argv[0]);
      f->eax = process_execute((const char *)argv[0]);
      break;
    case SYS_EXIT:
//      printf("exit() called\n");
      validate_args_addr(argv, 1);
      cur->exit_status = (int)argv[0];
      thread_exit();
      break;
    case SYS_FILESIZE:
      validate_args_addr(argv, 1);
      fd = (int)argv[0];
      if (fd > 2 && fd < FDT_SIZE && cur->fdt[fd]) {
        lock_acquire(&filesys_lock);
        f->eax = file_length(cur->fdt[fd]);
        lock_release(&filesys_lock);
      } else {
        f->eax = -1;
      }
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
      validate_args_addr(argv, 1);
      validate_string_addr((const char *)argv[0]);
      break;
    case SYS_MMAP:
      printf("mmap() called\n");
      validate_args_addr(argv, 2);
      validate_addr((const void *)argv[1]);
      break;
    case SYS_MUNMAP:
      printf("munmap() called\n");
      validate_args_addr(argv, 1);
      break;
    case SYS_OPEN:
//      printf("open() called\n");
      validate_args_addr(argv, 1);
      validate_string_addr((const char *)argv[0]);
      lock_acquire(&filesys_lock);
      file = filesys_open((const char *)argv[0]);
      lock_release(&filesys_lock);
      if (file) {
        for (int i = 3; i < FDT_SIZE; ++i) {
          if (!cur->fdt[i]) {
            fd = i;
            cur->fdt[i] = file;
            break;
          }
        }
      }
      f->eax = fd;
      break;
    case SYS_READ:
//      printf("read() called\n");
      validate_args_addr(argv, 3);
      validate_buffer_addr((const void *)argv[1], (unsigned)argv[2]);
      fd = (int)argv[0];
      if (fd > 2 && fd < FDT_SIZE && cur->fdt[fd]) {
        lock_acquire(&filesys_lock);
        f->eax = file_read(cur->fdt[fd], (void *)argv[1], (off_t)argv[2]);
        lock_release(&filesys_lock);
      } else if (fd == 0) {
        cnt = (unsigned)argv[2];
        buffer_addr = (void *)argv[1];
        while (cnt > 0) {
          byte = input_getc();
          if (byte == (uint8_t)-1) {
            break;
          }
          *(uint8_t *)buffer_addr = byte;
          ++buffer_addr;
          ++bytes_read;
          --cnt;
        }
        f->eax = bytes_read;
      } else {
        f->eax = -1;
      }
      break;
    case SYS_READDIR:
      printf("readdir() called\n");
      validate_args_addr(argv, 2);
      validate_addr((const char *)argv[1]);
      break;
    case SYS_REMOVE:
//      printf("remove() called\n");
      validate_args_addr(argv, 1);
      validate_string_addr((const char *)argv[0]);
      lock_acquire(&filesys_lock);
      f->eax = filesys_remove((const char *)argv[0]);
      lock_release(&filesys_lock);
      break;
    case SYS_SEEK:
//      printf("seek() called\n");
      validate_args_addr(argv, 2);
      fd = (int)argv[0];
      if (fd > 2 && fd < FDT_SIZE && cur->fdt[fd]) {
        lock_acquire(&filesys_lock);
        file_seek(cur->fdt[fd], (off_t)argv[1]);
        lock_release(&filesys_lock);
      }
      break;
    case SYS_TELL:
//      printf("tell() called\n");
      validate_args_addr(argv, 1);
      fd = (int)argv[0];
      if (fd > 2 && fd < FDT_SIZE && cur->fdt[fd]) {
        lock_acquire(&filesys_lock);
        f->eax = file_tell(cur->fdt[fd]);
        lock_release(&filesys_lock);
      }
      break;
    case SYS_WAIT:
//      printf("wait() called\n");
      validate_args_addr(argv, 1);
      f->eax = process_wait((pid_t)argv[0]);
      break;
    case SYS_WRITE:
//      printf("write() called\n");
      validate_args_addr(argv, 3);
      validate_buffer_addr((const void *)argv[1], (unsigned)argv[2]);
      fd = (int)argv[0];
      if (fd > 2 && fd < FDT_SIZE && cur->fdt[fd]) {
        lock_acquire(&filesys_lock);
        f->eax = file_write(cur->fdt[fd], (const void *)argv[1], (off_t)argv[2]);
        lock_release(&filesys_lock);
      } else if (fd == 1 || fd == 2) {
        putbuf((const char *)argv[1], (size_t)argv[2]);
        if (fd == 2) {
          serial_flush();
        }
        f->eax = (size_t)argv[2];
      } else {
        f->eax = -1;
      }
      break;
    default:
      printf("UNKNOWN SYSCALL NUMBER\n");
      cur->exit_status = -1;
      thread_exit();
  }
}
