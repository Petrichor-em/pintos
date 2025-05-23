#include "userprog/process.h"
#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hash.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "vm/page.h"
#include <bitmap.h>

#define MAX_TOKENS 32

struct process_info {
   tid_t self_tid;
   tid_t parent_tid;
   int exit_status;
   struct hash_elem process_info_elem;
};

struct start_process_args {
  bool load_success;
  char *file_name;
};

struct lock filesys_lock;
struct hash process_info_hashtable;

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/** Tokenize command line arguments. */
static void tokenize_cmd(char *s, const char *delim, char **cmd_tokens);

/** Get process's infomation by providing its TID. */
static struct process_info *get_process_info_by_tid(tid_t tid);

/** Compare two process information elements by their hash values. */
static bool cmp_process_info_elem_tid(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);

/** Hash function for process information element. */
static unsigned hash_process_info_elem(const struct hash_elem *e, void *aux UNUSED);

/** Remove process information of the current thread's childs. */
static void remove_and_free_process_info_by_tid(tid_t tid);

static unsigned hash_vm_entry_elem(const struct hash_elem *e, void *aux UNUSED);

static bool cmp_vm_entry_elem_vaddr(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);

static void destroy_vm_entry_elem(struct hash_elem *e, void *aux UNUSED);

static void tokenize_cmd(char *s, const char *delim, char **cmd_tokens)
{
 char *token, *save_ptr;
 int pos = 0;
 for (token = strtok_r(s, delim, &save_ptr);
      token != NULL;
      token = strtok_r(NULL, delim, &save_ptr), ++pos) {
    cmd_tokens[pos] = token;
  }
  cmd_tokens[pos] = NULL;
}

void process_init(void)
{
  // Initialize process_info_hashtable, which will be used by the process_wait() system call.
  hash_init(&process_info_hashtable, hash_process_info_elem, cmp_process_info_elem_tid, NULL);
  lock_init(&filesys_lock);  // Global filesystem lock.
  page_init(); // Initialize paging system.
}

/** Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */

tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

    /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  // Make another copy of FILE_NAME.
  char *_file_name = palloc_get_page(0);
  if (_file_name == NULL) {
    return TID_ERROR;
  }
  strlcpy(_file_name, file_name, PGSIZE);
  
  char *first_token, *save_ptr;
  first_token = strtok_r(_file_name, " ", &save_ptr);

  /* Create a new thread to execute FILE_NAME. */
  struct start_process_args args;
  args.load_success = false;
  args.file_name = fn_copy;
  tid = thread_create (first_token, PRI_DEFAULT, start_process, &args);
  sema_down(&thread_current()->load_sema);
  if (!args.load_success) {
    tid = TID_ERROR;
  }
  palloc_free_page(_file_name);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy); 
  sema_down(&thread_current()->load_sema);
  return tid;
}

/** A thread function that loads a user process and starts it
   running. */
static void
start_process (void *aux)
{
  struct start_process_args *args = aux;
  struct thread *cur = thread_current();

  cur->is_user_process = true;

  cur->fdt = malloc(FDT_SIZE * sizeof (struct file *));
  memset(cur->fdt, 0, FDT_SIZE * sizeof (struct file *));
  struct process_info *process_info = malloc (sizeof (struct process_info));
  process_info->exit_status = -1;
  process_info->parent_tid = cur->parent->tid;
  process_info->self_tid = cur->tid;
//  list_push_back(&process_info_list, &process_info->process_info_elem);
  hash_insert(&process_info_hashtable, &process_info->process_info_elem);

  vm_init(&cur->vm_table);

  char *file_name = args->file_name;
  struct intr_frame if_;
  bool success;

  char *cmd_tokens[MAX_TOKENS];
  tokenize_cmd(file_name, " ", cmd_tokens);
  int tail = 0;
  while (cmd_tokens[tail] != NULL) {
    ++tail;
  }
  --tail;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (cmd_tokens[0], &if_.eip, &if_.esp);
  cur->load_success = success;
  if (success) {
    args->load_success = true;
  } else {
    args->load_success = false;
  }
  sema_up(&cur->parent->load_sema);
  if (!success) {
    thread_exit();
  }
  
  int argc = tail + 1;
  int sum_of_length = 0;
  int index = tail;
  while (index >= 0) {
    int length = strlen(cmd_tokens[index]);
    sum_of_length += (length + 1);
    if_.esp -= (length + 1);
    strlcpy(if_.esp, cmd_tokens[index], length + 1);
    cmd_tokens[index] = if_.esp;
    --index;
  }
  int padding = 0;
  if (sum_of_length % 4 != 0) {
    padding = (sum_of_length / 4 + 1) * 4 - sum_of_length;
  }
  if_.esp -= padding;
  memset(if_.esp, 0, padding);
  if_.esp -= sizeof(char *);
  *(char **)if_.esp = 0;
  index = tail;
  while (index >= 0) {
    if_.esp -= sizeof (char *);
    *(char **)if_.esp = cmd_tokens[index];
    --index;
  }
  char **argv = (char **)if_.esp;
  if_.esp -= sizeof (char **);
  *(char ***)if_.esp = argv;
  if_.esp -= sizeof (int);
  *(int *)if_.esp = argc;
  if_.esp -= sizeof (void (*) (void));
  *(void (**) (void))if_.esp = 0;
  
  /* If load failed, quit. */
  palloc_free_page (file_name);
  sema_up(&cur->parent->load_sema);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/** Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
  struct thread *cur = thread_current();
  struct thread *child = thread_get_child_by_tid(child_tid);
  if (child) {
    if (child->is_waited) {
      return -1;
    }
    child->is_waited = true;
    sema_down(&child->wait_exit_sema);
  }

  enum intr_level old_level = intr_disable();
  struct process_info *info = get_process_info_by_tid(child_tid);
  if (info && info->parent_tid == cur->tid) {
    int exit_status = info->exit_status;
    remove_and_free_process_info_by_tid(child_tid);
    intr_set_level(old_level);
    return exit_status;
  }
  intr_set_level(old_level);
  return -1;
}

/** Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  // We will access memory in this function, so we must call it before pagedir_destroy().
  demand_destroy();

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

    enum intr_level old_level = intr_disable();

    // Store exit_status in process_info.
    struct process_info *info = get_process_info_by_tid(cur->tid);
    if (info) {
      info->exit_status = cur->exit_status;
    }
    
    // Remove and free all childs' process_info to avoid resource leak,
    // because there is no chance to free them after their parent exited.
    // process_info list is a global data structure, so we have to modify it with intrrupt disabled.
    struct list_elem *e;
    for (e = list_begin(&cur->childs); e != list_end(&cur->childs); e = list_next(e)) {
      struct thread *child = list_entry(e, struct thread, child_elem);
      remove_and_free_process_info_by_tid(child->tid);
    }
 
    vm_destroy(&cur->vm_table);

    intr_set_level(old_level);

    // Free file descriptor table.
    // Note that if the current thread fails to load, it won't open any file.
    // So before we close all the files it has open, we check if it succeeds to load.
    if (cur->load_success) {
      for (int i = 3; i < FDT_SIZE; ++i) {
        if (cur->fdt[i]) {
          file_close(cur->fdt[i]);
        }
      }
    }
    free(cur->fdt);

    // Close running file if we have open it.
    if (cur->running_file) {
      file_close(cur->running_file);
    }

//    vm_destroy(&cur->vm_table);

  // Print exit infomation. Note that we must ensure that if we failed to load,
  // we must print exit information FIRST, and wake up parent thread.
  // It is unnecessary to check if parent is valid, because parent is waiting now so it can't exit at the moment.
  printf("%s: exit(%d)\n", cur->name, cur->exit_status);
  if (!cur->load_success) {
    sema_up(&cur->parent->load_sema);
  }

  // We must check wether current thread's parent thread is still running (not NULL).
  // Wake up parent thread if it is waiting.
  // It is totally ok if current thread's parent has exited.
//  if (cur->parent) {
  sema_up(&cur->wait_exit_sema);
//  }

}

/** Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/** We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/** ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/** For use with ELF types in printf(). */
#define PE32Wx PRIx32   /**< Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /**< Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /**< Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /**< Print Elf32_Half in hexadecimal. */

/** Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/** Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/** Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /**< Ignore. */
#define PT_LOAD    1            /**< Loadable segment. */
#define PT_DYNAMIC 2            /**< Dynamic linking info. */
#define PT_INTERP  3            /**< Name of dynamic loader. */
#define PT_NOTE    4            /**< Auxiliary info. */
#define PT_SHLIB   5            /**< Reserved. */
#define PT_PHDR    6            /**< Program header table. */
#define PT_STACK   0x6474e551   /**< Stack segment. */

/** Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /**< Executable. */
#define PF_W 2          /**< Writable. */
#define PF_R 4          /**< Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/** Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  lock_acquire(&filesys_lock);
  file = filesys_open (file_name);
  thread_current()->running_file = file;
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
  file_deny_write(file);

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              // file_page is offset of the file and mem_page is the user virtual address where the segment should be place.
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
    lock_release(&filesys_lock);
  return success;
}

/** load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/** Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/** Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

     struct vm_entry *vme = vm_create();
     vme->page_type = VM_ELF_EXCUTABLE;
     vme->vaddr = upage;
     vme->is_writable = writable;
     vme->is_in_memory = false;

     vme->read_bytes = page_read_bytes;
     vme->zero_bytes = page_zero_bytes;
     vme->offset = ofs;
     ofs += PGSIZE;
     vme->file = file;
//     lock_init(&vme->access);
     vm_insert(&thread_current()->vm_table, vme);
 
//       /* Get a page of memory. */
//       uint8_t *kpage = palloc_get_page (PAL_USER);
//       if (kpage == NULL)
//         return false;
// 
//       /* Load this page. */
//       if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
//         {
//           palloc_free_page (kpage);
//           return false; 
//         }
//       memset (kpage + page_read_bytes, 0, page_zero_bytes);
// 
//       /* Add the page to the process's address space. */
//       if (!install_page (upage, kpage, writable)) 
//         {
//           palloc_free_page (kpage);
//           return false; 
//         }
// 
      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/** Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/** Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

static struct process_info *get_process_info_by_tid(tid_t tid)
{
  ASSERT (intr_get_level() == INTR_OFF);

  struct process_info lookup;
  lookup.self_tid = tid;
  struct hash_elem *e = hash_find(&process_info_hashtable, &lookup.process_info_elem);
  if (e != NULL) {
    struct process_info *process_info = hash_entry(e, struct process_info, process_info_elem);
    return process_info;
  } else {
    return NULL;
  }
}

static void remove_and_free_process_info_by_tid(tid_t tid)
{
  ASSERT (intr_get_level() == INTR_OFF);

  struct process_info lookup;
  lookup.self_tid = tid;
  struct hash_elem *e = hash_find(&process_info_hashtable, &lookup.process_info_elem);
  if (e != NULL) {
    struct process_info *process_info = hash_entry(e, struct process_info, process_info_elem);
    hash_delete(&process_info_hashtable, e);
    free(process_info);
  }
}

static unsigned hash_process_info_elem(const struct hash_elem *e, void *aux UNUSED)
{

   const struct process_info *process_info = hash_entry(e, struct process_info, process_info_elem);
   return hash_int(process_info->self_tid);
}

static bool cmp_process_info_elem_tid(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
   const struct process_info *info_a = hash_entry(a, struct process_info, process_info_elem);
   const struct process_info *info_b = hash_entry(b, struct process_info, process_info_elem);
   return info_a->self_tid < info_b->self_tid;
}

/*
  - allocate physical memory
  - load file in the disk to physical memory
    - use load_file(void *kaddr, struct vm_entry)
  - update the associated page table after loading into physical memory
    - use static bool install_page(void *upage, void *kpage, bool writable)
  
  So the flow is:
  1. page allocation
    - may fail, return false
  2. check the vm_entry type
    - if it is NOT a binary file, fail with returning false
  3. load the data from file to the memory
  4. set up page table
  5. succuess, return true

  For now, we only consider ELF file, later we'll cover anonymous page and the other file backed page.
*/
bool handle_mm_fault(struct vm_entry *vme)
{

  ASSERT(vme);
  ASSERT(!vme->is_in_memory);

  // @Debug
/*
  switch (vme->page_type) {
    case VM_INVALID:
      printf("Invalid page fault\n");
      break;
    case VM_ANONYMOUS:
      printf("Anonymous page fault\n");
      break;
    case VM_ELF_EXCUTABLE:
      printf("Elf page fault\n");
      break;
    case VM_GENERAL_FILE:
      printf("General file page fault\n");
      break;
    case VM_STACK_GROWTH:
      printf("Stack growth page fault\n");
      break;
  }
*/

  void *kpage = palloc_get_page(PAL_USER);
  if (kpage == NULL) {
//    return false;
    kpage = lru_evict_page();
    ASSERT(kpage);
  }

  if (vme->page_type == VM_ELF_EXCUTABLE) {
    if (!load_page_from_elf_excutable(kpage, vme)) {
      palloc_free_page(kpage);
      return false;
    }
    if (!install_page(vme->vaddr, kpage, vme->is_writable)) {
      palloc_free_page(kpage);
      return false;
    }
    if (!lru_add_frame(kpage, vme)) {
      palloc_free_page(kpage);
      return false;
    }
//    ASSERT(vme->is_in_memory);
    return true;
  } else if (vme->page_type == VM_ANONYMOUS) {
    // @Debug
    // We should wait for completing swapping, if is_swapped is false.
//    if (!vme->is_swapped) {
//      sema_down(&vme->swap_sema);
//    }
    swap_in(kpage, vme);
    if (!install_page(vme->vaddr, kpage, vme->is_writable)) {
      palloc_free_page(kpage);
      return false;
    }
    if (!lru_add_frame(kpage, vme)) {
      palloc_free_page(kpage);
      return false;
    }
//    ASSERT(vme->is_in_memory);
    return true;
  } else if (vme->page_type == VM_STACK_GROWTH) {
    if (!install_page(vme->vaddr, kpage, vme->is_writable)) {
      palloc_free_page(kpage);
      return false;
    }
    vme->page_type = VM_ANONYMOUS;
    vme->sector = 0;
    vme->is_swapped = false;
    if (!lru_add_frame(kpage, vme)) {
      palloc_free_page(kpage);
      return false;
    }
//    ASSERT(vme->is_in_memory);
    return true;
  }
  printf("NO REACH!\n");
  thread_exit();
}

void vm_init(struct hash *vm_table)
{
  hash_init(vm_table, hash_vm_entry_elem, cmp_vm_entry_elem_vaddr, NULL);
}

struct vm_entry *vm_create(void)
{
  struct vm_entry *vme = malloc(sizeof (struct vm_entry));
  if (vme == NULL) {
    return NULL;
  }
  memset(vme, 0, sizeof (struct vm_entry));
  return vme;
}

/*
  Insert vme into vm_table. Return true if successfully insert, and false if
  vme is already in the vm_table.
*/
bool vm_insert(struct hash *vm_table, struct vm_entry *vme)
{
  struct hash_elem *e = hash_insert(vm_table, &vme->vm_entry_elem);
  if (e == NULL) {
    return true;
  } else {
    return false;
  }
}

struct vm_entry *vm_find(struct hash *vm_table, void *vaddr)
{
  struct vm_entry lookup;
  lookup.vaddr = vaddr;
  struct hash_elem *e = hash_find(vm_table, &lookup.vm_entry_elem);
  if (e == NULL) {
    return NULL;
  }
  struct vm_entry *vme = hash_entry(e, struct vm_entry, vm_entry_elem);
  return vme;
}

bool vm_delete(struct hash *vm_table, struct vm_entry *vme)
{
  struct hash_elem *e = hash_delete(vm_table, &vme->vm_entry_elem);
  if (e != NULL) {
    return true;
  } else {
    return false;
  }
}

void vm_destroy(struct hash *vm_table)
{
  hash_destroy(vm_table, destroy_vm_entry_elem);
}

static unsigned hash_vm_entry_elem(const struct hash_elem *e, void *aux UNUSED)
{
  struct vm_entry *vme = hash_entry(e, struct vm_entry, vm_entry_elem);
  return hash_bytes(&vme->vaddr, sizeof (void *));
}

static bool cmp_vm_entry_elem_vaddr(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  const struct vm_entry *vme_a = hash_entry(a, struct vm_entry, vm_entry_elem);
  const struct vm_entry *vme_b = hash_entry(b, struct vm_entry, vm_entry_elem);
  return vme_a->vaddr < vme_b->vaddr;
}

static void destroy_vm_entry_elem(struct hash_elem *e, void *aux UNUSED)
{
  struct vm_entry *vme = hash_entry(e, struct vm_entry, vm_entry_elem);
  free(vme);
}