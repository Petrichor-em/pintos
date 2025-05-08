#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "devices/block.h"

#define FDT_SIZE 64
#define STACK_LIMIT 0xc0000000

extern struct lock filesys_lock;

void process_init(void);
tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

enum vm_page_type {
  VM_INVALID,
  VM_ELF_EXCUTABLE,
  VM_GENERAL_FILE,
  VM_ANONYMOUS,
  VM_STACK_GROWTH
};

struct vm_entry {
  struct hash_elem vm_entry_elem;

  enum vm_page_type page_type; // What's the type of this virtual page?
  void *vaddr; // Where should this virtual page be in virtual memory?
  bool is_writable; // Is this virtual page writable?
  bool is_in_memory; // Is this virtual page in memory?

  // For page locatng in disk, both VM_ELF_EXCUTABLE and VM_GENERAL_FILE.
  uint32_t read_bytes; // What's the size of the valid content in this virtual page?
  uint32_t zero_bytes; // What's the size of the rest in this virtual page?
  uint32_t offset; // What's the location of this virtual page in file?
  struct file *file; // Which file does this virtual page locate in?
  
  // For page in swap area.
  // For VM_ANONYMOUS pages, it can only locate in swap block.
//  struct block *block;
  block_sector_t sector; // Location of anonymous page (in sector) in swap block.
  bool is_swapped;

//  struct lock access; // The permission to access this resource.
};

void vm_init(struct hash *vm_table);
void vm_destroy(struct hash *vm_table);
struct vm_entry *vm_create(void);
struct vm_entry *vm_find(struct hash *vm_table, void *vaddr);
bool vm_insert(struct hash *vm_table, struct vm_entry *vme);
bool vm_delete(struct hash *vm_table, struct vm_entry *vme);

bool handle_mm_fault(struct vm_entry *vme);

#endif /**< userprog/process.h */
