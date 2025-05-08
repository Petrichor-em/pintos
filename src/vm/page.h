#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdbool.h>
#include "userprog/process.h"
#include "threads/thread.h"
#include <list.h>

struct frame {
    struct list_elem lru_elem;
    void *kaddr; // Where can we find this page if it's in memory.
    struct thread *holder;
    struct vm_entry *vme; // Where can we find this page if it's not in meomory.
};

void page_init(void);
void demand_destroy(void);
extern struct lock lru_list_lock;

bool load_page_from_elf_excutable(void *kaddr, struct vm_entry *vme);
// Swap in page into kaddr.
void swap_in(void *kaddr, struct vm_entry *vme);

// Evict a page from lru_list.
void *lru_evict_page(void);

// Add a frame to lru_list, providing kernel address and vm_entry.
bool lru_add_frame(void *kaddr, struct vm_entry *vme);


// @Incomplete
bool load_page_from_general_file(void);

// We must free struct page and swap slot associated with current thread.
//void lru_free_all_frames(void);

#endif