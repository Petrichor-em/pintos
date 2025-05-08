#include "page.h"
#include "filesys/file.h"
#include <string.h>
#include <bitmap.h>
#include "threads/synch.h"
#include "devices/block.h"
#include "threads/vaddr.h"
#include <round.h>
#include <debug.h>
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "threads/interrupt.h"
#include <hash.h>
#include "userprog/process.h"
#include <stdio.h>

// SLOT_SIZE = 4KB = (4KB / 512B) sectors = 8 sectors
#define SLOT_SIZE (PGSIZE / BLOCK_SECTOR_SIZE)

struct swap_pool {
  struct lock lock;
  struct bitmap *used_map;
  struct block *swap_block;
};

struct list lru_list;
struct lock lru_list_lock;
struct swap_pool pool;
struct condition swap_not_full;
struct list_elem *clock_ptr;

static void init_swap_pool(void);

static block_sector_t slot_offset(block_sector_t location);
static block_sector_t slot_index(block_sector_t location);

static bool swap_make_room(void);
static void write_swap(block_sector_t sector, const void *buf);

void page_init(void)
{
  list_init(&lru_list);
  lock_init(&lru_list_lock);
  cond_init(&swap_not_full);
  init_swap_pool();
  clock_ptr = list_end(&lru_list);
}

// Called by process_exit() to release associated resources.
void demand_destroy(void)
{

  // Free all frames in lru_list.
  lock_acquire(&lru_list_lock);

  // We are not allowed to destroy ourselves if some of our pages is evicting.
  // while (!lock_try_acquire(&thread_current()->evict_lock)) {
  //   lock_release(&lru_list_lock);
  //   thread_yield();
  //   lock_acquire(&lru_list_lock);
  // }

  struct list_elem *e = list_begin(&lru_list);
  while (e != list_end(&lru_list)) {
    struct frame *frame = list_entry(e, struct frame, lru_elem);
    if (frame->holder == thread_current()) {

      // This frame will be removed, so if clock_ptr points to this frame, we forward clock_ptr by one.
      if (clock_ptr == e) {
        clock_ptr = list_next(clock_ptr);
        if (clock_ptr == list_end(&lru_list)) {
          // When the lru_list becomes empty, clock_ptr will points to list end.
          clock_ptr = list_begin(&lru_list);
        }
      }

      struct list_elem *temp = e;
      e = list_next(e);
      list_remove(temp);
      free(frame);
    } else {
      e = list_next(e);
    }
  }

  struct hash_iterator i;
  hash_first(&i, &thread_current()->vm_table);
  while (hash_next(&i)) {
    struct vm_entry *vme = hash_entry(hash_cur(&i), struct vm_entry, vm_entry_elem);
    if (vme->page_type == VM_ANONYMOUS && vme->is_swapped) {
      lock_acquire(&pool.lock);
      bitmap_reset(pool.used_map, slot_index(vme->sector));
      lock_release(&pool.lock);
    } else if (vme->page_type == VM_GENERAL_FILE && pagedir_is_dirty(thread_current()->pagedir, vme->vaddr)) {
      // @Incomplete
    }
  }

  // lock_release(&thread_current()->evict_lock);
  // if (number_of_reseted_bits > 0) {
  //   cond_signal(&swap_not_full, &lru_list_lock);
  // }
  lock_release(&lru_list_lock);
}

static void init_swap_pool(void)
{
  struct block *swap_block = block_get_role(BLOCK_SWAP);
  block_sector_t sector_cnt = block_size(swap_block);
  // printf("Sector count is: %u\n", sector_cnt);
  // We devide swap block into slot_cnt slots.
  size_t slot_cnt = sector_cnt / SLOT_SIZE;
  // printf("Slot count is: %u\n", slot_cnt);
  pool.used_map = bitmap_create(slot_cnt);

  lock_init(&pool.lock);

  pool.swap_block = swap_block;
}

// Bring page from swap block to memory kaddr.
void swap_in(void *kaddr, struct vm_entry *vme)
{

  lock_acquire(&lru_list_lock);
  ASSERT(vme->page_type == VM_ANONYMOUS);
  ASSERT(vme->is_swapped);
  ASSERT(!vme->is_in_memory);
  ASSERT(slot_offset(vme->sector) == 0);

  uint32_t slot_idx = slot_index(vme->sector);
  lock_acquire(&pool.lock);
  ASSERT(bitmap_test(pool.used_map, slot_idx) == true);
  // We don't need to release space in swap block after swapping in the page
//  bitmap_set(pool.used_map, slot_idx, false);
  lock_release(&pool.lock);

//  lock_acquire(&vme->access);
  for (uint32_t i = 0; i < SLOT_SIZE; ++i) {
    block_sector_t cur_sector = vme->sector + i;
    void *cur_kaddr = kaddr + (BLOCK_SECTOR_SIZE * i);
    block_read(pool.swap_block, cur_sector, cur_kaddr);
  }
  lock_release(&lru_list_lock);
}

static block_sector_t slot_offset(block_sector_t location)
{
  return (location % SLOT_SIZE);
}

static uint32_t slot_index(block_sector_t location)
{
  ASSERT(slot_offset(location) == 0);
 
  return (location / SLOT_SIZE);
}

bool lru_add_frame(void *kaddr, struct vm_entry *vme)
{
  ASSERT(!vme->is_in_memory)
  lock_acquire(&lru_list_lock);

  vme->is_in_memory = true;
  struct frame *frame = malloc(sizeof (struct frame));
  if (frame == NULL) {
    return false;
  }
  frame->holder = thread_current();
  frame->kaddr = kaddr;
  frame->vme = vme;
  list_push_back(&lru_list, &frame->lru_elem);

  lock_release(&lru_list_lock);

  return true;
}

/*
  - Choose a frame to evict.
  - Free the frame in memory.
  - Remove the struct frame from lru_list and free its memory.
  - Return the evicted frame's kernel virtual address.
*/

// @Refactor
// For now we just use simple second chance algorithm.

// @Warning !!!
// We are accessing another thread's data such as vme and page.
// This may cause synchronization problem.
// For now we just disable intrrupt.
void *lru_evict_page(void)
{
 
  lock_acquire(&lru_list_lock);

  // struct list_elem *e;
  
  if (clock_ptr == list_end(&lru_list)) {
    clock_ptr = list_begin(&lru_list);
  }
  
  struct frame *evicted_frame = NULL;
  while (true) {
    struct frame *frame = list_entry(clock_ptr, struct frame, lru_elem);
    void *upage = frame->vme->vaddr;
    if (pagedir_is_accessed(frame->holder->pagedir, upage)) {
      pagedir_set_accessed(frame->holder->pagedir, upage, false);
    } else {
      evicted_frame = frame;
    }
    clock_ptr = list_next(clock_ptr);
    if (clock_ptr == list_end(&lru_list)) {
      clock_ptr = list_begin(&lru_list);
    }
    if (evicted_frame) {
      break;
    }
  }


  // for (second_chance_ptr = list_begin(&lru_list); second_chance_ptr != list_end(&lru_list); second_chance_ptr = list_next(second_chance_ptr)) {
  //   struct frame *frame = list_entry(second_chance_ptr, struct frame, lru_elem);
  //   void *upage = frame->vme->vaddr;
  //   if (pagedir_is_accessed(thread_current()->pagedir, upage)) {
  //     pagedir_set_accessed(thread_current()->pagedir, upage, false);
  //   } else {
  //     evicted_frame = frame;
  //     break;
  //   }
  // }
  // // second chance
  // if (!evicted_frame) {
  //   for (second_chance_ptr = list_begin(&lru_list); second_chance_ptr != list_end(&lru_list); second_chance_ptr = list_next(second_chance_ptr)) {
  //     struct frame *frame = list_entry(second_chance_ptr, struct frame, lru_elem);
  //     void *upage = frame->vme->vaddr;
  //     if (!pagedir_is_accessed(thread_current()->pagedir, upage)) {
  //       evicted_frame = frame;
  //       break;
  //     }
  //   }
  // }


  ASSERT(evicted_frame);
  ASSERT(evicted_frame->vme->is_in_memory);
  
  evicted_frame->vme->is_in_memory = false;
  pagedir_clear_page(evicted_frame->holder->pagedir, evicted_frame->vme->vaddr);
  list_remove(&evicted_frame->lru_elem);
  void *kaddr = evicted_frame->kaddr;

  if (evicted_frame->vme->page_type == VM_ANONYMOUS && !evicted_frame->vme->is_swapped) {

    uint32_t idx = 0;
    lock_acquire(&pool.lock);
    if ((idx = bitmap_scan_and_flip(pool.used_map, 0, 1, false)) == BITMAP_ERROR) {
      if (swap_make_room()) {
        idx = bitmap_scan_and_flip(pool.used_map, 0, 1, false);
      } else {
        printf("Bitmap error\n");
        lock_release(&lru_list_lock);
        lock_release(&pool.lock);
        thread_exit(); // No return
      }
    }
    lock_release(&pool.lock);
    
    // The evicted frame becomes swapped page from on.
    evicted_frame->vme->is_swapped = true;

    // We need to write this page to swap block.
    block_sector_t sector = SLOT_SIZE * idx;
    write_swap(sector, kaddr);
    evicted_frame->vme->sector = sector;
  } else if (evicted_frame->vme->page_type == VM_ANONYMOUS && evicted_frame->vme->is_swapped) {
    if (pagedir_is_dirty(evicted_frame->holder->pagedir, evicted_frame->vme->vaddr)) {
      // Write back
      block_sector_t sector = evicted_frame->vme->sector;
      write_swap(sector, kaddr);
    }
    // If this page isn't dirty, we just discard the content.
  } else if (evicted_frame->vme->page_type == VM_GENERAL_FILE &&
              pagedir_is_dirty(evicted_frame->holder->pagedir, evicted_frame->vme->vaddr)) {
    // @Incomplete
  }

  free(evicted_frame);
 
  // Now other thread can access their vm_entry and lru_list.
  lock_release(&lru_list_lock);
  
  return kaddr;
}

static void write_swap(block_sector_t sector, const void *buf)
{
  ASSERT(intr_get_level() == INTR_ON);
  for (int i = 0; i < SLOT_SIZE; ++i) {
    block_sector_t cur_sector = sector + i;
    const void *cur_kaddr = buf + (BLOCK_SECTOR_SIZE * i);
    block_write(pool.swap_block, cur_sector, cur_kaddr);
  }
}

static bool swap_make_room(void)
{
  ASSERT(lock_held_by_current_thread(&pool.lock));
  ASSERT(lock_held_by_current_thread(&lru_list_lock));

  for (struct list_elem *e = list_begin(&lru_list); e != list_end(&lru_list); e = list_next(e)) {
    struct frame *frame = list_entry(e, struct frame, lru_elem);
    if (frame->vme->is_swapped && frame->vme->is_in_memory) {
      // Redundant
      bitmap_reset(pool.used_map, slot_index(frame->vme->sector));
      frame->vme->is_swapped = false;
      return true;
    }
  }
  return false;
}

/*
  load the file to physical memory
  - Functoin to load a page from the disk to physical memory.
  - Implement this function to load a page to kaddr by <file, offset> of vme.
  - Use file_read_at() or file_read + file_seek()
  - If fail to write all 4KB, fill the rest with zero.
*/
bool load_page_from_elf_excutable(void *kaddr, struct vm_entry *vme)
{
  ASSERT(!vme->is_in_memory);
  bool already_held_filesys_lock = false;
  if (!lock_held_by_current_thread(&filesys_lock)) {
    lock_acquire(&filesys_lock);
  } else {
    already_held_filesys_lock = true;
  }
  file_seek(vme->file, vme->offset);
  uint32_t bytes_read = file_read(vme->file, kaddr, vme->read_bytes);
  if (!already_held_filesys_lock) {
    lock_release(&filesys_lock);
  }
  if (bytes_read != vme->read_bytes) {
    return false;
  }
  memset(kaddr + vme->read_bytes, 0, vme->zero_bytes);
  vme->page_type = VM_ANONYMOUS;
  vme->sector = 0;
  vme->is_swapped = false;
  return true;
}