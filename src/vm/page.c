#include "page.h"
#include "filesys/file.h"
#include <string.h>

/*
  load the file to physical memory
  - Functoin to load a page from the disk to physical memory.
  - Implement this function to load a page to kaddr by <file, offset> of vme.
  - Use file_read_at() or file_read + file_seek()
  - If fail to write all 4KB, fill the rest with zero.
*/
bool load_page(void *kaddr, struct vm_entry *vme)
{
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
  return true;
}