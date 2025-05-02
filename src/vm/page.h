#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdbool.h>
#include "userprog/process.h"

bool load_page(void *kaddr, struct vm_entry *vme);

#endif