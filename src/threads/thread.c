#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "fixed_point.h"
#include "init.h"
#include "malloc.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/** Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/** List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/** List of sleeping threads. */ 
struct list sleep_list;

/** List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/** Idle thread. */
static struct thread *idle_thread;

/** Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/** Lock used by allocate_tid(). */
static struct lock tid_lock;

/** mlfq */
static struct list mlfqs[PRI_MAX + 1];

/** Calculate the thread's priority, based on its niceness and the recent cpu. */
static int calculate_priority(struct thread *t);

/** Get the highest-priority-thread. If there is not, return NULL. */
static struct thread *get_highest_priority_thread();

/** Get number of ready_threads. */
static int get_num_ready_threads();

static Q14 calculate_recent_cpu(struct thread *t);

/** Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /**< Return address. */
    thread_func *function;      /**< Function to call. */
    void *aux;                  /**< Auxiliary data for function. */
  };

/** Statistics. */
static long long idle_ticks;    /**< # of timer ticks spent idle. */
static long long kernel_ticks;  /**< # of timer ticks in kernel threads. */
static long long user_ticks;    /**< # of timer ticks in user programs. */

static int64_t soon_wakeup_tick = -1; /**< # The tick of the thread that will wake up soon. */

/** Scheduling. */
#define TIME_SLICE 4            /**< # of timer ticks to give each thread. */
static unsigned thread_ticks;   /**< # of timer ticks since last yield. */

/** If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);
static bool cmp_lock_elem_priority(const struct list_elem *a, const struct list_elem *b, void *aux);
static int thread_get_donor_priority(struct thread *t);

/** Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);

  lock_init (&tid_lock);
  list_init (&ready_list);
  list_init (&all_list);
  list_init(&sleep_list);
//  list_init(&process_info_list);
//  hash_init(&process_info_hashtable, process_info_hash, process_info_less, NULL);
  for (int i = PRI_MIN; i <= PRI_MAX; ++i) {
    list_init(&mlfqs[i]);
  }

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
  initial_thread->nice = 0;
  initial_thread->recent_cpu = 0;
  if (thread_mlfqs) {
    initial_thread->priority = calculate_priority(initial_thread);
  }
}

/** Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/** Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) 
{
  struct thread *t = thread_current ();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();
}

/** Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/** Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);
  tid = t->tid = allocate_tid ();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  struct thread *cur = thread_current();
  t->nice = cur->nice;
  t->recent_cpu = cur->recent_cpu;
  if (thread_mlfqs) {
    t->priority = calculate_priority(t);
  }
  t->parent = cur;
  list_push_back(&cur->childs, &t->child_elem);
  /* Add to run queue. */
  thread_unblock (t);
  /* TODO:
    Compare the priorities of the currently running thread and the newly inserted one.
    Yield the CPU if the newly arriving thread has higher priority.
  */
  if (t->priority > cur->priority) {
    thread_yield();
  }

  return tid;
}

/** Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) 
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/** Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) 
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);
//  list_push_back (&ready_list, &t->elem);
  if (!thread_mlfqs) {
    list_insert_ordered(&ready_list, &t->elem, cmp_priority, NULL);
  }
  else {
    int priority = t->priority;
    list_push_back(&mlfqs[priority], &t->elem);
  }
  t->status = THREAD_READY;
  intr_set_level (old_level);
}

/** Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/** Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/** Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/** Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) 
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */

  // What if parent process exit but its childs are still running?
  struct thread *cur = thread_current();
  if (cur->parent) {
    sema_up(&cur->wait_exit_sema);
  }
  intr_disable();
  if (cur->parent) {
    list_remove(&cur->child_elem);
  }
  struct list_elem *e;
  for (e = list_begin(&cur->childs); e != list_end(&cur->childs); e = list_next(e)) {
    struct thread *child = list_entry(e, struct thread, child_elem);
    child->parent = NULL;
    remove_and_free_process_info_by_tid(child->tid);
  }

  // How can we release all the locks when we exit?

  list_remove (&cur->allelem);
  cur->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

struct process_info *get_process_info_by_tid(tid_t tid)
{
  ASSERT (intr_get_level() == INTR_OFF);

//  struct list_elem *e;
//  for (e = list_begin(&process_info_list); e != list_end(&process_info_list); e = list_next(e)) {
//    struct process_info *process_info = list_entry(e, struct process_info, process_info_elem);
//    if (process_info->self_tid == tid) {
//      return process_info;
//    }
//  }
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

void remove_and_free_process_info_by_tid(tid_t tid)
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

/** Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) 
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;
  
  ASSERT (!intr_context ());

  old_level = intr_disable ();
  if (cur != idle_thread) {
    if (!thread_mlfqs) {
      list_insert_ordered(&ready_list, &cur->elem, cmp_priority, NULL);
    }
    else {
      int priority = cur->priority;
      list_push_back(&mlfqs[priority], &cur->elem);
    }
  }
  cur->status = THREAD_READY;
  schedule ();
  intr_set_level (old_level);
}

/** Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/** Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) 
{
  // Can we set priority in mlfqs scheduling?
  ASSERT(!thread_mlfqs);

  struct thread *cur = thread_current();

  if (list_empty(&cur->hold_locks)) {
    cur->priority = new_priority;
  }
  else {
    if (cur->original_priority == -1) {
      cur->priority = new_priority;
    }
    else {
      cur->priority = cur->original_priority = new_priority;
      thread_update_priority(cur);
    }
  }

  enum intr_level old_level = intr_disable();
//  list_sort(&ready_list, cmp_priority, NULL);
  struct list_elem *found = list_find(&ready_list, &cur->elem);
  if (found != list_end(&ready_list)) {
    list_remove(found);
    list_insert_ordered(&ready_list, found, cmp_priority, NULL);
  }
  // Should we yield CPU here?
  struct thread *highest = NULL;
  if (!list_empty(&ready_list)) {
    highest = list_entry(list_front(&ready_list), struct thread, elem);
  }
  if (highest && highest->priority > cur->priority) {
    thread_yield();
  }
  intr_set_level(old_level);
}

/** Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  return thread_current ()->priority;
}

/** Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice UNUSED) 
{
  ASSERT (nice >= -20 && nice <= 20);

  struct thread *cur = thread_current();
  cur->nice = nice;
  int new_priority = calculate_priority(cur);
  struct thread *highest = get_highest_priority_thread();
  if (highest != NULL && highest->priority > cur->priority) {
    thread_yield();
  }
}

/** Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  return thread_current()->nice;
}

/** Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{
  Q14 times100 = q14_mul_i(load_avg, 100);
  return q14_to_i_nearest(times100);
}

/** Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) 
{
  Q14 recent_cpu = thread_current()->recent_cpu;
  Q14 times100 = q14_mul_i(recent_cpu, 100);
  return q14_to_i_nearest(times100);
}

int64_t get_soon_wakeup_tick(void)
{
  return soon_wakeup_tick;
}

void set_soon_wakeup_tick(int64_t wakeup_tick)
{
  soon_wakeup_tick = wakeup_tick;
}

static bool wakeup_tick_less(const struct list_elem *a,
                             const struct list_elem *b,
                             void *aux)
{
  int64_t wakeup_tick_a = list_entry(a, struct thread, sleep_elem)->wakeup_tick;
  int64_t wakeup_tick_b = list_entry(b, struct thread, sleep_elem)->wakeup_tick;
  if (wakeup_tick_a < wakeup_tick_b) {
    return true;
  }
  else {
    return false;
  }
}

void thread_sleep(int64_t wakeup_tick)
{
  /*
    If the current thread is not idle thread,
    change the state of the caller thread to BLOCKED,
    store the local ticks to wake up,
    update the global tick if neccessary,
    and call schedule().
    When manipulating thread list, disable interrupt!
  */
  struct thread *cur = thread_current();
  if (cur != idle_thread) {
    cur->wakeup_tick = wakeup_tick;
    int64_t min = get_soon_wakeup_tick();
    if (min == -1) {
      min = wakeup_tick;
    }
    else {
      min = (min < wakeup_tick) ? min : wakeup_tick;
    }
    set_soon_wakeup_tick(min);
    // Insert this thread into sleep_list.
    enum intr_level old_level = intr_disable();
    cur->status = THREAD_BLOCKED;
    list_insert_ordered(&sleep_list, &cur->sleep_elem, wakeup_tick_less, NULL);
    schedule();
    intr_set_level(old_level);
  }
}

/** Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/** Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /**< The scheduler runs with interrupts off. */
  function (aux);       /**< Execute the thread function. */
  thread_exit ();       /**< If function() returns, kill the thread. */
}

/** Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/** Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/** Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  enum intr_level old_level;

  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  t->priority = priority;
  t->magic = THREAD_MAGIC;
  list_init(&t->hold_locks);
  t->original_priority = -1;
  t->exit_status = -1;
  t->is_user_process = false;
  list_init(&t->childs);
  t->parent = NULL;
  t->is_waited = false;
  sema_init(&t->wait_exit_sema, 0);
  sema_init(&t->load_sema, 0);
  t->load_success = false;

  old_level = intr_disable ();
  list_push_back (&all_list, &t->allelem);
  intr_set_level (old_level);
}

/** Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/** Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  if (!thread_mlfqs) {
    if (list_empty (&ready_list))
      return idle_thread;
    else
      return list_entry (list_pop_front (&ready_list), struct thread, elem);
  }
  else {
    struct thread *highest = get_highest_priority_thread();
    if (highest == NULL) {
      return idle_thread;
    }
    else {
      ASSERT (highest != NULL);
      list_remove(&highest->elem);
      return highest;
    }
  }
}

/** Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/** Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule (void) 
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  thread_schedule_tail (prev);
}

/** Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/** Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);

/** Compare two elems' priority */
bool cmp_priority(const struct list_elem *a, const struct list_elem *b, void *aux)
{
  int priority_a = list_entry(a, struct thread, elem)->priority;
  int priority_b = list_entry(b, struct thread, elem)->priority;
  if (priority_a > priority_b) {
    return true;
  }
  else {
    return false;
  }
}

void thread_update_priority(struct thread *t)
{

  int old_priority = t->priority;
  int max_priority = thread_get_donor_priority(t);

  // We can't let t's priority lower than base_priority(original priority)
  int base_priority = (t->original_priority == -1) ? t->priority : t->original_priority;
  t->priority = (base_priority > max_priority) ? base_priority : max_priority;

  // We do update the priority.
  if (old_priority != t->priority) {
    if (t->original_priority == -1) {
      t->original_priority = old_priority;
    }
    if (t->wait_on_lock != NULL) {
      lock_update_priority(t->wait_on_lock);
    }
  }

  if (list_empty(&t->hold_locks)) {
    t->priority = (t->original_priority == -1) ? t->priority : t->original_priority;
    t->original_priority = -1;
  }

}

int thread_get_donor_priority(struct thread *t)
{
  if (list_empty(&t->hold_locks)) {
    return PRI_MIN;
  }
  else {
    struct lock *max_lock = list_entry(list_max(&t->hold_locks, cmp_lock_elem_priority, NULL), struct lock, lock_elem);
    return max_lock->max_priority;
  }
}

struct thread *get_highest_priority_thread()
{
  for (int i = PRI_MAX; i >= PRI_MIN; --i) {
    if (!list_empty(&mlfqs[i])) {
      return list_entry(list_front(&mlfqs[i]), struct thread, elem);
    }
  }
  return NULL;
}

int get_num_ready_threads()
{
  int num = 0;
  struct thread *t = NULL;
  struct list_elem *e = list_begin(&all_list);
  while (e != list_end(&all_list)) {
    t = list_entry(e, struct thread, allelem);
    if (t != idle_thread) {
      if (t->status == THREAD_READY || t->status == THREAD_RUNNING) {
        ++num;
      }
    }
    e = list_next(e);
  }
  return num;
}

static bool cmp_lock_elem_priority(const struct list_elem *a, const struct list_elem *b, void *aux)
{
  int priority_a = list_entry(a, struct lock, lock_elem)->max_priority;
  int priority_b = list_entry(b, struct lock, lock_elem)->max_priority;
  if (priority_a < priority_b) {
    return true;
  }
  else{
    return false;
  }
}

int calculate_priority(struct thread *t)
{
  ASSERT(t != NULL);

  Q14 four = i_to_q14(4);
  Q14 one_quarter = q14_div_q14(Q14_ONE, four);
  Q14 first_part = i_to_q14(PRI_MAX);
  Q14 second_part = q14_mul_q14(one_quarter, t->recent_cpu);
  int third_part = 2 * t->nice;
  Q14 first_step = q14_sub_q14(first_part, second_part);
  Q14 second_step = q14_sub_i(first_step, third_part);
  int priority = q14_to_i_nearest(second_step);
  if (priority < PRI_MIN) {
    priority = PRI_MIN;
  }
  if (priority > PRI_MAX) {
    priority = PRI_MAX;
  }
  return priority;
}


Q14 calculate_load_avg()
{
  Q14 fifty_nine = i_to_q14(59);
  Q14 sixty = i_to_q14(60);
  Q14 coeff_1 = q14_div_q14(fifty_nine, sixty);
  Q14 coeff_2 = q14_div_q14(Q14_ONE, sixty);
  Q14 first_part = q14_mul_q14(coeff_1, load_avg);
  int ready_threads = get_num_ready_threads();
  Q14 second_part = q14_mul_i(coeff_2, ready_threads);
  return q14_add_q14(first_part, second_part);
}

Q14 calculate_recent_cpu(struct thread *t)
{
  ASSERT (t != NULL);

  Q14 two_times_load_avg = q14_mul_i(load_avg, 2);
  Q14 two_times_load_avg_plus_one = q14_add_i(two_times_load_avg, 1);
  Q14 first_step = q14_div_q14(two_times_load_avg, two_times_load_avg_plus_one);
  Q14 second_step = q14_mul_q14(first_step, t->recent_cpu);
  Q14 third_step = q14_add_i(second_step, t->nice);
  return third_step;
}

void increase_recent_cpu(struct thread *t)
{
  ASSERT (t != NULL);

  if (t == idle_thread) {
    return;
  }
  Q14 old_recent_cpu = t->recent_cpu;
  Q14 new_recent_cpu = q14_add_i(old_recent_cpu, 1);
  t->recent_cpu = new_recent_cpu;
}

void update_priority_all()
{
  ASSERT (intr_get_level() == INTR_OFF);

// Note that after reset a thread's priority, we have to put the thread into
// the right queue if the priority changed.
  struct list_elem *e = list_begin(&all_list);
  struct thread *t = NULL;
  while (e != list_end(&all_list)) {
    t = list_entry(e, struct thread, allelem);
    if (t != idle_thread) {
      int old_prioroity = t->priority;
      t->priority = calculate_priority(t);
      if (t->priority != old_prioroity && t->status == THREAD_READY) {
        list_remove(&t->elem);
        list_push_back(&mlfqs[t->priority], &t->elem);
      }
    }
    e = list_next(e);
  }
}

void update_recent_cpu_all()
{
  ASSERT (intr_get_level() == INTR_OFF);

  struct list_elem *e = list_begin(&all_list);
  struct thread *t = NULL;
  while (e != list_end(&all_list)) {
    t = list_entry(e, struct thread, allelem);
    if (t != idle_thread) {
      t->recent_cpu = calculate_recent_cpu(t);
    }
    e = list_next(e);
  }
}

unsigned process_info_hash(const struct hash_elem *e, void *aux UNUSED)
{

   const struct process_info *process_info = hash_entry(e, struct process_info, process_info_elem);
   return hash_int(process_info->self_tid);
}

bool process_info_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
   const struct process_info *info_a = hash_entry(a, struct process_info, process_info_elem);
   const struct process_info *info_b = hash_entry(b, struct process_info, process_info_elem);
   return info_a->self_tid < info_b->self_tid;
}

struct thread *get_child_by_tid(child_tid)
{
  struct list_elem *e;
  struct thread *cur = thread_current();
  for (e = list_begin(&cur->childs); e != list_end(&cur->childs); e = list_next(e)) {
    struct thread *child = list_entry(e, struct thread, child_elem);
    if (child->tid == child_tid) {
      return child;
    }
  }
  return NULL;
}