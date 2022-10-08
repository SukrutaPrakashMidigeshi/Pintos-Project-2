#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/synch.h"


struct child_element* get_child(tid_t tid,struct list *mylist);
void fd_init(struct fd_element *file_d, int fd_, struct file *myfile_);
static void syscall_handler (struct intr_frame *);
struct fd_element* get_fd(int fd);
int write (int fd, const void *buffer_, unsigned size);
int wait (tid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
tid_t exec (const char *cmdline);
void exit (int status);
void argsget_3(struct intr_frame *f, int choose, void *args);
void argsget_2(struct intr_frame *f, int choose, void *args);
void argsget_1(struct intr_frame *f, int choose, void *args);

/* checks if the pointer is valid */ 
void check_ptr (const void *pointer)
{
    if (!is_user_vaddr(pointer))
    {
        exit(-1);
    }

    void *check = pagedir_get_page(thread_current()->pagedir, pointer);
    if (check == NULL)
    {
        exit(-1);
    }
}

/* initialising the system calls */ 
void
syscall_init (void)
{
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&lock_file);
}


void argsget_1(struct intr_frame *f, int choose, void *args)
{
    int argv = *((int*) args);
    args += 4;

    if (choose == SYS_EXIT)
    {
        exit(argv);
    }
    else if (choose == SYS_EXEC)
    {
        check_ptr((const void*) argv);
        f -> eax = exec((const char *)argv);
    }
    else if (choose == SYS_WAIT)
    {
        f -> eax = wait(argv);
    }
    else if (choose == SYS_REMOVE)
    {
        check_ptr((const void*) argv);
        f -> eax = remove((const char *) argv);
    }
    else if(choose == SYS_OPEN)
    {
        check_ptr((const void*) argv);
        f -> eax = open((const char *) argv);
    }
    else if (choose == SYS_FILESIZE)
    {
        f -> eax = filesize(argv);
    }
    else if (choose == SYS_TELL)
    {
        f -> eax = tell(argv);
    }
    else if (choose == SYS_TELL)
    {
        close(argv);
    }
}

void argsget_2(struct intr_frame *f, int choose, void *args)
{
    int argv = *((int*) args);
    args += 4;
    int argv_1 = *((int*) args);
    args += 4;

    if (choose == SYS_CREATE)
    {
        check_ptr((const void*) argv);
        f -> eax = create((const char *) argv, (unsigned) argv_1);
    }
    else if(choose == SYS_SEEK)
    {
        seek(argv, (unsigned)argv_1);
    }
}


void argsget_3 (struct intr_frame *f, int choose, void *args)
{
    int argv = *((int*) args);
    args += 4;
    int argv_1 = *((int*) args);
    args += 4;
    int argv_2 = *((int*) args);
    args += 4;

    check_ptr((const void*) argv_1);
    void * temp = ((void*) argv_1)+ argv_2 ;
    check_ptr((const void*) temp);
    if (choose == SYS_WRITE)
    {
        f->eax = write (argv,(void *) argv_1,(unsigned) argv_2);
    }
    else f->eax = read (argv,(void *) argv_1, (unsigned) argv_2);
}

/* executing all the system calls */ 
static void
syscall_handler (struct intr_frame *f )
{
    int syscall_number = 0;
    check_ptr((const void*) f -> esp);
    void *args = f -> esp;
    syscall_number = *( (int *) f -> esp);
    args+=4;
    check_ptr((const void*) args);
    switch(syscall_number)
    {
    case SYS_HALT:                  	/* Halt the operating system. */
        halt();
        break;
    case SYS_EXIT:                   /* Terminate this process. */
        argsget_1(f, SYS_EXIT,args);
        break;
    case SYS_EXEC:                   /* Start another process. */
        argsget_1(f, SYS_EXEC,args);
        break;
    case SYS_WAIT:                   /* Wait till a child process to die. */
        argsget_1(f, SYS_WAIT,args);
        break;
    case SYS_CREATE:                 /* Create a file. */
        argsget_2(f, SYS_CREATE,args);
        break;
    case SYS_REMOVE:                 /* Delete a file. */
        argsget_1(f, SYS_REMOVE,args);
        break;
    case SYS_OPEN:                   /* Open a file. */
        argsget_1(f, SYS_OPEN,args);
        break;
    case SYS_FILESIZE:               /* Obtain a file's size. */
        argsget_1(f, SYS_FILESIZE,args);
        break;
    case SYS_READ:                   /* Read from a file. */
        argsget_3(f, SYS_READ,args);
        break;
    case SYS_WRITE:                  /* Write into a file. */
        argsget_3(f, SYS_WRITE,args);
        break;
    case SYS_SEEK:                   /* change the current position in a file. */
        argsget_2(f, SYS_SEEK,args);
        break;
    case SYS_TELL:                   /* give out the current position in a file. */
        argsget_1(f, SYS_TELL,args);
        break;
    case SYS_CLOSE:                  /* To close an existing file*/
        argsget_1(f, SYS_CLOSE,args);
        break;
    default:
        exit(-1);
        break;
    }
}

/* executing the halt command */
void halt (void)
{
    shutdown_power_off();
}

/* executing the exit command */
void exit (int status)
{
    struct thread *cur = thread_current();
    printf ("%s: exit(%d)\n", cur -> name, status);

    /* setting the thread as a child */
    struct child_element *child = get_child(cur->tid, &cur -> parent -> child_list);

    /* setting the threads status */
    child -> exit_status = status;

    /* marking the current status */ 
    if (status == -1)
    {
        child -> cur_status = WAS_KILLED;
    }
    else
    {
        child -> cur_status = HAD_EXITED;
    }

    thread_exit();
}

/* executing the exec command */
tid_t
exec (const char *cmd_line)
{
    struct thread* parent = thread_current();
    tid_t pid = -1;
    /* creating a child process inorder to execute the command */ 
    pid = process_execute(cmd_line);

    /* get the created child */
    struct child_element *child = get_child(pid,&parent -> child_list);
    
    /* putting the child to sleep until load is complete */ 
    sema_down(&child-> real_child -> sema_exec);

    /* check if load was successful */ 
    if(!child -> loaded_success)
    {
        /* failed to load */ 
        return -1;
    }
    return pid;
}

/* executing the wait command */
int wait (tid_t pid)
{
    return process_wait(pid);
}


bool create (const char *file, unsigned initial_size)
{
    lock_acquire(&lock_file);
    bool ret = filesys_create(file, initial_size);
    lock_release(&lock_file);
    return ret;
}

bool remove (const char *file)
{
    lock_acquire(&lock_file);
    bool ret = filesys_remove(file);
    lock_release(&lock_file);
    return ret;
}

int open (const char *file)
{
    int ret = -1;
    lock_acquire(&lock_file);
    struct thread *cur = thread_current ();
    struct file * opened_file = filesys_open(file);
    lock_release(&lock_file);
    if(opened_file != NULL)
    {
        cur->fd_size = cur->fd_size + 1;
        ret = cur->fd_size;
        /* create and initilaise new fd_element*/
        struct fd_element *file_d = (struct fd_element*) malloc(sizeof(struct fd_element));
        file_d->fd = ret;
        file_d->myfile = opened_file;

        /* add the fd_element to the thread's fd_list */ 
        list_push_back(&cur->fd_list, &file_d->element);
    }
    return ret;
}

/* finding the files size */ 
int filesize (int fd)
{
    struct file *myfile = get_fd(fd)->myfile;
    lock_acquire(&lock_file);
    int ret = file_length(myfile);
    lock_release(&lock_file);
    return ret;
}

/* executing the read command */
int read (int fd, void *buffer, unsigned size)
{
    int ret = -1;

    /* deciding where to read from */ 
    if(fd == 0)
    {
        /* reading from the keyboard */
        ret = input_getc();
    }
    else if(fd > 0)
    {
        /* reading from the file and getting the fd_element*/
        struct fd_element *fd_elem = get_fd(fd);
        if(fd_elem == NULL || buffer == NULL)
        {
            return -1;
        }

        /* fetching the file */ 
        struct file *myfile = fd_elem->myfile;
        lock_acquire(&lock_file);
        ret = file_read(myfile, buffer, size);
        lock_release(&lock_file);
        if(ret < (int)size && ret != 0)
        {
            /* error handling */ 
            ret = -1;
        }
    }
    return ret;
}
/* executing the write command */
int write (int fd, const void *buffer_, unsigned size)
{
    uint8_t * buffer = (uint8_t *) buffer_;
    int ret = -1;
    if (fd == 1)
    {
        /* writing into the consol */ 
        putbuf( (char *)buffer, size);
        return (int)size;
    }
    else
    {
        /*  write into the file and get the fd_element */ 
        struct fd_element *fd_elem = get_fd(fd);
        if(fd_elem == NULL || buffer_ == NULL )
        {
            return -1;
        }
        /* fetch the file */ 
        struct file *myfile = fd_elem->myfile;
        lock_acquire(&lock_file);
        ret = file_write(myfile, buffer_, size);
        lock_release(&lock_file);
    }
    return ret;
}

/* executing the seek command */
void seek (int fd, unsigned position)
{
    struct fd_element *fd_elem = get_fd(fd);
    if(fd_elem == NULL)
    {
        return;
    }
    struct file *myfile = fd_elem->myfile;
    lock_acquire(&lock_file);
    file_seek(myfile,position);
    lock_release(&lock_file);
}

unsigned tell (int fd)
{
    struct fd_element *fd_elem = get_fd(fd);
    if(fd_elem == NULL)
    {
        return -1;
    }
    struct file *myfile = fd_elem->myfile;
    lock_acquire(&lock_file);
    unsigned ret = file_tell(myfile);
    lock_release(&lock_file);
    return ret;
}

void close (int fd)
{
    struct fd_element *fd_elem = get_fd(fd);
    if(fd_elem == NULL)
    {
        return;
    }
    struct file *myfile = fd_elem->myfile;
    lock_acquire(&lock_file);
    file_close(myfile);
    lock_release(&lock_file);
}

/* close and free all file the current thread posseses */
void close_all(struct list *fd_list)
{
    struct list_elem *e;
    while(!list_empty(fd_list))
    {
        e = list_pop_front(fd_list);
        struct fd_element *fd_elem = list_entry (e, struct fd_element, element);
        file_close(fd_elem->myfile);
        list_remove(e);
        free(fd_elem);
    }
}

/* iterate on the fd_list of the current thread and get the file which has the same fd, if the file is not found return NULL */
struct fd_element*
get_fd(int fd)
{
    struct list_elem *e;
    for (e = list_begin (&thread_current()->fd_list); e != list_end (&thread_current()->fd_list);
            e = list_next (e))
    {
        struct fd_element *fd_elem = list_entry (e, struct fd_element, element);
        if(fd_elem->fd == fd)
        {
            return fd_elem;
        }
    }
    return NULL;
}


/* intrate on mylist and return the child with the given tid */
struct child_element*
get_child(tid_t tid, struct list *mylist)
{
    struct list_elem* e;
    for (e = list_begin (mylist); e != list_end (mylist); e = list_next (e))
    {
        struct child_element *child = list_entry (e, struct child_element, child_elem);
        if(child -> child_pid == tid)
        {
            return child;
        }
    }
}
