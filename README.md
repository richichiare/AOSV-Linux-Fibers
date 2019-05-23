# Advanced Operating Systems & Virtualization - Final Project 2018
Linux Fibers. Authors: Matteo Mariani (1815188) &amp; Riccardo Chiaretti (16611390).

The following report discusses about the implementation of Kernel-level fibers into Linux OS. The concept
of fiber was born in Windows OS where they are already implemented as lightweight User-level threads.

In order to accomplish our goal and provide the required functionalities, we can follow two strategies:
-implement a set of system calls that encapsulate the needed services and recompile the kernel to have
a default and dedicated subsystem;
- write a loadable kernel module (LKM) that wraps up the necessary operations without the need to
recompile the kernel. This strategy needs a way to interface the module with the User-space - using
ioctl() system call.

There are two version of the code:

1. *code_slower* folder: it contains a less performant version of the module. Here only two are are fundamental data      structures: *Processes* and *Fibers*. (Keep in mind that refactoring has not been done)
    - each thread using fiber system is one entry of *Process*
    - each thread in the *Processes* entry has a *Fibers* hasmap

2. *code* folder: it contains the most performant version of the module. Here, the whole logic is based on three fundamental data structures: *Processes*, *Threads* and *Fibers*. (Refactoring has been done correctly)
    - each *Processes* entry is identified by the TID
    - each TID has a list *Threads* of threads sharing that same TID
    - each process has a list *Fibers* of fibers created by threads having that TID 

For more information about the implementation and the usage, look at the pdf file *aosv_report.pdf*.
