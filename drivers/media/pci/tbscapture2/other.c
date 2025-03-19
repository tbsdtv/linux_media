#include <linux/pci.h>
#include "tbs_pcie-reg.h"
#include "tbs_pcie.h"
void *malloc(size_t __size);
void *malloc(size_t __size)
{
    return kzalloc(__size, GFP_KERNEL);
}
void free(void *__ptr);
void free(void *__ptr)
{
    if(__ptr)
        kfree(__ptr);
}

