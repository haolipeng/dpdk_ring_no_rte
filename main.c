//
// Created by guozh on 2018/1/31.
//
#include "rte_ring.h"
#include <assert.h>
int main(int argc,char *argv[])
{
    struct rte_ring *r = rte_ring_create("test",4096, 0);
    assert(rte_ring_empty(r));
    for(int i = 0; i < 4095; i++)
    {
        assert(rte_ring_enqueue(r, malloc(512)) == 0);
    }
    assert(rte_ring_full(r));
    void *p;
    for(int i = 0; i < 4095; i++)
    {
        assert(rte_ring_dequeue(r, &p) == 0);
        free(p);
    }
    assert(rte_ring_empty(r));
    rte_ring_free(r);
}