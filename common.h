//
// Created by root on 23-3-5.
//

#ifndef DPDK_RING_NO_RTE_COMMON_H
#define DPDK_RING_NO_RTE_COMMON_H

#include "branch_prediction.h"
#define __rte_always_inline inline __attribute__((always_inline))
#define RTE_SET_USED(x) (void)(x)
/**
 * Compiler barrier.
 *
 * Guarantees that operation reordering does not occur at compile time
 * for operations directly before and after the barrier.
 */
#define	rte_compiler_barrier() do {		\
	asm volatile ("" : : : "memory");	\
} while(0)

#define rte_smp_wmb() rte_compiler_barrier()
#define rte_smp_rmb() rte_compiler_barrier()
#endif//DPDK_RING_NO_RTE_COMMON_H
