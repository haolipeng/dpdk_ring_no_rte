cmake_minimum_required(VERSION 3.16)
project(dpdk_ring_no_rte C)

set(CMAKE_C_STANDARD 11)

add_executable(dpdk_ring_no_rte main.c rte_ring.c rte_ring.h rte_ring_c11_mem.h rte_ring_generic.h common.h branch_prediction.h)
