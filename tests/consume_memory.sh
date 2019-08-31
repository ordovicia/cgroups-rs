#!/bin/bash

# used in v1::memory::tests::test_subsystem_stat_throttled

sleep 1

ary=()
for _i in $(seq $1); do
    ary+=(0)
    # echo ${#ary[@]}
done
