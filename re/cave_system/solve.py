#!/usr/bin/env python

import angr
import claripy

success_addr = 0x101ab3
failure_addr = 0x101ac1
base_addr = 0x100000

project = angr.Project("./cave", main_opts = {"base_addr" : base_addr})

state = project.factory.entry_state()
simgr = project.factory.simulation_manager(state)

simgr.explore(find=success_addr, avoid=failure_addr)

if len(simgr.found) > 0:
    for found in simgr.found:
        print(found.posix.dumps(0))
