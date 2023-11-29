import angr, argparse, IPython
bitness = 0

def check_mem_corruption(simgr):
# def check_mem_corruption(simgr, function_mapping):
    corruption_detected = False
    num_count = (bitness / 8)
    pc_text = b"C" * int(num_count)
    

    if len(simgr.unconstrained):
        for path in simgr.unconstrained:
            if path.satisfiable(extra_constraints=[path.regs.pc == pc_text]):
                path.add_constraints(path.regs.pc == pc_text)
                if path.satisfiable():
                    # corrupted_function = get_function_name(function_mapping, path.addr)
                    # print(f"Memory corruption detected in function: {corrupted_function}")
                    simgr.stashes['mem_corrupt'].append(path)
                    corruption_detected = True
                simgr.stashes['unconstrained'].remove(path)
        simgr.drop(stash='active')

    if corruption_detected:
        print("Memory corruption detected!")
    # else:
    #     print("No memory corruption detected in this step.")

    return simgr

# def get_function_name(function_mapping, addr):
#     for function_addr, function_name in function_mapping.items():
#         if function_addr <= addr < function_mapping.get(function_name, function_addr):
#             return function_name
#     return "Unknown"

def main():
    global bitness
    parser = argparse.ArgumentParser()

    parser.add_argument("Binary")
    # start_addr = 0x00405008
    args = parser.parse_args()

    p = angr.Project(args.Binary)

    arch_info = p.arch
    print(arch_info)
    bitness = p.arch.bits
    print(f"The binary is {bitness}-bit.")

    # cfg = p.analyses.CFGFast()
    # function_mapping = {f.addr: f.name for f in cfg.kb.functions.values()}

    state = p.factory.entry_state()
    # state = p.factory.blank_state(addr=start_addr)
    # state = p.factory.call_state(addr=start_addr)
    # state = p.factory.full_init_state(addr=start_addr)

    print("Test line:")
    print(state.addr)
    
    simgr = p.factory.simgr(state, save_unconstrained=True)
    simgr.stashes['mem_corrupt'] = []
    
    simgr.explore(step_func=lambda simgr: check_mem_corruption(simgr))
    # simgr.explore(step_func=lambda simgr: check_mem_corruption(simgr, function_mapping))

    if len(simgr.mem_corrupt) > 0:
        print("Memory corruption detected in the binary.")
    else:
        print("No memory corruption found in the binary.")

    IPython.embed()

if __name__ == "__main__":
    main()

