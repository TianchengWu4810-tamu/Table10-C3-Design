import angr, argparse, IPython

def check_mem_corruption(simgr):
    # if len(simgr.unconstrained):
    #     for path in simgr.unconstrained:
    #         if path.satisfiable(extra_constraints=[path.regs.pc == b"CCCC"]):
    #             path.add_constraints(path.regs.pc == b"CCCC")
    #             if path.satisfiable():
    #                 simgr.stashes['mem_corrupt'].append(path)
    #             simgr.stashes['unconstrained'].remove(path)
    #             simgr.drop(stash='active')
    # return simgr
    for path in simgr.unconstrained:  
            state = path.state 
            eip = state.regs.pc   
            bits = state.arch.bits 
            state_copy = state.copy()
            #Constrain pc to 0x41414141 or 0x41414141414141 
            constraints = []
            for i in range(bits / 8):    
                curr_byte = eip.get_byte(i)
                constraint = claripy.And(curr_byte == 0x41)
                constraints.append(constraint)

            if state_copy.se.satisfiable(extra_constraints=constraints):
                for constraint in constraints:
                    state_copy.add_constraints(constraint)
    stdin = state.posix.files[0]
    constraints = []
    stdin_size = 300
    stdin.length = stdin_size
    stdin.seek(0)
    stdin_bytes = stdin.all_bytes()
    for i in range(stdin_size):
        curr_byte = stdin.read_from(1)
        constraint = claripy.And(curr_byte > 0x2F, curr_byte < 0x7F)
        if state.se.satisfiable(extra_constraints=[constraint]):  
            constraints.append(constraint)
    stdin_str = repr(str(state.posix.dumps(0).replace('\x00','').replace('\x01','')))
    print("[+] Vulnerable path found {}".format(stdin_str))
    simgr.stashes['found'].append(path) 
    simgr.stashes['unconstrained'].remove(path)    
    return simgr

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("Binary")
    parser.add_argument("Start_Addr", type=int)

    args = parser.parse_args()

    p = angr.Project(args.Binary, load_options={"auto_load_libs": False})
    state = p.factory.blank_state(addr=args.Start_Addr)
    
    simgr = p.factory.simgr(state, save_unconstrained=True)
    simgr.stashes['mem_corrupt']  = []
    
    simgr.explore(step_func=check_mem_corruption)

    IPython.embed()
    
if __name__ == "__main__":
    main()
