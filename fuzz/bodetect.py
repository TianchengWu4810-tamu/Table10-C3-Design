import angr, argparse, IPython

import angr, argparse, IPython

def check_mem_corruption(simgr):
    corruption_detected = False

    if len(simgr.unconstrained):
        for path in simgr.unconstrained:
            if path.satisfiable(extra_constraints=[path.regs.pc == b"CCCC"]):
                path.add_constraints(path.regs.pc == b"CCCC")
                if path.satisfiable():
                    simgr.stashes['mem_corrupt'].append(path)
                    corruption_detected = True
                simgr.stashes['unconstrained'].remove(path)
        simgr.drop(stash='active')

    if corruption_detected:
        print("Memory corruption detected!")
    else:
        print("No memory corruption detected in this step.")

    return simgr

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("Binary")
    parser.add_argument("Start_Addr", type=int)

    args = parser.parse_args()

    p = angr.Project(args.Binary)
    state = p.factory.blank_state(addr=args.Start_Addr)
    
    simgr = p.factory.simgr(state, save_unconstrained=True)
    simgr.stashes['mem_corrupt'] = []
    
    while len(simgr.active) > 0:
        simgr.step(step_func=check_mem_corruption)

    if len(simgr.mem_corrupt) > 0:
        print("Memory corruption detected in the binary.")
    else:
        print("No memory corruption found in the binary.")

    IPython.embed()

if __name__ == "__main__":
    main()


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
