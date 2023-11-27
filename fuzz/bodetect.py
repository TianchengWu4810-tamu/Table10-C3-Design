import angr, argparse, IPython

def check_mem_corruption(simgr):
    if len(simgr.unconstrained):
        for path in simgr.unconstrained:
            if path.satisfiable(extra_constraints=[path.regs.pc == b"CCCC"]):
                path.add_constraints(path.regs.pc == b"CCCC")
                if path.satisfiable():
                    simgr.stashes['mem_corrupt'].append(path)
                simgr.stashes['unconstrained'].remove(path)
                simgr.drop(stash='active')
    return simgr

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("Binary")
    parser.add_argument("Start_Addr", type=int)

    args = parser.parse_args()

    p = angr.Project(args.Binary)
    state = p.factory.blank_state(addr=args.Start_Addr)
    
    simgr = p.factory.simgr(state, save_unconstrained=True)
    simgr.stashes['mem_corrupt']  = []
    
    simgr.explore(step_func=check_mem_corruption)

    IPython.embed()
    
if __name__ == "__main__":
    main()
