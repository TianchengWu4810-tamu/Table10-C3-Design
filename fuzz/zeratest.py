import angr
from angr import sim_options as so
import claripy
import time
import timeout_decorator
import IPython
import logging

logging.getLogger("pwnlib.elf.elf").disabled = True
log = logging.getLogger(__name__)
is_printable = False

def overflow_detect_filter(simgr):

    for state in simgr.active:
        if state.globals.get("type", None) == "overflow_variable":
            log.info("Found vulnerable state. Overflow variable to win")
            user_input = state.globals["user_input"]
            input_bytes = state.solver.eval(user_input, cast_to=bytes)
            log.info("[+] Vulnerable path found {}".format(input_bytes))
            state.globals["type"] = "overflow_variable"
            state.globals["input"] = input_bytes
            simgr.stashes["found"].append(state)
            simgr.stashes["active"].remove(state)
            return simgr

    for state in simgr.unconstrained:
        bits = state.arch.bits
        num_count = bits / 8
        pc_value = b"C" * int(num_count)

        # Check satisfiability
        if state.solver.satisfiable(extra_constraints=[state.regs.pc == pc_value]):

            state.add_constraints(state.regs.pc == pc_value)
            user_input = state.globals["user_input"]

            log.info("Found vulnerable state.")

            if is_printable:
                log.info("Constraining input to be printable")
                for c in user_input.chop(8):
                    constraint = claripy.And(c > 0x2F, c < 0x7F)
                    if state.solver.satisfiable([constraint]):
                        state.add_constraints(constraint)

            # Get input values
            input_bytes = state.solver.eval(user_input, cast_to=bytes)
            log.info("[+] Vulnerable path found {}".format(input_bytes))
            if b"CCCC" in input_bytes:
                log.info("[+] Offset to bytes : {}".format(input_bytes.index(b"CCCC")))
            state.globals["type"] = "Overflow"
            state.globals["input"] = input_bytes
            simgr.stashes["found"].append(state)
            simgr.stashes["unconstrained"].remove(state)
            break

    return simgr

def checkOverflow(binary_name, inputType="STDIN"):

    p = angr.Project(binary_name, load_options={"auto_load_libs": False})
    argv = [binary_name]
    input_arg = claripy.BVS("input", 300 * 8)
    
    if inputType == "STDIN":
        state = p.factory.full_init_state(args=argv, stdin=input_arg)
        state.globals["user_input"] = input_arg
    elif inputType == "LIBPWNABLE":
        handle_connection = p.loader.main_object.get_symbol("handle_connection")
        state = p.factory.entry_state(
            addr=handle_connection.rebased_addr, stdin=input_arg, add_options=extras
        )
        state.globals["user_input"] = input_arg
    else:
        argv.append(input_arg)
        state = p.factory.full_init_state(args=argv)
        state.globals["user_input"] = input_arg

    state.libc.buf_symbolic_bytes = 0x100
    state.globals["inputType"] = inputType
    simgr = p.factory.simgr(state, save_unconstrained=True)

    run_environ = {}
    run_environ["type"] = None
    end_state = None
    # Lame way to do a timeout
    try:

        @timeout_decorator.timeout(120)
        def exploreBinary(simgr):
            simgr.explore(
                find=lambda s: "type" in s.globals, step_func=overflow_detect_filter
            )

        exploreBinary(simgr)
        if "found" in simgr.stashes and len(simgr.found):
            end_state = simgr.found[0]
            run_environ["type"] = end_state.globals["type"]

    except (KeyboardInterrupt, timeout_decorator.TimeoutError) as e:
        log.info("[~] Keyboard Interrupt")

    if "input" in run_environ.keys() or run_environ["type"] == "overflow_variable":
        run_environ["input"] = end_state.globals["input"]
        log.info("[+] Triggerable with input : {}".format(end_state.globals["input"]))
    return run_environ