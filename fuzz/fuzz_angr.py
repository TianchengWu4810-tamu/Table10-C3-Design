import angr
import claripy

def main():
    project = angr.Project('bo', load_options={'auto_load_libs': False})

    buffer_size = 10  # More than the size of the buffer in vulnerable_function
    input_buffer = claripy.BVS('input_buffer', buffer_size * 8)

    # Find the address of the vulnerable_function
    vulnerable_function_addr = project.loader.find_symbol('vulnerable_function').rebased_addr

    # Prepare the state at the beginning of vulnerable_function
    state = project.factory.call_state(vulnerable_function_addr, input_buffer)

    simgr = project.factory.simgr(state)

    # Define a custom function to check for buffer overflow
    def is_overflow(state):
        # Check if the return address on the stack has become symbolic
        # and is different from the expected return address
        stack_pointer = state.regs.sp
        ret_addr = state.memory.load(stack_pointer, project.arch.bytes)

        # Obtain the expected return address (e.g., the address following the call to vulnerable_function)
        # You might need to adjust this address based on your specific binary
        expected_ret_addr = 0x0010119b  # Replace 0xADDRESS with the actual address

        return state.solver.symbolic(ret_addr) and state.solver.eval(ret_addr) != expected_ret_addr

    # Explore the binary using the custom overflow detection function
    simgr.explore(find=is_overflow)

    if simgr.found:
        found_state = simgr.found[0]
        solution = found_state.solver.eval(input_buffer, cast_to=bytes)
        print("Found a crashing input:", solution)
    else:
        print("No crashing input found.")

if __name__ == "__main__":
    main()
