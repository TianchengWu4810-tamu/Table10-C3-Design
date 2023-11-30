import angr, argparse
import claripy
import ghidra
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import ghidra.program.flatapi
import os
import csv

##### USER SETTINGS

#"fuzz" for fuzz testing a function, "bo" for identifying buffer overflow
mode = "fuzz" 
#set name of function to fuzz test
fuzz_func = "main"

#####

bitness = 0
location = ""

def check_mem_corruption(simgr):
# def check_mem_corruption(simgr, funcs):
    corruption_detected = False
    num_count = (bitness / 8)
    pc_text = b"C" * int(num_count)

    if len(simgr.unconstrained):
        for path in simgr.unconstrained:
            # print(path.regs.rip)
            if path.satisfiable(extra_constraints=[path.regs.pc == pc_text]):
                path.add_constraints(path.regs.pc == pc_text)
                if path.satisfiable():
                    # corrupted_function = get_function_name(funcs, before_corrupt_addr)
                    # print(f"Memory corruption detected in function: {corrupted_function}")
                    simgr.stashes['mem_corrupt'].append(path)
                    corruption_detected = True
                simgr.stashes['unconstrained'].remove(path)
        simgr.drop(stash='active')

    # if corruption_detected:
    #     print("Memory corruption detected!")
    # else:
    #     print("No memory corruption detected in this step.")

    return simgr

def get_function_name(funcs, addr):
    # print("addr: ")
    # print (addr)
    
    for func in funcs:
        entry_point = int ("0x"+func.getEntryPoint().toString(),16)
        end_point = int ("0x"+func.getBody().getMaxAddress().toString(),16)
        # print("//////entry_point:///////")
        # print(entry_point)
        # print("//////end_point:///////")
        # print(end_point)
        if (entry_point <= addr) and (addr < end_point):
            # print(func.getName())
            return func.getName()
    return "Unknown"

	
#Reads CSV file with list of functions:
def read_functs(file_path):
	data = []
	
	with open(file_path, newline='') as csvfile:
		csv_reader = csv.DictReader(csvfile)
		
		for row in csv_reader:
			data.append(row)
			
	return data	

#For each step of the exploration, verify conditions:
def fuzz_check(simgr):
	if (simgr.found):
		print(simgr.found[0].regs.rax)
		if (simgr.found[0].regs.rax): #if function returns true
			return True
	return False

#Fuzzing each function to get desired output:
def fuzz(start_addr, end_addr, path):
    p = angr.Project(path)
    #input buffer to fuzz the input parameter of the function:

    input_length = 50
    input_buffer = claripy.BVS('input_buffer', 8*input_length)

    state = p.factory.call_state(addr=start_addr, stdin=input_buffer)

    for i in range(input_length):
        state.add_constraints(input_buffer.get_byte(i) >= 0x20)  # ASCII printable characters
        state.add_constraints(input_buffer.get_byte(i) <= 0x7E)  # ASCII printable characters
	
    simgr = p.factory.simulation_manager(state)
	
    #explore each state within the function:
    simgr.explore(find=end_addr, step_func=fuzz_check)
	
	#print out results of the fuzzing simulation:
    print(simgr)
    if len(simgr.errored) > 0:
        print("error")
		
    if len(simgr.found) > 0:
        print("found")
        print("input: ", simgr.found[0].posix.dumps(0))

def main():
    csv_values = []
    ghidraState = getState()
    currentProgram = ghidraState.getCurrentProgram()
    name = currentProgram.getName()
    global location
    location = currentProgram.getExecutablePath()
	
    csv_values.append(["The currently loaded program is: '{}'".format(name)])
    csv_values.append(["Its location on disk is: '{}'".format(location)])
    # print("The currently loaded program is: '{}'".format(name))
    # print("Its location on disk is: '{}'".format(location))
    options = DecompileOptions()
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(currentProgram)

    fm = currentProgram.getFunctionManager()
    funcs = fm.getFunctions(True)
    
    fuzzstart = 0
    fuzzend = 0
    csv_values.append(['Function Name', 'Start Address', 'End Address', 'Parameters', 'Return Type'])
    for func in funcs:
        if func.getName() == fuzz_func:
            fuzzstart = int ("0x"+func.getEntryPoint().toString(),16)
            fuzzend = int ("0x"+func.getBody().getMaxAddress().toString(),16)
        entry_point = func.getEntryPoint()
        end_point = func.getBody().getMaxAddress()
        parameters = '|'.join(str(param.getDataType()) for param in func.getParameters())
        return_type_obj = func.getReturnType()
        return_type = str(return_type_obj) if return_type_obj else None
        func_list = [
            str(func.getName()),
            str(entry_point),
            str(end_point),
            str(parameters),
            str(return_type)
        ]
        csv_values.append(func_list)
        
        # csv_writer.writerow(func_list)
    #Specifying CSV file path
    csv_file_path = os.path.join(os.path.dirname(location), 'output.csv')
    
    
    #     print("Function: {} @ 0x{}".format(func.getName(), entry_point))
    #     print(func.getParameters())
    #     print("Return type: {}".format(func.getReturnType()))
    #     print(func.getName())
    #     if func.getName() == "main":
    #         mainAdress = entry_point
    #     newDict = {
    #         "name": func.getName(),
    #         "address": entry_point,
    #         "parameters": func.getParameters(),
    #         "return type": func.getReturnType(),
    #     }
    #     funcDicts.append(newDict)

    # parser = argparse.ArgumentParser()
    # parser.add_argument("Binary")
    # args = parser.parse_args()
    
    global bitness
    # start_addr = mainAdress
	
	
    if (mode == 'fuzz'):		
        fuzz(fuzzstart, fuzzend, location)
    elif(mode == "bo"):
        p = angr.Project(location)
        arch_info = p.arch
        print(arch_info)
        bitness = p.arch.bits
        print(f"The binary is {bitness}-bit.")

        state = p.factory.entry_state() 
        # state = p.factory.blank_state(addr=start_addr)
		# print("Test line:")
		# print(state.addr)
		
        simgr = p.factory.simgr(state, save_unconstrained=True)
        simgr.stashes['mem_corrupt'] = []
		
        simgr.explore(step_func=lambda simgr: check_mem_corruption(simgr))
		# simgr.explore(step_func=lambda simgr: check_mem_corruption(simgr, funcs))

        if len(simgr.mem_corrupt) > 0:
            print("Memory corruption detected.")
            path = simgr.mem_corrupt[0]
            history = path.history.parents
            history_elements = []
            for h_element in history:
                history_elements.append(h_element)
            for h_element in reversed(history_elements):
                function_name = get_function_name(funcs, h_element.addr) 
                if function_name != "Unknown":
                    toprint = f"Memory corruption detected in function: {function_name}"
                    csv_values.append([toprint])
                    print(toprint)
                    break
                
                funcs = fm.getFunctions(True)
        else:
            print("No memory corruption found.")
    
    with open(csv_file_path, 'w') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerows(csv_values)  
        print("Results written to:", csv_file_path)


if __name__ == "__main__":
    main()