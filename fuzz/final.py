import angr, argparse
import ghidra
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import ghidra.program.flatapi
import os
import csv

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
                    # for buf_addr in find_symbolic_buffer(path, len(num_count)): 
                    #     memory = path.memory.load(buf_addr, len(num_count)) 
                    #     sc_bvv = path.solver.BVV(pc_text) 
                    #     if path.satisfiable(extra_constraints=(memory == sc_bvv,path.regs.pc == buf_addr)):
                    #         path.add_constraints(memory == sc_bvv) # constrain 1 
                    #         path.add_constraints(path.regs.pc == buf_addr) # constrain 2 
                    #         corrupted_function = get_function_name(funcs, path.regs.pc)
                    #         print(f"Memory corruption detected in function: {corrupted_function}")
                    #         break
                    
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
    for func in funcs:
        entry_point = int ("0x"+func.getEntryPoint().toString(),16)
        end_point = int ("0x"+func.getBody().getMaxAddress().toString(),16)
        
        if entry_point <= addr < end_point:
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
def fuzz(start_addr, end_addr,path):
	p = angr.Project(path)
	
	#input buffer to fuzz the input parameter of the function:
	input_buffer = claripy.BVS('input_buffer',8*50)

	state = p.factory.call_state(addr=start_addr, stdin=input_buffer)
	
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
    ghidraState = getState()
    currentProgram = ghidraState.getCurrentProgram()
    name = currentProgram.getName()
    global location
    location = currentProgram.getExecutablePath()
	
    # print("The currently loaded program is: '{}'".format(name))
    # print("Its location on disk is: '{}'".format(location))
    options = DecompileOptions()
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(currentProgram)

    # mainAdress = 0

    fm = currentProgram.getFunctionManager()
    funcs = fm.getFunctions(True)
    
    #Specifying CSV file path
    csv_file_path = os.path.join(os.path.dirname(location), 'output.csv')
    
    with open(csv_file_path, 'w') as csvfile:
        fieldnames = ['Function Name', 'Address', 'Parameters', 'Return Type']
        csv_writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        csv_writer.writeheader()
        
        for func in funcs:
            entry_point = func.getEntryPoint()
            parameters = ', '.join(str(param.getDataType()) for param in func.getParameters())
            return_type_obj = func.getReturnType()
            return_type = str(return_type_obj) if return_type_obj else None
            
            func_dict = {
                'Function Name': func.getName(),
                'Address': entry_point,
                'Parameters': parameters,
                'Return Type': return_type
            }

            # Write the row to the CSV file
            csv_writer.writerow(func_dict)
            
    print("Results written to:", csv_file_path)
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

    
    global bitness
    # parser = argparse.ArgumentParser()

    # parser.add_argument("Binary")
    start_addr = mainAdress
    
    # args = parser.parse_args()
	
	#UI:
	usr = input("Identify Buffer Overflow? [Y or N]")
	
	if (usr == 'N'):
		usr = input("Fuzz test a function? [Y or N]")
		
		if (usr == 'Y'):
			usr = input("Enter name of function you want to test: ")
			objData = read_functs(csv_file_path)
			startAdr = ''
			usr = input("Up to what address do you want to stop the test: ")
			endAdr = usr;
			
			for row in objData:
				if (usr == row['Function Name']):
					startAdr = int(row['Address'], 16)
					endAdr = int(endAdr, 16)
		
	else:
		p = angr.Project("./demo")

		arch_info = p.arch
		print(arch_info)
		bitness = p.arch.bits
		print(f"The binary is {bitness}-bit.")
		
		# Angr CFG below:
		# function_mapping = {f.addr: f.name for f in cfg.kb.functions.values()}

		state = p.factory.entry_state() 
		# state = p.factory.blank_state(addr=start_addr)
		# state = p.factory.call_state(addr=start_addr)
		# state = p.factory.full_init_state(addr=start_addr)

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
				if get_function_name(funcs,h_element.addr) != "Unknown":
					print(f"Memory corruption detected in function: {get_function_name(funcs,h_element.addr)}")
					break
		else:
			print("No memory corruption found.")


if __name__ == "__main__":
    main()