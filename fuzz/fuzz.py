import angr
import claripy
import csv

def read_functs(file_path):
	data = []
	
	with open(file_path, newline='') as csvfile:
		csv_reader = csv.DictReader(csvfile)
		
		for row in csv_reader:
			data.append(row)
			
	return data	

def fuzz_check(simgr):
	if (simgr.found):
		print(simgr.found[0].regs.rax)
		if (simgr.found[0].regs.rax):
			return True
	return False

def fuzz(start_addr, end_addr,path):
	p = angr.Project(path)
	
	input_buffer = claripy.BVS('input_buffer',8*50)

	state = p.factory.call_state(addr=start_addr, stdin=input_buffer)
	
	simgr = p.factory.simulation_manager(state)
	
	simgr.explore(find=end_addr, step_func=fuzz_check)
	
	print(simgr)
	if len(simgr.errored) > 0:
		print("error")
		
	if len(simgr.found) > 0:
		print("found")
		print("input: ", simgr.found[0].posix.dumps(0))
		
if __name__ == "__main__":
	usr = input("Enter name of function you want to test: ")
	objData = read_functs('demo.csv')
	startAdr = ''
	endAdr = ''
	
	for row in objData:
		if (usr == row['Name']):
			startAdr = int(row['Start'], 16)
			endAdr = int(row['End'], 16)
	
			
	fuzz(startAdr, endAdr, 'test')
