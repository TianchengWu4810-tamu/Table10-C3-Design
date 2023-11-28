# import ghidra
import ghidra.app.script.GhidraScript

state = getState()
currentProgram = state.getCurrentProgram()
name = currentProgram.getName()
location = currentProgram.getExecutablePath()
# print("The currently loaded program is: '{}'".format(name))
# print("Its location on disk is: '{}'".format(location))

fm = currentProgram.getFunctionManager()
funcs = fm.getFunctions(True)  # True means 'forward'
for func in funcs:
    print("Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint()))
