import ghidra
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# import ghidra.app.script.GhidraScript
# from ghidra.app.util.datatype import DataTypeSelectionDialog
# from ghidra.util.data.DataTypeParser import AllowedDataTypes


state = getState()
currentProgram = state.getCurrentProgram()
name = currentProgram.getName()
location = currentProgram.getExecutablePath()
# print("The currently loaded program is: '{}'".format(name))
# print("Its location on disk is: '{}'".format(location))

options = DecompileOptions()
monitor = ConsoleTaskMonitor()
ifc = DecompInterface()
ifc.setOptions(options)
ifc.openProgram(currentProgram)

funcDicts = []
fm = currentProgram.getFunctionManager()
funcs = fm.getFunctions(True)
for func in funcs:
    entry_point = func.getEntryPoint()
    newDict = {"name": func.getName(), "address": entry_point}
    funcDicts.append(newDict)
    print("Function: {} @ 0x{}".format(func.getName(), entry_point))

    references = getReferencesTo(entry_point)
    for xref in references:
        print(xref)
