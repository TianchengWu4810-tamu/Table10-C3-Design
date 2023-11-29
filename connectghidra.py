import ghidra
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import ghidra.program.flatapi

# import ghidra.app.script.GhidraScript
# from ghidra.app.util.datatype import DataTypeSelectionDialog
# from ghidra.util.data.DataTypeParser import AllowedDataTypes


state = getState()
currentProgram = state.getCurrentProgram()
print(currentProgram.getImageBase())
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
    # print("Function: {} @ 0x{}".format(func.getName(), entry_point))
    # print(func.getParameters())
    # print("Return type: {}".format(func.getReturnType()))
    newDict = {
        "name": func.getName(),
        "address": entry_point,
        "parameters": func.getParameters(),
        "return type": func.getReturnType(),
    }
    funcDicts.append(newDict)

    # references = getReferencesTo(entry_point)
    # for xref in references:
    #     print(xref)
