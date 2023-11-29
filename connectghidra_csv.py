import ghidra
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import ghidra.program.flatapi
import csv
import os

state = getState()
currentProgram = state.getCurrentProgram()
name = currentProgram.getName()
location = currentProgram.getExecutablePath()

options = DecompileOptions()
monitor = ConsoleTaskMonitor()
ifc = DecompInterface()
ifc.setOptions(options)
ifc.openProgram(currentProgram)

funcDicts = []
fm = currentProgram.getFunctionManager()
funcs = fm.getFunctions(True)

# Get the directory containing the executable
executable_directory = os.path.dirname(location)

# Specify the CSV file path in the same directory as the executable
csv_file_path = os.path.join(executable_directory, 'output.csv')

with open(csv_file_path, 'w') as csvfile:
    fieldnames = ['Function Name', 'Address', 'Parameters', 'Return Type']
    csv_writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    # Write the header row
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

        # Append the dictionary to the list
        funcDicts.append(func_dict)

        # Write the row to the CSV file
        csv_writer.writerow(func_dict)

print("Results written to:", csv_file_path)