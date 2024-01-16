# Locates GOT gadgets for Jump or Call Oriented Programming. These are useful for bypassing shadow stack
# protections in the case where we have the ability to overwrite Global Offset Table entries.
# The program must have been analyzed and xrefs resolved previously for this to work.
#@author Michael Benedetti
#@category Exploit

import ghidra

# Handle running in Python3 via Ghidrathon or Python2 via the original interpreter
program = currentProgram
if callable(program):
    program = currentProgram()
listing = program.getListing()
_monitor_ = monitor
if callable(_monitor_):
    _monitor_ = monitor()

# Locate the .plt.sec segment
plt_sec = None
for block in program.getMemory().getBlocks():
    if block.getName() == ".plt.sec":
        plt_sec = block
        print("[+] Found .plt.sec: 0x{} - 0x{}".format(plt_sec.getStart(), plt_sec.getEnd()))
        break

# Iterate through all .plt.sec entries to find call or jump references to them, then work backwards to produce gadgets.
for symbol in program.getSymbolTable().getDefinedSymbols():
    if isinstance(symbol, ghidra.program.database.symbol.FunctionSymbol):
        if plt_sec.contains(symbol.getAddress()):
            for reference in symbol.getReferences(_monitor_):
                reference_type = str(reference.getReferenceType())
                if reference_type == 'UNCONDITIONAL_CALL' or reference_type == "UNCONDITIONAL_JUMP":
                    codeUnits = listing.getCodeUnits(reference.getFromAddress(), False)
                    instructions = []
                    i = 0
                    while True:
                        codeUnit = codeUnits.next()
                        if i != 0 and (not isinstance(codeUnit, ghidra.program.database.code.InstructionDB) or str(codeUnit.getFlowType()) != 'FALL_THROUGH'):
                            break
                        instructions.insert(0, codeUnit)
                        i += 1
                    for i in range(len(instructions)):
                        resolved = [str(codeUnit).replace("0x{}".format(reference.getToAddress()), symbol.getName()) for codeUnit in instructions[i:]]
                        print("0x{}: {}".format(instructions[i].getAddress(), '; '.join(resolved)))
