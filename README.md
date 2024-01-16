# GotGadget

GotGadget is a ghidra plugin for finding gadgets for Jump Oriented Programming or Call Oriented Programming targeting
the Global Offset Table (GOT) and Procedure Linkage Table.  The use-case for these types of gadgets would be a scenario 
where we have the ability to overwrite GOT entries and Return Oriented Programming (ROP) is not an option, like in the
face of Control-flow Enforcement Technology such as the shadow stack.

## Installation
Simply copy [gotgadget.py](gotgadget.py) into your ghidra scripts directory.

## Usage
GotGadget should work with the out-of-the-box Python 2 interpreter that Ghidra provides, or with Python 3 and [Ghidrathon](https://github.com/mandiant/Ghidrathon).

### Via the Scripts Interface
Ensure analysis has been run on your target binary, then invoke the script via the scripts interface in Ghidra.
### Via analyzeHeadless
GotGadget can be run headless via the following command:
```bash
analyzeHeadless <project_path> <project_name> -noanalysis -process <target_binary_name> -postScript <path_to_got_gadget> > <output_path>

# Example:
analyzeHeadless /home/user/projects myproject -noanalysis -process libc.so.6 -postScript /home/user/ghidra_scripts/gotgadget.py > /tmp/output
```

## Gadgets
Output is presented in a similar style as other gadget finding tools:

```
0x001a6840: ADD RSP,0x18; XOR ESI,ESI; MOV RDI,RAX; POP RBX; POP RBP; POP R12; POP R13; JMP memset
0x001a6844: XOR ESI,ESI; MOV RDI,RAX; POP RBX; POP RBP; POP R12; POP R13; JMP memset
0x001a6846: MOV RDI,RAX; POP RBX; POP RBP; POP R12; POP R13; JMP memset
0x001a6849: POP RBX; POP RBP; POP R12; POP R13; JMP memset
0x001a684a: POP RBP; POP R12; POP R13; JMP memset
0x001a684b: POP R12; POP R13; JMP memset
```
