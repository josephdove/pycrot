# PyCRot

Pycrot is a dynamic Python debugger designed to inject directly into a running Python process. With Pycrot, developers can introduce breakpoints, inspect state, and modify variables and functions in the code in real-time, offering powerful capabilities for debugging live applications without restarting them.


## Building

To build, use Visual Studio 2022 x64 and select the Release x64 option.

## Usage

```bash
pycrot pythonProcessPID [shouldSuspendThreads]
```

While in the debugger, type the help function provided by the inspector to analyze all the possible choices.

Functions in the debugger (while a breakpoint isn't triggered):
```bash
bootstrapper.log(argument)					This function outputs whatever you pass into it in the PyCRot terminal
bootstrapper.suspendAllThreads()			Suspends all running threads (except for the pycrot one)
bootstrapper.resumeAllThreads()				Resumes all running threads (except for the pycrot one)
bootstrapper.addBreakpoint(type, value)		Adds a breakpoint to the table, also callable with addBP() or addbp()
bootstrapper.deleteBreakpoint(type, value)	Removed a breakpoint to the table, also callable with delBP() or delbp()
bootstrapper.clearBreakpoints()				Clears the breakpoint table, also callable with clsBP() or clsbp()
```

Breakpoint types:
```bash
variable/var			Breakpoints when a variable with the specified name is found
value/val				Breakpoints when a variable with the specified value is found
constant/const			Breakpoints when a constant with the specified value is found
exception/exc			Breakpoints when a exception is triggered
line/ln					Breakpoints when a number line gets executed
```

Functions in the debugger (while a breakpoint is triggered):
```bash
c	    Continues exeution
rc	    Continues exeution and removes breakpoint
s	    Skips to next variable
d	    Disassembles current line and shows output
l	    Tries to get and print current line (might not work)
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

## License

[MIT](https://choosealicense.com/licenses/mit/)