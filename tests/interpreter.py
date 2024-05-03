import code

class bootstrapperClass:
	serverPort = 4545
	shouldSuspendThreads = False

	def __init__(self, currentLocals):
		# Delete any trace of the class in locals
		del currentLocals[self.__class__.__name__]

		# Define static variables and import table
		self.locals = currentLocals
		self.compile = __import__("codeop").CommandCompiler()
		self.importTable = {"threading": __import__("threading"), "traceback": __import__("traceback"), "random": __import__("random"), "inspect": __import__("inspect"), "ctypes": __import__("ctypes"), "socket": __import__("socket"), "sys": __import__("sys"), "dis": __import__("dis"), "os": __import__("os")}
		self.currentThreadID = self.importTable["ctypes"].windll.kernel32.GetCurrentThreadId()
		self.interpreterBuffer = []
		self.cApis = {}

		# Debugger variables
		self.breakpointTypes = ["variable", "value", "constant", "exception", "line"]
		self.vtypeMapping = {
			"var": "variable",
			"val": "value",
			"const": "constant",
			"exc": "exception",
			"ln": "line"
		}
		self.breakpoints = []
		self.debuggerBuffer = []
		self.debuggerEnabled = False
		self.currentBreakpoint = None

		# Define local self that user will use to execute pycrot functions
		self.localSelfName = ''.join(self.importTable["random"].SystemRandom().choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(16))
		self.locals[self.localSelfName] = self

		# Define CApis and CTypes
		self.cApis["OpenThread"] = self.importTable["ctypes"].windll.kernel32.OpenThread
		self.cApis["SuspendThread"] = self.importTable["ctypes"].windll.kernel32.SuspendThread
		self.cApis["ResumeThread"] = self.importTable["ctypes"].windll.kernel32.ResumeThread
		self.cApis["CreateToolhelp32Snapshot"] = self.importTable["ctypes"].windll.kernel32.CreateToolhelp32Snapshot
		self.cApis["Thread32First"] = self.importTable["ctypes"].windll.kernel32.Thread32First
		self.cApis["Thread32Next"] = self.importTable["ctypes"].windll.kernel32.Thread32Next
		self.cApis["CloseHandle"] = self.importTable["ctypes"].windll.kernel32.CloseHandle
		self.cApis["ThreadEntry32"] = self.importTable["ctypes"].c_ulong * 7

		# Enable settrace hooks
		self.importTable["sys"]._settraceallthreads(self.traceHook)

		# If defined in settings, suspend runtime of all threads (except for the current one)
		if self.shouldSuspendThreads:
			self.suspendAllThreads()

		# Start listening to socket
		sock = self.importTable["socket"].socket(self.importTable["socket"].AF_INET, self.importTable["socket"].SOCK_STREAM)
		sock.connect(('127.0.0.1', self.serverPort))

		# Make files to interact with socket
		self.rfile = sock.makefile('r')
		self.wfile = sock.makefile('w')

		# Start interactive shell
		self.interact()

	# Define help section
	def help(self):
		self.log("Welcome to PyCRot's help utility! Here you can see all the functions in the hidden class and what they do!")
		self.log("")
		self.log(self.localSelfName + ".log(argument)\t\t\tThis function outputs whatever you pass into it in the PyCRot terminal")
		self.log(self.localSelfName + ".suspendAllThreads()\t\tSuspends all running threads (except for the pycrot one)")
		self.log(self.localSelfName + ".resumeAllThreads()\t\tResumes all running threads (except for the pycrot one)")
		self.log(self.localSelfName + ".addBreakpoint(type, value)\tAdds a breakpoint to the table, also callable with addBP() or addbp()")
		self.log(self.localSelfName + ".deleteBreakpoint(type, value)\tRemoved a breakpoint to the table, also callable with delBP() or delbp()")
		self.log(self.localSelfName + ".clearBreakpoints()\t\tClears the breakpoint table, also callable with clsBP() or clsbp()")
		self.log("")
		self.log("Breakpoint types:")
		self.log("\tvariable/var\t\t\t\tBreakpoints when a variable with the specified name is found")
		self.log("\tvalue/val\t\t\t\tBreakpoints when a variable with the specified value is found")
		self.log("\tconstant/const\t\t\t\tBreakpoints when a constant with the specified value is found")
		self.log("\texception/exc\t\t\t\tBreakpoints when a exception is triggered")
		self.log("\tline/ln\t\t\t\t\tBreakpoints when a number line gets executed")

	# Write to self.wfile
	def writeRaw(self, data):
		self.wfile.write(data)
		self.wfile.flush()

	# Suspend all threads
	def suspendAllThreads(self):
		self.actionOnThreads("SuspendThread")

	# Resume all threads
	def resumeAllThreads(self):
		self.actionOnThreads("ResumeThread")

	# Trace hook for all threads
	def traceHook(self, currentFrame, event, arg):
		currentFBack = currentFrame
		
		# Block every pycrot call by iterating through every frame and checking if it was called by this function
		while currentFBack.f_back != None:
			currentFBack = currentFBack.f_back
			if currentFBack.f_locals.get("self") == self:
				return self.traceHook

		currentFrame.f_trace_opcodes = True

		# Breakpoint handler, added "v" to breakpoint var name so sublime text highlighting doesn't highlight it.
		for vbreakpoint in self.breakpoints.copy():
			if vbreakpoint == True:
				self.triggerBreakpoint(currentFrame, vbreakpoint, "breakpoint on next execution")
			elif vbreakpoint["type"] == "variable":
				if vbreakpoint["value"] in currentFrame.f_locals.keys():
					self.triggerBreakpoint(currentFrame, vbreakpoint, str(vbreakpoint["value"]) + " found in locals with value " + str(currentFrame.f_locals[vbreakpoint["value"]]), arg)
			elif vbreakpoint["type"] == "value":
				if vbreakpoint["value"] in currentFrame.f_locals.values():
					self.triggerBreakpoint(currentFrame, vbreakpoint, str(vbreakpoint["value"]) + " found in locals with key " + str(list(currentFrame.f_locals.keys())[list(currentFrame.f_locals.values()).index(vbreakpoint["value"])]), arg)
			elif vbreakpoint["type"] == "constant":
				if vbreakpoint["value"] in currentFrame.f_code.co_consts:
					self.triggerBreakpoint(currentFrame, vbreakpoint, str(vbreakpoint["value"]) + " found in constants", arg)
			elif vbreakpoint["type"] == "line":
				if self.currentBreakpoint.get("frame").f_lineno == vbreakpoint["value"]:
					self.triggerBreakpoint(currentFrame, vbreakpoint, "reached line " + str(vbreakpoint["value"]), arg)
			elif event == "exception" and vbreakpoint["type"] == "exception":
				# arg has signature (exception, value, traceback)
				if issubclass(arg[0], vbreakpoint["value"]):
					self.triggerBreakpoint(currentFrame, vbreakpoint, "triggered for " + str(vbreakpoint["value"].__name__) + " because of " + str(arg[1].__class__.__name__) + ": " + str(arg[1]), arg)

		return self.traceHook

	# Add a breakpoint to the table
	def addBreakpoint(self, vtype, vvalue):
		# Abbreviation mapping
		vtype = self.vtypeMapping.get(vtype, vtype)
		if not vtype in self.breakpointTypes:
			self.log("Couldn't add breakpoint, "+vtype+" isn't a valid breakpoint type.")
			return
		self.breakpoints.append({"type": vtype, "value": vvalue})

	# Remove a breakpoint from the table
	def deleteBreakpoint(self, vtype, vvalue):
		# Abbreviation mapping
		vtype = self.vtypeMapping.get(vtype, vtype)
		if not vtype in self.breakpointTypes:
			self.log("Couldn't remove breakpoint, "+vtype+" isn't a valid breakpoint type.")
			return
		self.breakpoints.remove({"type": vtype, "value": vvalue})

	# Clears the breakpoint table
	def clearBreakpoints(self):
		self.breakpoints = []

	# Abbreviation for addBreakpoint
	addBP = addBreakpoint
	addbp = addBreakpoint
	delBP = deleteBreakpoint
	delbp = deleteBreakpoint
	clsBP = clearBreakpoints
	clsbp = clearBreakpoints

	# Function that gets called whenever a breakpoint gets hit
	def triggerBreakpoint(self, frame, vbreakpoint, reason, arg):
		self.log("\nTriggered breakpoint at "+str(frame))
		self.log("Reason: "+reason)
		if vbreakpoint["type"] == "exception":
			self.log("Exception tree: ")
			self.importTable["traceback"].print_tb(arg[2], file=self.wfile)
		self.log("Type 'h' for more information.")
		self.writeRaw("$ ")
		self.debuggerEnabled = True
		self.currentBreakpoint = {"frame": frame, "vbreakpoint": vbreakpoint}
		self.suspendAllThreads()

	# Resume from a breakpoint break
	def continueFromBreakpoint(self):
		self.debuggerEnabled = False
		self.currentBreakpoint = None
		self.resumeAllThreads()

	# Handles commands in breakpoint mode, return value is whether or not to continue getting the input from user
	def handleBreakpointCommand(self, debuggerBuffer):
		if debuggerBuffer == "h":
			self.log("Debugger commands: ")
			self.log("\tc\tContinues exeution")
			self.log("\trc\tContinues exeution and removes breakpoint")
			self.log("\ts\tSkips to next variable")
			self.log("\td\tDisassembles current line and shows output")
			self.log("\tl\tTries to get and print current line (might not work)")
			self.log("")
			self.log('Any other command will be executed as the program, '+self.localSelfName+'.currentBreakpoint["frame"] gets the current frame object.')
		elif debuggerBuffer == "c":
			if self.currentBreakpoint.get("vbreakpoint") == True:
				self.breakpoints.remove(self.currentBreakpoint.get("vbreakpoint"))
			# Continue execution
			self.continueFromBreakpoint()
			return False
		elif debuggerBuffer == "rc":
			# Remove breakpoint and continue execution
			self.breakpoints.remove(self.currentBreakpoint.get("vbreakpoint"))
			self.continueFromBreakpoint()
			return False
		elif debuggerBuffer == "s":
			# Continue execution and breakpoint on next execution
			if self.currentBreakpoint.get("vbreakpoint") == True:
				self.breakpoints.remove(self.currentBreakpoint.get("vbreakpoint"))
			self.breakpoints.append(True)
			self.continueFromBreakpoint()
			return False
		elif debuggerBuffer == "d":
			# Disassemble current frame
			self.importTable["dis"].dis(self.currentBreakpoint.get("frame").f_code, file=self.wfile)
			return False
		elif debuggerBuffer == "l":
			# Try to display current line
			try:
				source = self.importTable["inspect"].getsourcelines(self.currentBreakpoint.get("frame").f_code)[0]
				self.log(source[self.currentBreakpoint.get("frame").f_lineno - self.currentBreakpoint.get("frame").f_code.co_firstlineno])
			except OSError:
				self.log("Source code unavalible.")
			return False
		else:
			# Inject the current local table and run the code with the locals of the current frame
			self.currentBreakpoint.get("frame").f_locals[self.localSelfName] = self
			runSourceOut = self.runSource(debuggerBuffer, self.currentBreakpoint.get("frame").f_locals)
			del self.currentBreakpoint.get("frame").f_locals[self.localSelfName]
			return runSourceOut

		# Sadly, the python interpreter crashes whenever we try to read the hacked in code, maybe we can make an hook to _PyEval_EvalFrameDefault and check the frame being executed.
		"""
		elif debuggerBuffer == "r":
			# Assemble new code for current frame
			self.writeRaw("| ")
			assembleInputBuffer = ""
			while not assembleInputBuffer.endswith("\n"):
				assembleInputBuffer += self.rfile.read(1)

			# Get f_code ptr in memory and overwrite it
			self.importTable["ctypes"].cast(id(self.currentBreakpoint.get("frame"))+24, self.importTable["ctypes"].POINTER(self.importTable["ctypes"].POINTER(self.importTable["ctypes"].c_void_p))).contents.contents.value = id(self.currentBreakpoint.get("frame").f_code.replace())

			print(self.currentBreakpoint.get("frame").f_code.co_consts)
			return False
		"""

	# Execute specific win32 api function on all threads
	def actionOnThreads(self, action):
		hSnapshot = self.cApis["CreateToolhelp32Snapshot"](0x00000004, 0)
		if hSnapshot != -1:
			thread_entry = self.cApis["ThreadEntry32"]()
			thread_entry[0] = self.importTable["ctypes"].sizeof(self.cApis["ThreadEntry32"])
			
			if self.cApis["Thread32First"](hSnapshot, self.importTable["ctypes"].byref(thread_entry)):
				while True:
					if thread_entry[3] == self.importTable["os"].getpid():
						if self.currentThreadID != thread_entry[2]:
							self.cApis[action](self.cApis["OpenThread"](0x0002, 0, thread_entry[2]))
					if not self.cApis["Thread32Next"](hSnapshot, self.importTable["ctypes"].byref(thread_entry)):
						break

			self.cApis["CloseHandle"](hSnapshot)

	# Log function to be used by user
	def log(self, data):
		self.writeRaw(str(data)+"\n")

	# Manual input but for debug
	def debugInput(self, leftoverCharacter):
		# Define input buffer
		debuggerInputBuffer = ""
		debuggerInputBuffer += leftoverCharacter
		while True:
			while not debuggerInputBuffer.endswith("\n"):
				debuggerInputBuffer += self.rfile.read(1)

			self.debuggerBuffer.append(debuggerInputBuffer[:-1])
			debuggerInputBuffer = ""

			hbpOut = self.handleBreakpointCommand("\n".join(self.debuggerBuffer))

			if not self.debuggerEnabled:
				self.debuggerBuffer = []
				break

			if hbpOut:
				self.writeRaw("> ")
			else:
				self.debuggerBuffer = []
				self.writeRaw("$ ")

	# Manual input that uses self.wfile
	def input(self, prompt=""):
		self.wfile.write(prompt)
		self.wfile.flush()
		inputBuffer = ""
		while not inputBuffer.endswith("\n"):
			receivedCharacter = self.rfile.read(1)
			if self.debuggerEnabled:
				self.debugInput(receivedCharacter)
				self.writeRaw('>>> ')
				self.interpreterBuffer = []
				inputBuffer = ""
			else:
				inputBuffer += receivedCharacter

		return inputBuffer[:-1]

	# Shows tracebacks
	def showTraceback(self):
		ei = self.importTable["sys"].exc_info()
		lines = self.importTable["traceback"].format_exception(ei[0], ei[1], ei[2].tb_next)
		self.writeRaw(''.join(lines))

	# Shows syntax errors
	def showSyntaxError(self, filename=None):
		exctype, excvalue, tb = self.importTable["sys"].exc_info()
		if filename and exctype is SyntaxError:
			try:
				msg, (_, lineno, offset, line) = excvalue.args
				excvalue = SyntaxError(msg, (filename, lineno, offset, line))
			except ValueError:
				pass
		lines = self.importTable["traceback"].format_exception_only(exctype, excvalue)
		self.writeRaw(''.join(lines))

	# Runs the code with specified locals
	def runSource(self, source, vlocals, filename = None):
		if filename == None:
			filename = "<"+self.localSelfName+">"
		try:
			code = self.compile(source, filename, "single")
			if code:
				exec(code, vlocals)
				return False
			return True
		except (OverflowError, SyntaxError, ValueError):
			self.showSyntaxError(filename)
		except SystemExit:
			self.importTable["sys"].exit()
		except:
			self.showTraceback()
		return False

	# Starts the interactive shell
	def interact(self):
		self.writeRaw("PyCRot Debugger | Python "+self.importTable["sys"].version+" on "+self.importTable["sys"].platform+"\nType '"+self.localSelfName+".help()' for more information.\n")
		while True:
			try:
				line = self.input('>>> ' if not self.interpreterBuffer else '... ')
				self.interpreterBuffer.append(line)
				if not self.runSource("\n".join(self.interpreterBuffer), self.locals):
					self.interpreterBuffer = []
			except EOFError:
				break
			except KeyboardInterrupt:
				self.writeRaw("\nKeyboardInterrupt\n")

__import__("threading").Thread(target=bootstrapperClass, args=(locals(),)).start()

code.interact()