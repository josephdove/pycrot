#include <WinSock2.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>
#include <random>
#include <string>
#include <future>

#pragma comment(lib, "ws2_32.lib")

std::string pyCRotBootstrapper = "\n\tdef __init__(self,currentLocals):\n\t\tdel currentLocals[self.__class__.__name__];self.locals=currentLocals;self.compile=__import__('codeop').CommandCompiler();self.importTable={'threading':__import__('threading'),'traceback':__import__('traceback'),'random':__import__('random'),'inspect':__import__('inspect'),'ctypes':__import__('ctypes'),'socket':__import__('socket'),'sys':__import__('sys'),'dis':__import__('dis'),'os':__import__('os')};self.currentThreadID=self.importTable['ctypes'].windll.kernel32.GetCurrentThreadId();self.interpreterBuffer=[];self.cApis={};self.breakpointTypes=['variable','value','constant','exception','line'];self.vtypeMapping={'var':'variable','val':'value','const':'constant','exc':'exception','ln':'line'};self.breakpoints=[];self.debuggerBuffer=[];self.debuggerEnabled=False;self.currentBreakpoint=None;self.localSelfName=''.join(self.importTable['random'].SystemRandom().choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')for _ in range(16));self.locals[self.localSelfName]=self;self.cApis['OpenThread']=self.importTable['ctypes'].windll.kernel32.OpenThread;self.cApis['SuspendThread']=self.importTable['ctypes'].windll.kernel32.SuspendThread;self.cApis['ResumeThread']=self.importTable['ctypes'].windll.kernel32.ResumeThread;self.cApis['CreateToolhelp32Snapshot']=self.importTable['ctypes'].windll.kernel32.CreateToolhelp32Snapshot;self.cApis['Thread32First']=self.importTable['ctypes'].windll.kernel32.Thread32First;self.cApis['Thread32Next']=self.importTable['ctypes'].windll.kernel32.Thread32Next;self.cApis['CloseHandle']=self.importTable['ctypes'].windll.kernel32.CloseHandle;self.cApis['ThreadEntry32']=self.importTable['ctypes'].c_ulong*7;self.importTable['sys']._settraceallthreads(self.traceHook)\n\t\tif self.shouldSuspendThreads:self.suspendAllThreads()\n\t\tsock=self.importTable['socket'].socket(self.importTable['socket'].AF_INET,self.importTable['socket'].SOCK_STREAM);sock.connect(('127.0.0.1',self.serverPort));self.rfile=sock.makefile('r');self.wfile=sock.makefile('w');self.interact()\n\tdef help(self):self.log(\"Welcome to PyCRot's help utility! Here you can see all the functions in the hidden class and what they do!\");self.log('');self.log(self.localSelfName+'.log(argument)\\t\\t\\tThis function outputs whatever you pass into it in the PyCRot terminal');self.log(self.localSelfName+'.suspendAllThreads()\\t\\tSuspends all running threads (except for the pycrot one)');self.log(self.localSelfName+'.resumeAllThreads()\\t\\tResumes all running threads (except for the pycrot one)');self.log(self.localSelfName+'.addBreakpoint(type, value)\\tAdds a breakpoint to the table, also callable with addBP() or addbp()');self.log(self.localSelfName+'.deleteBreakpoint(type, value)\\tRemoved a breakpoint to the table, also callable with delBP() or delbp()');self.log(self.localSelfName+'.clearBreakpoints()\\t\\tClears the breakpoint table, also callable with clsBP() or clsbp()');self.log('');self.log('Breakpoint types:');self.log('\\tvariable/var\\t\\t\\t\\tBreakpoints when a variable with the specified name is found');self.log('\\tvalue/val\\t\\t\\t\\tBreakpoints when a variable with the specified value is found');self.log('\\tconstant/const\\t\\t\\t\\tBreakpoints when a constant with the specified value is found');self.log('\\texception/exc\\t\\t\\t\\tBreakpoints when a exception is triggered');self.log('\\tline/ln\\t\\t\\t\\t\\tBreakpoints when a number line gets executed')\n\tdef writeRaw(self,data):self.wfile.write(data);self.wfile.flush()\n\tdef suspendAllThreads(self):self.actionOnThreads('SuspendThread')\n\tdef resumeAllThreads(self):self.actionOnThreads('ResumeThread')\n\tdef traceHook(self,currentFrame,event,arg):\n\t\tcurrentFBack=currentFrame\n\t\twhile currentFBack.f_back!=None:\n\t\t\tcurrentFBack=currentFBack.f_back\n\t\t\tif currentFBack.f_locals.get('self')==self:return self.traceHook\n\t\tcurrentFrame.f_trace_opcodes=True\n\t\tfor vbreakpoint in self.breakpoints.copy():\n\t\t\tif vbreakpoint==True:self.triggerBreakpoint(currentFrame,vbreakpoint,'breakpoint on next execution')\n\t\t\telif vbreakpoint['type']=='variable':\n\t\t\t\tif vbreakpoint['value']in currentFrame.f_locals.keys():self.triggerBreakpoint(currentFrame,vbreakpoint,str(vbreakpoint['value'])+' found in locals with value '+str(currentFrame.f_locals[vbreakpoint['value']]),arg)\n\t\t\telif vbreakpoint['type']=='value':\n\t\t\t\tif vbreakpoint['value']in currentFrame.f_locals.values():self.triggerBreakpoint(currentFrame,vbreakpoint,str(vbreakpoint['value'])+' found in locals with key '+str(list(currentFrame.f_locals.keys())[list(currentFrame.f_locals.values()).index(vbreakpoint['value'])]),arg)\n\t\t\telif vbreakpoint['type']=='constant':\n\t\t\t\tif vbreakpoint['value']in currentFrame.f_code.co_consts:self.triggerBreakpoint(currentFrame,vbreakpoint,str(vbreakpoint['value'])+' found in constants',arg)\n\t\t\telif vbreakpoint['type']=='line':\n\t\t\t\tif currentFrame.f_lineno==vbreakpoint['value']:self.triggerBreakpoint(currentFrame,vbreakpoint,'reached line '+str(vbreakpoint['value']),arg)\n\t\t\telif event=='exception'and vbreakpoint['type']=='exception':\n\t\t\t\tif issubclass(arg[0],vbreakpoint['value']):self.triggerBreakpoint(currentFrame,vbreakpoint,'triggered for '+str(vbreakpoint['value'].__name__)+' because of '+str(arg[1].__class__.__name__)+': '+str(arg[1]),arg)\n\t\treturn self.traceHook\n\tdef addBreakpoint(self,vtype,vvalue):\n\t\tvtype=self.vtypeMapping.get(vtype,vtype)\n\t\tif not vtype in self.breakpointTypes:self.log(\"Couldn't add breakpoint, \"+vtype+\" isn't a valid breakpoint type.\");return\n\t\tself.breakpoints.append({'type':vtype,'value':vvalue})\n\tdef deleteBreakpoint(self,vtype,vvalue):\n\t\tvtype=self.vtypeMapping.get(vtype,vtype)\n\t\tif not vtype in self.breakpointTypes:self.log(\"Couldn't remove breakpoint, \"+vtype+\" isn't a valid breakpoint type.\");return\n\t\tself.breakpoints.remove({'type':vtype,'value':vvalue})\n\tdef clearBreakpoints(self):self.breakpoints=[]\n\taddBP=addBreakpoint;addbp=addBreakpoint;delBP=deleteBreakpoint;delbp=deleteBreakpoint;clsBP=clearBreakpoints;clsbp=clearBreakpoints\n\tdef triggerBreakpoint(self,frame,vbreakpoint,reason,arg):\n\t\tself.log('\\nTriggered breakpoint at '+str(frame));self.log('Reason: '+reason)\n\t\tif vbreakpoint['type']=='exception':self.log('Exception tree: ');self.importTable['traceback'].print_tb(arg[2],file=self.wfile)\n\t\tself.log(\"Type 'h' for more information.\");self.writeRaw('$ ');self.debuggerEnabled=True;self.currentBreakpoint={'frame':frame,'vbreakpoint':vbreakpoint};self.suspendAllThreads()\n\tdef continueFromBreakpoint(self):self.debuggerEnabled=False;self.currentBreakpoint=None;self.resumeAllThreads()\n\tdef handleBreakpointCommand(self,debuggerBuffer):\n\t\tif debuggerBuffer=='h':self.log('Debugger commands: ');self.log('\\tc\\tContinues exeution');self.log('\\trc\\tContinues exeution and removes breakpoint');self.log('\\ts\\tSkips to next variable');self.log('\\td\\tDisassembles current line and shows output');self.log('\\tl\\tTries to get and print current line (might not work)');self.log('');self.log('Any other command will be executed as the program, '+self.localSelfName+'.currentBreakpoint[\"frame\"] gets the current frame object.')\n\t\telif debuggerBuffer=='c':\n\t\t\tif self.currentBreakpoint.get('vbreakpoint')==True:self.breakpoints.remove(self.currentBreakpoint.get('vbreakpoint'))\n\t\t\tself.continueFromBreakpoint();return False\n\t\telif debuggerBuffer=='rc':self.breakpoints.remove(self.currentBreakpoint.get('vbreakpoint'));self.continueFromBreakpoint();return False\n\t\telif debuggerBuffer=='s':\n\t\t\tif self.currentBreakpoint.get('vbreakpoint')==True:self.breakpoints.remove(self.currentBreakpoint.get('vbreakpoint'))\n\t\t\tself.breakpoints.append(True);self.continueFromBreakpoint();return False\n\t\telif debuggerBuffer=='d':self.importTable['dis'].dis(self.currentBreakpoint.get('frame').f_code,file=self.wfile);return False\n\t\telif debuggerBuffer=='l':\n\t\t\ttry:source=self.importTable['inspect'].getsourcelines(self.currentBreakpoint.get('frame').f_code)[0];self.log(source[self.currentBreakpoint.get('frame').f_lineno-self.currentBreakpoint.get('frame').f_code.co_firstlineno])\n\t\t\texcept OSError:self.log('Source code unavalible.')\n\t\t\treturn False\n\t\telse:self.currentBreakpoint.get('frame').f_locals[self.localSelfName]=self;runSourceOut=self.runSource(debuggerBuffer,self.currentBreakpoint.get('frame').f_locals);del self.currentBreakpoint.get('frame').f_locals[self.localSelfName];return runSourceOut\n\tdef actionOnThreads(self,action):\n\t\thSnapshot=self.cApis['CreateToolhelp32Snapshot'](4,0)\n\t\tif hSnapshot!=-1:\n\t\t\tthread_entry=self.cApis['ThreadEntry32']();thread_entry[0]=self.importTable['ctypes'].sizeof(self.cApis['ThreadEntry32'])\n\t\t\tif self.cApis['Thread32First'](hSnapshot,self.importTable['ctypes'].byref(thread_entry)):\n\t\t\t\twhile True:\n\t\t\t\t\tif thread_entry[3]==self.importTable['os'].getpid():\n\t\t\t\t\t\tif self.currentThreadID!=thread_entry[2]:self.cApis[action](self.cApis['OpenThread'](2,0,thread_entry[2]))\n\t\t\t\t\tif not self.cApis['Thread32Next'](hSnapshot,self.importTable['ctypes'].byref(thread_entry)):break\n\t\t\tself.cApis['CloseHandle'](hSnapshot)\n\tdef log(self,data):self.writeRaw(str(data)+'\\n')\n\tdef debugInput(self,leftoverCharacter):\n\t\tdebuggerInputBuffer='';debuggerInputBuffer+=leftoverCharacter\n\t\twhile True:\n\t\t\twhile not debuggerInputBuffer.endswith('\\n'):debuggerInputBuffer+=self.rfile.read(1)\n\t\t\tself.debuggerBuffer.append(debuggerInputBuffer[:-1]);debuggerInputBuffer='';hbpOut=self.handleBreakpointCommand('\\n'.join(self.debuggerBuffer))\n\t\t\tif not self.debuggerEnabled:self.debuggerBuffer=[];break\n\t\t\tif hbpOut:self.writeRaw('> ')\n\t\t\telse:self.debuggerBuffer=[];self.writeRaw('$ ')\n\tdef input(self,prompt=''):\n\t\tself.wfile.write(prompt);self.wfile.flush();inputBuffer=''\n\t\twhile not inputBuffer.endswith('\\n'):\n\t\t\treceivedCharacter=self.rfile.read(1)\n\t\t\tif self.debuggerEnabled:self.debugInput(receivedCharacter);self.writeRaw('>>> ');self.interpreterBuffer=[];inputBuffer=''\n\t\t\telse:inputBuffer+=receivedCharacter\n\t\treturn inputBuffer[:-1]\n\tdef showTraceback(self):ei=self.importTable['sys'].exc_info();lines=self.importTable['traceback'].format_exception(ei[0],ei[1],ei[2].tb_next);self.writeRaw(''.join(lines))\n\tdef showSyntaxError(self,filename=None):\n\t\texctype,excvalue,tb=self.importTable['sys'].exc_info()\n\t\tif filename and exctype is SyntaxError:\n\t\t\ttry:msg,(_,lineno,offset,line)=excvalue.args;excvalue=SyntaxError(msg,(filename,lineno,offset,line))\n\t\t\texcept ValueError:pass\n\t\tlines=self.importTable['traceback'].format_exception_only(exctype,excvalue);self.writeRaw(''.join(lines))\n\tdef runSource(self,source,vlocals,filename=None):\n\t\tif filename==None:filename='<'+self.localSelfName+'>'\n\t\ttry:\n\t\t\tcode=self.compile(source,filename,'single')\n\t\t\tif code:exec(code,vlocals);return False\n\t\t\treturn True\n\t\texcept(OverflowError,SyntaxError,ValueError):self.showSyntaxError(filename)\n\t\texcept SystemExit:self.importTable['sys'].exit()\n\t\texcept:self.showTraceback()\n\t\treturn False\n\tdef interact(self):\n\t\tself.writeRaw('PyCRot Debugger | Python '+self.importTable['sys'].version+' on '+self.importTable['sys'].platform+\"\\nType '\"+self.localSelfName+\".help()' for more information.\\n\")\n\t\twhile True:\n\t\t\ttry:\n\t\t\t\tline=self.input('>>> 'if not self.interpreterBuffer else'... ');self.interpreterBuffer.append(line)\n\t\t\t\tif not self.runSource('\\n'.join(self.interpreterBuffer),self.locals):self.interpreterBuffer=[]\n\t\t\texcept EOFError:break\n\t\t\texcept KeyboardInterrupt:self.writeRaw('\\nKeyboardInterrupt\\n')\n";

std::string generateRandomName() {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::string result;
    result.resize(16);

    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> distribution(0, sizeof(charset) - 2);

    std::generate_n(result.begin(), 16, [&]() {
        return charset[distribution(generator)];
    });

    return result;
}

DWORD getExportAddress(const std::wstring& dllPath, const std::string exportName) {
    // Open the module

    std::ifstream file(dllPath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "[-] Could not open DLL file" << std::endl;
        return 0;
    }

    // Get DOS signature
    IMAGE_DOS_HEADER dosHeader;
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "[-] Invalid DOS signature" << std::endl;
        return 0;
    }

    // Get NT signature
    file.seekg(dosHeader.e_lfanew, std::ios::beg);
    IMAGE_NT_HEADERS ntHeaders;
    file.read(reinterpret_cast<char*>(&ntHeaders), sizeof(ntHeaders));

    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "[-] Invalid NT signature" << std::endl;
        return 0;
    }

    // Get export table
    auto exportDirRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    auto exportDirSize = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    if (exportDirRVA == 0) {
        std::cerr << "[-] No export table found" << std::endl;
        return 0;
    }

    // Get section header
    IMAGE_SECTION_HEADER sectionHeader = {};
    for (unsigned i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
        file.read(reinterpret_cast<char*>(&sectionHeader), sizeof(sectionHeader));
        if (exportDirRVA >= sectionHeader.VirtualAddress &&
            exportDirRVA < sectionHeader.VirtualAddress + sectionHeader.SizeOfRawData) {
            exportDirRVA = exportDirRVA - sectionHeader.VirtualAddress + sectionHeader.PointerToRawData;
            break;
        }
    }

    // Get all module exports and iterate through them
    file.seekg(exportDirRVA, std::ios::beg);
    IMAGE_EXPORT_DIRECTORY exportDir;
    file.read(reinterpret_cast<char*>(&exportDir), sizeof(exportDir));

    DWORD namesRVA = exportDir.AddressOfNames;
    DWORD* nameRVAs = new DWORD[exportDir.NumberOfNames];
    file.seekg(namesRVA - sectionHeader.VirtualAddress + sectionHeader.PointerToRawData, std::ios::beg);
    file.read(reinterpret_cast<char*>(nameRVAs), exportDir.NumberOfNames * sizeof(DWORD));

    DWORD* funcRVAs = new DWORD[exportDir.NumberOfFunctions];
    file.seekg(exportDir.AddressOfFunctions - sectionHeader.VirtualAddress + sectionHeader.PointerToRawData, std::ios::beg);
    file.read(reinterpret_cast<char*>(funcRVAs), exportDir.NumberOfFunctions * sizeof(DWORD));

    for (DWORD i = 0; i < exportDir.NumberOfNames; i++) {
        DWORD nameRVA = nameRVAs[i];
        file.seekg(nameRVA - sectionHeader.VirtualAddress + sectionHeader.PointerToRawData, std::ios::beg);
        std::string functionName;
        std::getline(file, functionName, '\0');
        if (functionName == exportName) {
            return funcRVAs[i];
        }
    }

    return 0;
}

std::string addressToBytes(uint64_t value) {
    std::string result;
    result.resize(sizeof(value));
    for (size_t i = 0; i < sizeof(value); ++i) {
        char byte = (value >> (i * 8)) & 0xFF;
        result[i] = byte;
    }
    return result;
}

void forwardSocketToStdout(SOCKET sock) {
    char buffer[1024];
    while (true) {
        int bytesReceived = recv(sock, buffer, sizeof(buffer), 0);
        if (bytesReceived <= 0) {
            break;
        }
        std::cout.write(buffer, bytesReceived);
        std::cout.flush();
    }
}

int main(int argc, char** argv) {
    if (argc < 2 || argc > 3) {
        std::cout << "Usage: " << argv[0] << " pythonProcessPID [shouldSuspendThreads]\n";
        return 1;
    }

    // Parse pythonProcessPID
    char* end;
    int pid = std::strtol(argv[1], &end, 10);
    if (*end != '\0') {
        std::cerr << "[-] Invalid PID: must be an integer.\n";
        return 1;
    }

    // Parse shouldSuspendThreads, default is false
    bool shouldSuspendThreads = false;
    if (argc == 3) {
        std::string suspendArg = argv[2];
        if (suspendArg == "true" || suspendArg == "1") {
            shouldSuspendThreads = true;
        }
        else if (suspendArg == "false" || suspendArg == "0") {
            shouldSuspendThreads = false;
        }
        else {
            std::cerr << "[-] Invalid bool for shouldSuspendThreads. Use 'true' or 'false'.\n";
            return 1;
        }
    }

    // Initialize WinSock2
    WSADATA wsaData;
    int wsaInit = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaInit != 0) {
        std::cout << "[-] WSAStartup failed, error code " << wsaInit << std::endl;
        return 1;
    }

    // Define needed variables
    HMODULE hModules[1024];
    DWORD cbNeeded;
    MODULEINFO pyModuleInfo;
    bool wasModuleFound = false;
    std::wstring pyModuleName;
    SOCKET serverSocket, clientSocket;
    struct sockaddr_in server, client;

    // Get handles to process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);

    if (NULL == hProcess) {
        std::cerr << "[-] Process couldn't be opened, either PID is invalid or no permissions" << std::endl;
        return 1;
    }
    else {
        std::cout << "[+] Got handle to process" << std::endl;
    }

    // Get all process modules
    if (!EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
        std::cerr << "[-] Couldn't enum process modules" << std::endl;
        return 1;
    }

    // Iterate through all modules to find python*.dll
    for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
    {
        TCHAR szModName[MAX_PATH];

        // Get module filename
        if (!GetModuleFileNameEx(hProcess, hModules[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
            std::cerr << "[-] Couldn't read module name" << std::endl;
            return 1;
        }

        std::wstring tempModuleName = szModName;

        // If module has \python and ends with .dll
        if (tempModuleName.find(L"\\python") != std::wstring::npos && (tempModuleName.rfind(L".dll") == (tempModuleName.size() - 4))) {
            // Get module info
            if (!GetModuleInformation(hProcess, hModules[i], &pyModuleInfo, sizeof(pyModuleInfo))) {
                std::cerr << "[-] Couldn't get module info" << std::endl;
                return 1;
            }
            pyModuleName = tempModuleName;
            wasModuleFound = true;
            std::wcout << L"[+] Found python module at " << pyModuleName << std::endl;
        }
    }

    if (!wasModuleFound) {
        std::cerr << "[-] Couldn't find module, is this a python runtime?" << std::endl;
        return 1;
    }

    // Get address of PyGILState_Ensure
    uint64_t pyGILEnsureLocation = getExportAddress(pyModuleName, "PyGILState_Ensure");
    uint64_t pyGILEnsure = (uint64_t)pyModuleInfo.lpBaseOfDll + pyGILEnsureLocation;
    
    std::cout << "[+] Found PyGILState_Ensure function at 0x" << std::hex << std::setfill('0') << std::setw(16) << pyGILEnsure << std::endl;

    // Get address of PyRun_SimpleString
    uint64_t pySimpleStringLocation = getExportAddress(pyModuleName, "PyRun_SimpleString");
    uint64_t pySimpleString = (uint64_t)pyModuleInfo.lpBaseOfDll + pySimpleStringLocation;

    std::cout << "[+] Found PyRun_SimpleString function at 0x" << std::hex << std::setfill('0') << std::setw(16) << pyGILEnsure << std::endl;

    // Get address of PyGILState_Ensure
    uint64_t pyGILReleaseLocation = getExportAddress(pyModuleName, "PyGILState_Release");
    uint64_t pyGILRelease = (uint64_t)pyModuleInfo.lpBaseOfDll + pyGILReleaseLocation;

    std::cout << "[+] Found PyGILState_Release function at 0x" << std::hex << std::setfill('0') << std::setw(16) << pyGILEnsure << std::endl;

    // Get address of ExitThread
    uint64_t k32ExitThreadLocation = getExportAddress(L"C:\\Windows\\System32\\KERNEL32.DLL", "ExitThread");
    uint64_t k32ExitThread = (uint64_t)pyModuleInfo.lpBaseOfDll + k32ExitThreadLocation;

    // Create a socket and bind it
    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    server.sin_port = htons(0);
    int serverLen = sizeof(server);

    if (bind(serverSocket, (sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        std::cerr << "[-] Socket bind failed with error code " << WSAGetLastError() << std::endl;
        return 1;
    }

    getsockname(serverSocket, (struct sockaddr*)&server, &serverLen);

    std::string listeningPort = std::to_string(ntohs(server.sin_port));

    std::cout << "[+] Bound socket with port " << listeningPort << std::endl;

    // Create a random name for the pycrot instance
    std::string randomName = generateRandomName();

    // Put the string to execute into memory

    SIZE_T codeBufferBytesWritten = 0;
    std::string codeToInject = "class "+randomName+":"+
        "\n\tserverPort = "+listeningPort +
        "\n\tshouldSuspendThreads = " + (shouldSuspendThreads ? "True" : "False") +
        pyCRotBootstrapper+
        randomName+"(locals())";
    PVOID codeBuffer = VirtualAllocEx(hProcess, NULL, codeToInject.length(), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, codeBuffer, codeToInject.c_str(), codeToInject.length(), &codeBufferBytesWritten);

    std::cout << "[+] Wrote " << std::to_string(codeBufferBytesWritten) << " bytes to 0x" << std::hex << std::setfill('0') << std::setw(16) << codeBuffer << std::endl;

    // Create buffer for the shellcode, 1KB should be plenty
    PVOID shellcodeBuffer = VirtualAllocEx(hProcess, NULL, 1024, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

    // Generate shellcode to run function
    std::string shellcode = "";

    shellcode.append("\x50\x53\x51\x52\x56\x57\x55\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57"); // Push all registers into stack

    shellcode.append("\x48\xb8"); // Push PyGILState_Ensure address to RAX
    shellcode.append(addressToBytes(pyGILEnsure));
    shellcode.append("\xff\xd0"); // Call RAX
    
    shellcode.append("\x49\x89\xC4"); // Move RAX to R12

    shellcode.append("\x48\xb9"); // Push codeBuffer address to RCX
    shellcode.append(addressToBytes((uint64_t)codeBuffer));

    shellcode.append("\x48\xb8"); // Push PyRun_SimpleString address to RAX
    shellcode.append(addressToBytes(pySimpleString));
    shellcode.append("\xff\xd0"); // Call RAX
    
    shellcode.append("\x4C\x89\xE1"); // Move R12 to RCX

    shellcode.append("\x48\xb8"); // Push PyGILState_Release address to RAX
    shellcode.append(addressToBytes(pyGILRelease));
    shellcode.append("\xff\xd0"); // Call RAX

    // Exit thread gracefully
    shellcode.append("\x48\x31\xC9"); // Xor RCX with RCX to clear 
    shellcode.append("\x48\xb8"); // Push k32ExitThread to RAX
    shellcode.append(addressToBytes(k32ExitThread));
    shellcode.append("\xff\xd0"); // Call RAX

    // Write the shellcode to a buffer
    SIZE_T shellcodeBufferBytesWritten = 0;
    WriteProcessMemory(hProcess, shellcodeBuffer, shellcode.c_str(), shellcode.length(), &shellcodeBufferBytesWritten);

    std::cout << "[+] Wrote " << std::to_string(shellcodeBufferBytesWritten) << " bytes to 0x" << std::hex << std::setfill('0') << std::setw(16) << shellcodeBuffer << std::endl;

    // Create a new thread and execute the payload
    if (!CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)shellcodeBuffer, NULL, 0, NULL)) {
        std::cerr << "[-] Couldn't start thread" << std::endl;
        return 1;
    }
    else {
        std::cout << "[+] Started thread in target process" << std::endl;
    }

    // Close handles
    CloseHandle(hProcess);

    // Start listening and wait for python client to connect
    listen(serverSocket, 3);

    std::cout << "[+] Waiting for client to connect" << std::endl;
    int c = sizeof(struct sockaddr_in);
    clientSocket = accept(serverSocket, (struct sockaddr*)&client, &c);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "[-] Accept failed with error code: " << WSAGetLastError() << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "[+] Connection received from client, redirecting outputs" << std::endl;

    // Redirect stdin to socket
    std::thread thread(forwardSocketToStdout, clientSocket);
    thread.detach();

    char userInput;
    while (std::cin.get(userInput)) {
        send(clientSocket, &userInput, 1, 0);
    }
}