using System;
using System.Runtime.InteropServices;
using System.Security;

namespace ConsoleApp1
{
    public static class SecureStringExtension
    {
        public static string ToManagedString(this SecureString @in) {
            IntPtr valuePtr = IntPtr.Zero;
            try {
                valuePtr = Marshal.SecureStringToGlobalAllocUnicode(@in);
                return Marshal.PtrToStringUni(valuePtr);
            }
            finally {
                Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
            }
        }

        public static SecureString ToSecureString(this byte[] @in) {
            SecureString secureData = new SecureString();

            foreach (var b in @in) {
                char ch = (char)b;
                secureData.AppendChar(ch);
            }

            return secureData;
        }
    }
}
