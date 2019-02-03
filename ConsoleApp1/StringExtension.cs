using System;
using System.Security;

namespace ConsoleApp1
{
    public static class StringExtension
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="in"></param>
        /// <returns></returns>
        public static byte[] GetBytes(this string @in) {
            byte[] bytes = new byte[@in.Length * sizeof(char)];
            Buffer.BlockCopy(@in.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="in"></param>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static string GetString(this string @in, byte[] bytes) {
            char[] chars = new char[bytes.Length / sizeof(char)];
            Buffer.BlockCopy(bytes, 0, chars, 0, bytes.Length);
            return new string(chars);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="in"></param>
        /// <returns></returns>
        public static byte[] ToBase64Bytes(this string @in) {
            return Convert.FromBase64String(@in);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="in"></param>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static string FromBase64Bytes(this string @in, byte[] bytes) {
            return Convert.ToBase64String(bytes);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="in"></param>
        /// <returns></returns>
        public static SecureString ToSecureString(this string @in) {
            if (@in == string.Empty || @in.Length == 0)
                return null;

            SecureString ss = new SecureString();
            char[] chs = @in.ToCharArray(0, @in.Length);

            foreach (var ch in chs) {
                ss.AppendChar(ch);
            }
            return ss;
        }
    }
}
