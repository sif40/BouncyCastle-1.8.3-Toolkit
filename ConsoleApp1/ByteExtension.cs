using System.Collections.Generic;

namespace ConsoleApp1
{
    public static class ByteExtension
    {
        private const string _BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        private static readonly char[] _base64Alphabet = _BASE64_ALPHABET.ToCharArray();
        private static readonly Dictionary<char, byte> _base64ReverseAlphabet = GetAlphabet(_BASE64_ALPHABET, false);

        /// <summary>
        ///   Converts a byte array to its corresponding Base64 encoding described in
        ///   <see
        ///     cref="!:http://tools.ietf.org/html/rfc4648">
        ///     RFC 4648
        ///   </see>
        ///   .
        /// </summary>
        /// <param name="inArray"> An array of 8-bit unsigned integers. </param>
        /// <returns> Encoded string </returns>
        public static string ToBase64String(this byte[] inArray) =>
            inArray.ToBase64String(0, inArray.Length);

        /// <summary>
        ///   Converts a byte array to its corresponding Base64 encoding described in
        ///   <see
        ///     cref="!:http://tools.ietf.org/html/rfc4648">
        ///     RFC 4648
        ///   </see>
        ///   .
        /// </summary>
        /// <param name="inArray"> An array of 8-bit unsigned integers. </param>
        /// <param name="offset"> An offset in inArray. </param>
        /// <param name="length"> The number of elements of inArray to convert. </param>
        /// <returns> Encoded string </returns>
        public static string ToBase64String(this byte[] inArray, int offset, int length)
            => inArray.ToBase64String(offset, length, _base64Alphabet);

        private static string ToBase64String(this byte[] inArray, int offset, int length, char[] alphabet) {
            int inRemain = length % 3;
            int inSafeEnd = offset + length - inRemain;

            int outLength = length / 3 * 4 + ((inRemain == 0) ? 0 : 4);

            char[] outData = new char[outLength];
            int outPos = 0;

            int inPos = offset;
            while (inPos < inSafeEnd) {
                outData[outPos++] = alphabet[(inArray[inPos] & 0xfc) >> 2];
                outData[outPos++] = alphabet[((inArray[inPos] & 0x03) << 4) | ((inArray[++inPos] & 0xf0) >> 4)];
                outData[outPos++] = alphabet[((inArray[inPos] & 0x0f) << 2) | ((inArray[++inPos] & 0xc0) >> 6)];
                outData[outPos++] = alphabet[inArray[inPos++] & 0x3f];
            }

            switch (inRemain) {
                case 1:
                    outData[outPos++] = alphabet[(inArray[inPos] & 0xfc) >> 2];
                    outData[outPos++] = alphabet[(inArray[inPos] & 0x03) << 4];
                    outData[outPos++] = alphabet[64];
                    outData[outPos] = alphabet[64];
                    break;
                case 2:
                    outData[outPos++] = alphabet[(inArray[inPos] & 0xfc) >> 2];
                    outData[outPos++] = alphabet[((inArray[inPos] & 0x03) << 4) | ((inArray[++inPos] & 0xf0) >> 4)];
                    outData[outPos++] = alphabet[(inArray[inPos] & 0x0f) << 2];
                    outData[outPos] = alphabet[64];
                    break;
            }

            return new string(outData);
        }

        private static Dictionary<char, byte> GetAlphabet(string alphabet, bool isCaseIgnored) {
            Dictionary<char, byte> res = new Dictionary<char, byte>(isCaseIgnored ? 2 * alphabet.Length : alphabet.Length);

            for (byte i = 0; i < alphabet.Length; i++) {
                res[alphabet[i]] = i;
            }

            if (isCaseIgnored) {
                alphabet = alphabet.ToLowerInvariant();
                for (byte i = 0; i < alphabet.Length; i++) {
                    res[alphabet[i]] = i;
                }
            }

            return res;
        }
    }
}
