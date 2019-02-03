using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;

namespace ConsoleApp1
{
    public class EncryptionParameters
    {
        // RSA parameters
        public const int RSA_KEY_SIZE = 2048;
        public const int SALT_SIZE = 256;
        public const int ITERATION = 10;
        public static DerObjectIdentifier ENCRYPTION_ALG = PkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc;

        // certification parameters
        public const string HASH_ENCRYPTION_ALGORITHM = "SHA512WITHRSA";

        // AES GCM parameters
        public const int NONCE_BIT_SIZE = 128;
        public const int MAC_BIT_SIZE = 128;
        public const int AES_KEY_SIZE = 256;

        // unknown
        //public const int DH_BITS = 512;

        // every key generation starts with this value
        public const int KEY_GENERATION_START = 1;
    }
}
