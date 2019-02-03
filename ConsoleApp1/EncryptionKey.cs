using System.Security;

namespace ConsoleApp1
{
    /// <summary>
    /// 
    /// </summary>
    public sealed class EncryptionKey
    {
        private readonly SecureString _key;
        private readonly ulong _hash;
        private readonly int _generation;

        /// <summary>
        /// Constructor, instantiating a <see cref="EncryptionKey"/> instance.
        /// </summary>
        /// <param name="keyType">Specifies if key is public or private.</param>
        /// <param name="key">PEM formatted key.</param>
        /// <param name="generation">Key generation.</param>
        public EncryptionKey(KeyType keyType, SecureString key, int generation) {
            KeyType = keyType;
            _key = key;
            Generation = generation;
        }

        /// <summary>
        /// Specifies if key is public or private.
        /// </summary>
        public KeyType KeyType {
            get;
        }

        /// <summary>
        /// String serialized key.
        /// </summary>
        public SecureString Key => _key;

        /// <summary>
        /// Returns the encryption key as an array of bytes.
        /// </summary>
        /// <returns>Base 64 encoded byte array.</returns>
        public byte[] KeyToBytes() => _key.ToManagedString().ToBase64Bytes();

        /// <summary>
        /// Returns the encryption key as a string.
        /// </summary>
        /// <returns>Key as a string.</returns>
        public string KeyToString() => _key.ToManagedString();

        /// <summary>
        /// For ephemeral keys, this tells what generation this key is.
        /// </summary>
        public int Generation {
            get;
        }

        /// <summary>
        /// Hash64 key signature, allowing to perform consistency test.
        /// </summary>
        public ulong Hash => _hash;
    }
}
