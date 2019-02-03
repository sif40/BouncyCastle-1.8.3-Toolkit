using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.OpenSsl;
using System;
using System.Collections;
using System.IO;
using System.Text;

namespace ConsoleApp1
{
    /// <summary>
    /// IN THE ORIGINAL CLASS THERE ARE ALSO THE AES ENCRYPTION METHODS...DO NOT REPLACE ALL!!!
    /// 
    /// THIS CLASS CONTAINS ONLY THE RSA METHODS
    /// 
    /// </summary>
    class Encryptor
    {
        #region Public method

        /// <summary>
        /// RSA encrypts any sized message with the public key. The RSA
        /// asymmetric encryption can only encrypt messages of a maximum size.
        /// The size is dependent on the private key length and consequently,
        /// this method splits the message to encrypt into fragments meeting
        /// this requirement.
        /// </summary>
        /// <param name="clearText">Data to encrypt.</param>
        /// <param name="keyPair">Instance of <see cref="RsaKeyPair"/>
        /// containing the public key.</param>
        /// <returns>Base 64 encrypted data.</returns>
        public ArrayList RsaEncryptWithPublic(string clearText, RsaKeyPair keyPair) {
            byte[] data = Encoding.UTF8.GetBytes(clearText);
            // determine if the message to encrypt is too long and hence must be split-up
            byte[][] messageBlocks = GetMessageBlocks(keyPair.PublicKeyParameters.Modulus.BitLength, data);
            ArrayList list = new ArrayList();
            for (int i = 0; i < messageBlocks.Length; i++) {
                byte[] encrypted = RsaCryptingWithPublic(messageBlocks[i], keyPair, true);
                list.Add(Convert.ToBase64String(encrypted));
            }

            return list;
        }

        /// <summary>
        /// RSA decrypts a message with the private key. The message to decrypt
        /// must not surpass the maximum message length. As the method <see
        /// cref="RsaEncryptWithPrivate"/> takes the message length into
        /// consideration, no message length checking is performed inside this
        /// method. Hence, when decrypting messages which was encrypted with a
        /// different message, the method will return null if the limitation is
        /// surpassed.
        /// </summary>
        /// <param name="encryptedText">Base 64 encoded encrypted text.</param>
        /// <param name="keyPair"></param>
        /// <returns>UTF-8 decrypted data or null if the message is too
        /// long.</returns>
        public string RsaDecryptWithPublic(string encryptedText, RsaKeyPair keyPair) {
            byte[] data = Convert.FromBase64String(encryptedText);

            if (CheckMessageLength(data, keyPair.PublicKeyParameters.Modulus.BitLength))
            {
                byte[] decrypted = RsaCryptingWithPublic(data, keyPair, false);
                return Encoding.UTF8.GetString(decrypted);
            }

            return null;
        }

        /// <summary>
        /// RSA encrypts any sized message with the private key. The RSA
        /// asymmetric encryption can only encrypt messages of a maximum size.
        /// The size is dependent on the private key length and consequently,
        /// this method splits the message to encrypt into fragments meeting
        /// this requirement.
        /// </summary>
        /// <param name="clearText">Data to encrypt.</param>
        /// <param name="keyPair">Instance of <see cref="RsaKeyPair"/>
        /// containing the public key.</param>
        /// <returns>Base 64 encrypted data.</returns>
        public ArrayList RsaEncryptWithPrivate(string clearText, RsaKeyPair keyPair) {
            byte[] data = Encoding.UTF8.GetBytes(clearText);
            // determine if the message to encrypt is too long and hence must be split-up
            byte[][] messageBlocks = GetMessageBlocks(keyPair.PrivateKeyParameters.Modulus.BitLength, data);
            ArrayList list = new ArrayList();
            for (int i = 0; i < messageBlocks.Length; i++) {
                byte[] encrypted = RsaCryptingWithPrivate(messageBlocks[i], keyPair, true);
                list.Add(Convert.ToBase64String(encrypted));
            }

            return list;
        }

        /// <summary>
        /// RSA decrypts a message with the private key. The message to decrypt
        /// must not surpass the maximum message length. As the method <see
        /// cref="RsaEncryptWithPublic"/> takes the message length into
        /// consideration, no message length checking is performed inside this
        /// method. Hence, when decrypting messages which was encrypted with a
        /// different message, the method will return null if the limitation is
        /// surpassed.
        /// </summary>
        /// <param name="encryptedText">Base 64 encoded encrypted text.</param>
        /// <param name="keyPair">Instance of <see cref="RsaKeyPair"/>
        /// containing the public key.</param>
        /// <returns>UTF-8 decrypted data or null if the message is too
        /// long.</returns>
        public string RsaDecryptWithPrivate(string encryptedText, RsaKeyPair keyPair) {
            byte[] data = Convert.FromBase64String(encryptedText);
            if (CheckMessageLength(data, keyPair.PrivateKeyParameters.Modulus.BitLength))
            {
                byte[] decrypted = RsaCryptingWithPrivate(data, keyPair, false);
                return Encoding.UTF8.GetString(decrypted);
            }

            return null;
        }

        #endregion Public method

        #region Private method

        /// <summary>
        /// Method performing asymmetric encryption with the public key.
        /// </summary>
        /// <param name="data">Data to encrypt.</param>
        /// <param name="keyPair">Instance of <see cref="RsaKeyPair"/>
        /// containing the public key.</param>
        /// <param name="encryptOrDecrypt">Flag indicating if an encryption or
        /// decryption is performed.</param>
        /// <returns>Encrypted or decrypted base64 encoded data.</returns>
        private byte[] RsaCryptingWithPublic(byte[] data, RsaKeyPair keyPair, bool encryptOrDecrypt) {
            Pkcs1Encoding cryptEngine = new Pkcs1Encoding(new RsaEngine());
            AsymmetricKeyParameter keyParam = keyPair.PublicKey;
            cryptEngine.Init(encryptOrDecrypt, keyParam);
            return cryptEngine.ProcessBlock(data, 0, data.Length);
        }

        /// <summary>
        /// Method performing asymmetric encryption with the private key.
        /// </summary>
        /// <param name="data">Data to encrypt.</param>
        /// <param name="keyPair">Instance of <see cref="RsaKeyPair"/>
        /// containing the private key.</param>
        /// <param name="encryptOrDecrypt">Flag indicating if an encryption or
        /// decryption is performed.</param>
        /// <returns>Encrypted or decrypted base64 encoded data.</returns>
        private byte[] RsaCryptingWithPrivate(byte[] data, RsaKeyPair keyPair, bool encryptOrDecrypt) {
            Pkcs1Encoding cryptEngine = new Pkcs1Encoding(new RsaEngine());
            AsymmetricKeyParameter keyParam = keyPair.PrivateKey;
            cryptEngine.Init(encryptOrDecrypt, keyParam);
            return cryptEngine.ProcessBlock(data, 0, data.Length);
        }

        /// <summary>
        /// Determines if the message to decrypt does not surpass the RSA
        /// maximum message length.
        /// </summary>
        /// <param name="message">Is the message to validate.</param>
        /// <param name="keyLength">Is the length of the public or private RSA
        /// key.</param>
        /// <returns>True if the message does not surpass the RSA decryption
        /// limitation.</returns>
        private bool CheckMessageLength(byte[] message, int keyLength)
        {
            // calculate the block size...depending on encryption or decryption
            // The formula to calculate the block size originates from the BouncyCastle 1.8.3
            // RSACoreEngine.GetInputBlockSize() method.
            int blockSize = blockSize = (keyLength + 7) / 8;
            return blockSize <= message.Length;
        }

        /// <summary>
        /// This adjust the message to block to be encrypted individually. This
        /// is necessary, as RSA encrypts block-wise and a block must not
        /// surpass the maximum length of key length - 1.
        /// </summary>
        /// <param name="keyLength">Is the length of the public or private RSA
        /// key.</param>
        /// <param name="message">Is the message to encrypt.</param>
        /// <returns>Blocks satisfying the RSA message length.</returns>
        private byte[][] GetMessageBlocks(int keyLength, byte[] message) {
            byte[][] blocks;
            int blockSize = 0;

            // calculate the block size...depending on encryption or decryption
            // The formula to calculate the block size originates from the BouncyCastle 1.8.3
            // RSACoreEngine.GetInputBlockSize() method.
            blockSize = ((keyLength - 1) / 8) - 10;
            //if (encryptOrDecrypt)
            //    blockSize = ((keyLength - 1) / 8) - 10;  // 10 is for the header
            //else
            //    blockSize = (keyLength + 7) / 8;

            if (blockSize < message.Length) {
                int numBlocks = (int)Math.Ceiling((decimal)message.Length / (decimal)(blockSize));
                blocks = new byte[numBlocks][];
            }
            else {
                blocks = new byte[1][];
                blockSize = message.Length;
            }

            int pos = 0;
            for (int i = 0; i < blocks.Length; i++) {

                if (message.Length < blockSize * (i + 1)) {
                    blockSize = message.Length - (blockSize * i);
                }
                blocks[i] = new byte[blockSize];
                Array.Copy(message, pos, blocks[i], 0, blockSize);
                pos += blockSize;
            }

            return blocks;
        }

        #endregion Private method

        //#region Reference method

        //public void Test() {
        //    // Set up 
        //    var input = "Perceived determine departure explained no forfeited";
        //    var publicKey = "-----BEGIN PUBLIC KEY----- // Base64 string omitted // -----END PUBLIC KEY-----";
        //    var privateKey = "-----BEGIN PRIVATE KEY----- // Base64 string omitted// -----END PRIVATE KEY-----";

        //    // Encrypt it
        //    var encryptedWithPublic = RefRsaEncryptWithPublic(input, publicKey);
        //    var encryptedWithPrivate = RefRsaEncryptWithPrivate(input, privateKey);

        //    // Decrypt
        //    var output1 = RefRsaDecryptWithPrivate(encryptedWithPublic, privateKey);
        //    var output2 = RefRsaDecryptWithPublic(encryptedWithPrivate, publicKey);

        //    Console.WriteLine(output1 == output2 && output2 == input);
        //    Console.Read();
        //}

        //public string RefRsaEncryptWithPublic(string clearText, string publicKey) {
        //    var bytesToEncrypt = Encoding.UTF8.GetBytes(clearText);
        //    var encryptEngine = new Pkcs1Encoding(new RsaEngine());

        //    using (var txtreader = new StringReader(publicKey)) {
        //        AsymmetricKeyParameter keyParameter = (AsymmetricKeyParameter)new PemReader(txtreader).ReadObject();
        //        encryptEngine.Init(true, keyParameter);
        //    }

        //    var encrypted = Convert.ToBase64String(
        //        encryptEngine.ProcessBlock(bytesToEncrypt, 0, bytesToEncrypt.Length));
        //    return encrypted;
        //}

        //public string RefRsaEncryptWithPrivate(string clearText, string privateKey) {
        //    var bytesToEncrypt = Encoding.UTF8.GetBytes(clearText);
        //    var encryptEngine = new Pkcs1Encoding(new RsaEngine());

        //    using (var txtreader = new StringReader(privateKey)) {
        //        var keyPair = (AsymmetricCipherKeyPair)new PemReader(txtreader).ReadObject();
        //        encryptEngine.Init(true, keyPair.Private);
        //    }

        //    var encrypted = Convert.ToBase64String(
        //        encryptEngine.ProcessBlock(bytesToEncrypt, 0, bytesToEncrypt.Length));
        //    return encrypted;
        //}


        //// Decryption:

        //public string RefRsaDecryptWithPrivate(string base64Input, string privateKey) {
        //    var bytesToDecrypt = Convert.FromBase64String(base64Input);
        //    AsymmetricCipherKeyPair keyPair;
        //    var decryptEngine = new Pkcs1Encoding(new RsaEngine());

        //    using (var txtreader = new StringReader(privateKey)) {
        //        keyPair = (AsymmetricCipherKeyPair)new PemReader(txtreader).ReadObject();
        //        decryptEngine.Init(false, keyPair.Private);
        //    }

        //    var decrypted = Encoding.UTF8.GetString(decryptEngine.ProcessBlock(bytesToDecrypt, 0, bytesToDecrypt.Length));
        //    return decrypted;
        //}

        //public string RefRsaDecryptWithPublic(string base64Input, string publicKey) {
        //    var bytesToDecrypt = Convert.FromBase64String(base64Input);
        //    var decryptEngine = new Pkcs1Encoding(new RsaEngine());

        //    using (var txtreader = new StringReader(publicKey)) {
        //        var keyParameter = (AsymmetricKeyParameter)new PemReader(txtreader).ReadObject();
        //        decryptEngine.Init(false, keyParameter);
        //    }

        //    var decrypted = Encoding.UTF8.GetString(decryptEngine.ProcessBlock(bytesToDecrypt, 0, bytesToDecrypt.Length));
        //    return decrypted;
        //}

        //#endregion
    }
}
