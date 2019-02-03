using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.Security;
using System.Text;
using PemReader = Org.BouncyCastle.OpenSsl.PemReader;
using PemWriter = Org.BouncyCastle.OpenSsl.PemWriter;
using Pkcs8Generator = Org.BouncyCastle.OpenSsl.Pkcs8Generator;

namespace ConsoleApp1
{
    /// <summary>
    /// Class is either used to factor a new secret client RSA key pair, 
    /// read an existing secret client key pair or to save and read public key
    /// received from other users. Every new key must be registered with the
    /// <see cref="RsaKeyRecord"/> entity class.
    /// Note: The generated RSA keys are stored in the PKCS8 format.
    /// </summary>
    public class RsaKeyPair : IConfigurable
    {
        private readonly EncryptionKey _publicKey;
        private readonly EncryptionKey _privateKey;
        private X509Certificate _certificate;
        // path for the client PEM encoded and encrypted private key file
        private static string _clientPrivateKeyPemFile;
        // path for the client certificate
        private static string _clientCertPemFile;
        private const int _rsaKeySize = EncryptionParameters.RSA_KEY_SIZE;
        private const int _saltSize = EncryptionParameters.SALT_SIZE;
        private const int _iteration = EncryptionParameters.ITERATION;
        //private static DerObjectIdentifier _encryptionAlgorithm = EncryptionParameters.ENCRYPTION_ALG;
        private AsymmetricKeyParameter _privateKeyInfo;
        private SecureString _pwd;
        private bool _overwriteExisting = false;
        private bool _isConfigured = false;

        /// <summary>
        /// Constructor to be used to factor a new RSA key pair.
        /// <param name="passphrase">Client secret password used to encrypt the
        /// private key.</param>
        /// <param name="overwriteExisting">Flag allowing or denying to replace
        /// an existing PEM file.</param>
        /// </summary>
        public RsaKeyPair(string passphrase, bool overwriteExisting) {
            if (!IsConfigured)
                Configure();

            _overwriteExisting = overwriteExisting;

            AsymmetricCipherKeyPair keyPair = FactorKeyPair();

            PrivateKeyInfo pkInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
            _privateKey = new EncryptionKey(KeyType.RSAPrivate,
                                            Convert.ToBase64String(pkInfo.GetDerEncoded()).ToSecureString(),
                                            EncryptionParameters.KEY_GENERATION_START);

            SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
            _publicKey = new EncryptionKey(KeyType.RSAPublic,
                                           Convert.ToBase64String(info.GetDerEncoded()).ToSecureString(),
                                           EncryptionParameters.KEY_GENERATION_START);

            //// Encrypt private key info for later to be stored with the SavePrivateKeyAsPemFile method
            _pwd = passphrase.ToSecureString();
            _privateKeyInfo = PrivateKeyFactory.CreateKey(pkInfo);

            keyPair = null;
            pkInfo = null;
            info = null;
            GC.Collect();
        }

        /// <summary>
        /// Constructor to be used to recover the existing RSA key pair and server
        /// signed certificate found on the local file system.
        /// </summary>
        /// <param name="passphrase">Passphrase for private key.</param>
        public RsaKeyPair(string passphrase) {
            if (!IsConfigured)
                Configure();

            if (File.Exists(_clientPrivateKeyPemFile) && File.Exists(_clientCertPemFile)) {
                byte[] pkData = File.ReadAllBytes(_clientPrivateKeyPemFile);
                _pwd = passphrase.ToSecureString();
                AsymmetricCipherKeyPair keyPair = PemDecodeKeyPair(pkData);
                // Generate key info's
                PrivateKeyInfo pkInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
                SubjectPublicKeyInfo info =
                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);

                _privateKey = new EncryptionKey(KeyType.RSAPrivate,
                    Convert.ToBase64String(pkInfo.GetDerEncoded()).ToSecureString(),
                    EncryptionParameters.KEY_GENERATION_START);

                _publicKey = new EncryptionKey(KeyType.RSAPublic,
                    Convert.ToBase64String(info.GetDerEncoded()).ToSecureString(),
                    EncryptionParameters.KEY_GENERATION_START);

                byte[] certData = File.ReadAllBytes(_clientCertPemFile);
                X509CertificateParser certParser = new X509CertificateParser();
                _certificate = certParser.ReadCertificate(certData);


                pkData = null;
                certData = null;
                keyPair = null;
                pkInfo = null;
                info = null;
                _pwd = null;
                GC.Collect();
            }
            else
                throw new Exception("Cannot find the PEM formatted certificate or private key file");
        }

        #region Public method

        /// <summary>
        /// Returns the public key.
        /// </summary>
        public AsymmetricKeyParameter PublicKey => GetPublicKeyParameter(_publicKey.Key);

        /// <summary>
        /// Returns the private key. Note that the key is not
        /// encrypted.
        /// </summary>
        public AsymmetricKeyParameter PrivateKey => GetPrivateKeyParamter(_privateKey.Key);

        /// <summary>
        /// Returns the server-signed client certificate.
        /// </summary>
        public X509Certificate Certificate
        {
            get => _certificate;
            set => _certificate = value;
        } 

        /// <summary>
        /// Returns the private unencrypted key parameters used by the <see
        /// cref="Certificator.CreateCsr"/> method to generate a certificate
        /// request.
        /// </summary>
        public RsaPrivateCrtKeyParameters PrivateKeyParameters
            => (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(GetPrivateKeyInfo(_privateKey.Key));

        /// <summary>
        /// Returns the public key parameters used by the <see
        /// cref="Certificator.CreateCsr"/> method to generate a certificate
        /// request.
        /// </summary>
        public RsaKeyParameters PublicKeyParameters
            => (RsaKeyParameters)PublicKeyFactory.CreateKey(GetPublicKeyInfo(_publicKey.Key));

        ///// <summary>
        ///// Saves a RSA public key as a PEM encoded file.
        ///// </summary>
        ///// <param name="pemFile">Is the content of the PEM file to store.</param>
        ///// <param name="path">Is the absolute path name including a file name.</param>
        ///// <param name="derEncodedInfo">Is the DER encoded public key.</param>
        //public void SavePublicKeyAsPemFile(string pemFile, string path, string derEncodedInfo) {
        //    if (pemFile != null && derEncodedInfo != null && !File.Exists(pemFile)) {
        //        byte[] data = Convert.FromBase64String(derEncodedInfo);
        //        AsymmetricKeyParameter keyParam = PublicKeyFactory.CreateKey(data);
        //        SubjectPublicKeyInfo info =
        //            SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyParam);
        //        byte[] infoSer = PemEncodePublicKey(info);
        //        using (FileStream fs = File.OpenWrite(pemFile)) {
        //            fs.Write(infoSer, 0, infoSer.Length);
        //        }
        //    }
        //    else
        //        throw new Exception();
        //}

        ///// <summary>
        ///// Reads a PEM file containing a public key.
        ///// </summary>
        ///// <param name="pemFile">Is the absolute path name to a PEM file to be read.</param>
        ///// <returns>Instance of <see cref="EncryptionKey"/> containing the RSA public key.</returns>
        //public static EncryptionKey ReadPublicKeyFromPem(string pemFile) {

        //    if (File.Exists(pemFile)) {
        //        byte[] data = File.ReadAllBytes(pemFile);
        //        RsaKeyParameters param;
        //        AsymmetricKeyParameter keyParam;

        //        using (MemoryStream stream = new MemoryStream(data)) {
        //            using (StreamReader reader = new StreamReader(stream, Encoding.ASCII, false)) {
        //                PemReader pemReader = new PemReader(reader);
        //                param = pemReader.ReadObject() as RsaKeyParameters;
        //                pemReader.Reader.Close();
        //            }
        //        }

        //        if (param != null) {
        //            keyParam = param;
        //            SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(param);
        //            return new EncryptionKey(KeyType.RSAPublic,
        //                Convert.ToBase64String(info.GetDerEncoded()).ToSecureString(),
        //                EncryptionParameters.KEY_GENERATION_START);
        //        }
        //        else
        //            throw new Exception("");
        //    }
        //    else
        //        throw new Exception("");
        //}

        /// <summary>
        /// Stores on the client local file system the RSA private key and
        /// server signed certificate.
        /// </summary>
        /// <param name="certificate">Instance of <see cref="X509Certificate"/>
        /// which has been signed by the server.</param>
        /// 
        public void Save(X509Certificate certificate) {
            // Save the private key and certificate
            SavePrivateKeyAsPemFile();
            SaveCertificateAsPemFile(certificate);
            _privateKeyInfo = null;
            _pwd = null;
            GC.Collect();
        }

        public void Configure() {
            _clientPrivateKeyPemFile = @"w:\fluffysSecret.pem";
            _clientCertPemFile = @"w:\fluffyCert.pem";
            _isConfigured = true;
        }

        public bool IsConfigured => _isConfigured;

        #endregion Public method

        #region Private method

        /// <summary>
        /// Converts the DER encoded public key info into an instance of <see
        /// cref="AsymmetricKeyParameter"/>.
        /// </summary>
        /// <param name="derEncoded">DER encoded <see
        /// cref="SubjectPublicKeyInfo"/>.</param>
        /// <returns>An instance of <see
        /// cref="AsymmetricKeyParameter"/>.</returns>
        private AsymmetricKeyParameter GetPublicKeyParameter(SecureString derEncoded) {
            byte[] data = Convert.FromBase64String(derEncoded.ToManagedString());
            return PublicKeyFactory.CreateKey(data);
        }

        /// <summary>
        /// Converts the DER encoded public key info into an instance of <see
        /// cref="SubjectPublicKeyInfo"/>.
        /// </summary>
        /// <param name="derEncoded">DER encoded <see
        /// cref="SubjectPublicKeyInfo"/>.</param>
        /// <returns>An instance of <see
        /// cref="SubjectPublicKeyInfo"/>.</returns>
        private SubjectPublicKeyInfo GetPublicKeyInfo(SecureString derEncoded) {
            byte[] data = Convert.FromBase64String(derEncoded.ToManagedString());
            AsymmetricKeyParameter keyParam = PublicKeyFactory.CreateKey(data);
            return SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyParam);
        }

        /// <summary>
        /// Converts the DER encoded private key info into an instance of <see
        /// cref="AsymmetricKeyParameter"/>.
        /// </summary>
        /// <param name="derEncoded">DER encoded <see
        /// cref="PrivateKeyInfo"/>.</param>
        /// <returns>An instance of <see cref="AsymmetricKeyParameter"/>.</returns>
        private AsymmetricKeyParameter GetPrivateKeyParamter(SecureString derEncoded) {
            byte[] data = Convert.FromBase64String(derEncoded.ToManagedString());
            return PrivateKeyFactory.CreateKey(data);
        }

        /// <summary>
        /// Converts the DER encoded private key info into an instance of <see
        /// cref="PrivateKeyInfo"/>.
        /// </summary>
        /// <param name="derEncoded">DER encoded <see
        /// cref="PrivateKeyInfo"/>.</param>
        /// <returns>An instance of <see cref="PrivateKeyInfo"/>.</returns>
        private PrivateKeyInfo GetPrivateKeyInfo(SecureString derEncoded) {
            byte[] data = Convert.FromBase64String(derEncoded.ToManagedString());
            AsymmetricKeyParameter keyParam = PrivateKeyFactory.CreateKey(data);
            return PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyParam);
        }

        /// <summary>
        /// Factors a new RSA pair of unencrypted private and public keys.
        /// </summary>
        /// <returns>Returns an instance of <see
        /// cref="AsymmetricCipherKeyPair"/> from which the unencrypted private
        /// and public key can be obtained.</returns>
        private AsymmetricCipherKeyPair FactorKeyPair() {
            RsaKeyPairGenerator generator = new RsaKeyPairGenerator();
            generator.Init(new KeyGenerationParameters(new SecureRandom(
                new CryptoApiRandomGenerator()), _rsaKeySize));
            return generator.GenerateKeyPair();
        }

        ///// <summary>
        ///// Encrypts and serializes the private key.
        ///// </summary>
        ///// <param name="privateKey">Instance of <see
        ///// cref="AsymmetricKeyParameter"/> containing the private key.</param>
        ///// <param name="passphrase">Password to be used to encrypt the private
        ///// key.</param>
        ///// <returns>Encrypts and serializes the private key.</returns>
        //private byte[] EncryptAndSerializePrivateKey(AsymmetricKeyParameter privateKey,
        //    string passphrase)
        //    => PrivateKeyFactory.EncryptKey(_encryptionAlgorithm,
        //        passphrase.ToCharArray(),
        //        new byte[_saltSize],
        //        _iteration,
        //        privateKey);

        ///// <summary>
        ///// Encrypts the private key information with the specified password.
        ///// </summary>
        ///// <param name="key">Instance of <see cref="AsymmetricKeyParameter"/>,
        ///// from which the private key can be obtained.</param>
        ///// <param name="passphrase">Password to be used to encrypt the private
        ///// key information.</param>
        ///// <returns>Instance of <see cref="EncryptedPrivateKeyInfo"/>
        ///// containing the encrypted private key.</returns>
        //private EncryptedPrivateKeyInfo GetEncryptedPrivateKeyInfo(AsymmetricKeyParameter key, string passphrase) {
        //    IBufferedCipher cipher = PbeUtilities.CreateEngine(_encryptionAlgorithm) as IBufferedCipher;
        //    PrivateKeyInfo keyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(key);
        //    SecureRandom random = new SecureRandom(new CryptoApiRandomGenerator());
        //    byte[] salt = new byte[_saltSize];
        //    random.NextBytes(salt);
        //    Asn1Encodable pbeParameters =
        //        PbeUtilities.GenerateAlgorithmParameters(_encryptionAlgorithm, salt, _iteration);
        //    AlgorithmIdentifier algorithm = new AlgorithmIdentifier(_encryptionAlgorithm, pbeParameters);
        //    object cipherParameters =
        //        PbeUtilities.GenerateCipherParameters(algorithm, passphrase.ToCharArray());
        //    cipher?.Init(true, (ICipherParameters)cipherParameters);
        //    byte[] encoded = cipher?.DoFinal(keyInfo.GetEncoded());
        //    return new EncryptedPrivateKeyInfo(algorithm, encoded);
        //}

        ///// <summary>
        ///// Decrypt the private key information.
        ///// </summary>
        ///// <param name="passphrase">Password to decrypt the private key
        ///// information</param>
        ///// <param name="pKeyInfo">Encrypted private key information.</param>
        ///// <returns>Decrypted private key.</returns>
        //private AsymmetricKeyParameter DecryptPrivateKey(string passphrase, EncryptedPrivateKeyInfo pKeyInfo)
        //    => PrivateKeyFactory.DecryptKey(passphrase.ToCharArray(), pKeyInfo);

        ///// <summary>
        ///// Decrypts and deserializes the encrypted and serialized private key.
        ///// </summary>
        ///// <param name="passphrase">Password to decrypt the private
        ///// key.</param>
        ///// <param name="serializedEncryptedPrivateKey"></param>
        ///// <returns>Instance of <see cref="AsymmetricKeyParameter"/> from which
        ///// the private key can be obtained.</returns>
        //private AsymmetricKeyParameter DecryptAndDeserializePrivateKey(string passphrase,
        //    byte[] serializedEncryptedPrivateKey)
        //    => PrivateKeyFactory.DecryptKey(passphrase.ToCharArray(), serializedEncryptedPrivateKey);

        ///// <summary>
        ///// Serializes and PEM encodes the RSA public key. If required, the
        ///// resulting PEM formatted key can be persisted onto the file system
        ///// without any additional processing.
        ///// </summary>
        ///// <param name="data">Public key to PEM encode.</param>
        ///// <returns>Byte array containing the PEM encoded public key.</returns>
        //private static byte[] PemEncodePublicKey(SubjectPublicKeyInfo data) {
        //    using (MemoryStream stream = new MemoryStream()) {
        //        using (StreamWriter writer = new StreamWriter(stream, Encoding.ASCII)) {
        //            PemWriter pemWriter = new PemWriter(writer);
        //            PemObjectGenerator pemObject = new PemObject("", data.GetDerEncoded());
        //            pemWriter.WriteObject(pemObject);
        //            pemWriter.Writer.Flush();
        //            return stream.ToArray();
        //        }
        //    }
        //}

        /// <summary>
        /// Serializes and PEM encodes the encrypted RSA private key. If
        /// required, the resulting PEM formatted key can be persisted onto the
        /// file system without any additional processing.
        /// </summary>
        /// <param name="data">Private key to PEM encode.</param>
        /// <returns>Byte array containing the PEM encoded private
        /// key.</returns>
        private byte[] PemEncodePrivateKey(AsymmetricKeyParameter data) {
            Pkcs8Generator builder = new Pkcs8Generator(data);
            builder.SecureRandom = new SecureRandom(new CryptoApiRandomGenerator());
            builder.Password = _pwd.ToManagedString().ToCharArray();
            PemObject obj = builder.Generate();
            using (MemoryStream stream = new MemoryStream()) {
                using (StreamWriter writer = new StreamWriter(stream, Encoding.ASCII)) {
                    PemWriter pemWriter = new PemWriter(writer);
                    pemWriter.WriteObject(obj);
                    pemWriter.Writer.Close();
                    return stream.ToArray();
                }
            }
        }

        /// <summary>
        /// Deserializes from a PEM encoded private key the public/private RSA
        /// key pair.
        /// </summary>
        /// <param name="data">Is the PEM encoded RSA private key.</param>
        /// <returns>Instance of type <see cref="AsymmetricCipherKeyPair"/>
        /// containing the RSA public and private keys.</returns>
        private AsymmetricCipherKeyPair PemDecodeKeyPair(byte[] data) {
            using (TextReader reader = new StringReader(Encoding.UTF8.GetString(data))) {
                PasswordFinder pwFinder = new PasswordFinder(_pwd.ToManagedString());
                PemReader pemReader = new PemReader(reader, pwFinder);
                //keyPair = pemReader.ReadObject() as AsymmetricCipherKeyPair;
                object obj = pemReader.ReadObject();
                pemReader.Reader.Close();
                RsaPrivateCrtKeyParameters rsaPrivatekey = (RsaPrivateCrtKeyParameters)obj;
                RsaKeyParameters rsaPublicKey = new RsaKeyParameters(false, rsaPrivatekey.Modulus, rsaPrivatekey.PublicExponent);
                AsymmetricCipherKeyPair kp = new AsymmetricCipherKeyPair(rsaPublicKey, rsaPrivatekey);
                return kp;
            }
        }

        /// <summary>
        /// Saves a RSA encrypted private key as a PEM encoded file.
        /// </summary>
        private void SavePrivateKeyAsPemFile() {
            //if (_encryptedPrivateKeyInfo != null) {
            if (_privateKeyInfo != null) {
                if (_overwriteExisting || !File.Exists(_clientPrivateKeyPemFile)) {
                    if (File.Exists(_clientPrivateKeyPemFile))
                        File.Delete(_clientPrivateKeyPemFile);
                    byte[] data = PemEncodePrivateKey(_privateKeyInfo);
                    using (FileStream fs = File.OpenWrite(_clientPrivateKeyPemFile)) {
                        fs.Write(data, 0, data.Length);
                    }
                }
                else
                    throw new Exception();
            }
            else
                throw new Exception();
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="certificate"></param>
        private void SaveCertificateAsPemFile(X509Certificate certificate) {
            if (certificate != null) {
                if (_overwriteExisting || !File.Exists(_clientCertPemFile)) {
                    if (File.Exists(_clientCertPemFile))
                        File.Delete(_clientCertPemFile);
                    byte[] data = Certificator.SerializeCert(certificate);
                    using (FileStream fs = File.OpenWrite(_clientCertPemFile)) {
                        fs.Write(data, 0, data.Length);
                    }
                }
                else
                    throw new Exception("Certificate already exists");
            }
            else
                throw new Exception("Certificate instance is null");
        }

        #endregion Private method
    }

    class PasswordFinder : IPasswordFinder
    {
        private SecureString pwd;
        //private char[] pwd;

        public PasswordFinder(string passphrase) {
            pwd = passphrase.ToSecureString();
            //pwd = passphrase.ToCharArray();
        }

        public char[] GetPassword() => pwd.ToManagedString().ToCharArray();
    }
}