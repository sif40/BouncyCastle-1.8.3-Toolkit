using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections;
using System.Globalization;
using System.IO;
using System.Text;

namespace ConsoleApp1
{
    public class Certificator : IConfigurable
    {
        // configuration parameters - server CA PEM formatted certificate file path
        private static string _caCert = "";
        // configuration parameters - server CA PEM formatted unencrypted private key file path
        private static string _caPrivKey = "";
        // configuration parameters - number of days a signed certificate is declared as valid
        private static int _certValidity = 0;
        // certificate signing and encryption algorithm
        public static string HASH_ENCRYPTION_ALGORITHM = EncryptionParameters.HASH_ENCRYPTION_ALGORITHM;
        // serial number
        private DateTime _serialNumStart;

        #region Public method

        /// <summary>
        /// Constructor needed for the IConfigurable interface.
        /// </summary>
        public Certificator() {
            if (!IsConfigured)
                Configure();
        }

        /// <summary>
        /// Generates a cert request (csr).
        /// </summary>
        /// <param name="keyPair">Is the public / private key pair of the
        /// client generating a cert request.</param>
        /// <param name="country">Is the optional country value of the client generating
        /// a cert request.</param>
        /// <param name="state">Is the optional state name value of the client generating
        /// a cert request.</param>
        /// <param name="city">Is the optional city name value of the client generating
        /// a cert request.</param>
        /// <param name="orgName">Is the optional organization name value of the 
        /// client generating a cert request.</param>
        /// <param name="email">Is the optional email value of the client generating
        /// a cert request.</param>
        /// <param name="userId">Is the compulsory user ID value of the client generating
        /// a cert request.</param>
        /// <returns>Certificate request</returns>
        /// <exception cref="UserIDException">Throws this exception if the user ID
        /// is set to null.</exception>
        public static byte[] CreateCsr(RsaKeyPair keyPair,
                                       RegionInfo country,
                                       string state,
                                       string city,
                                       string orgName,
                                       string email,
                                       Guid userId) {
            IDictionary attributes = new Hashtable();
            attributes.Add(X509Name.C, country?.TwoLetterISORegionName ?? "");
            attributes.Add(X509Name.ST, state ?? "");
            attributes.Add(X509Name.L, city ?? "");
            attributes.Add(X509Name.O, orgName ?? "");
            attributes.Add(X509Name.EmailAddress, email ?? "");
            if (userId == null)
                throw new Exception();
            attributes.Add(X509Name.CN, userId.ToString());

            X509Name subject = new X509Name(new ArrayList(attributes.Keys), attributes);

            ISignatureFactory signatureFactory = new Asn1SignatureFactory(HASH_ENCRYPTION_ALGORITHM,
                                                                          keyPair.PrivateKeyParameters,
                                                                          new SecureRandom());

            Pkcs10CertificationRequest csr = new Pkcs10CertificationRequest(signatureFactory,
                                                                            subject,
                                                                            keyPair.PublicKeyParameters,
                                                                            null);
            return SerializeCsr(csr);
        }

        /// <summary>
        /// Signs a cert request with the server CA certificate and returns 
        /// a signed x509 certificate.
        /// </summary>
        /// <param name="serializedCsr">Is the serialized cert request (csr).</param>
        /// <returns>Signed x509 certificate.</returns>
        /// <exception cref="CertificateIOException">Thrown when the 
        /// <see cref="serializedCsr"/> is either null or zero length.</exception>
        public X509Certificate SignCsr(byte[] serializedCsr) {
            if (serializedCsr == null || serializedCsr.Length == 0)
                throw new Exception();
            X509Certificate issuer = GetCACert();
            Pkcs10CertificationRequest pkcsr = DeserializeCsr(serializedCsr);

            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
            TimeSpan ts = DateTime.Now.Subtract(_serialNumStart);
            certGen.SetSerialNumber(BigInteger.ValueOf(ts.Ticks));
            certGen.SetIssuerDN(issuer.SubjectDN);
            certGen.SetNotBefore(DateTime.Today);
            certGen.SetNotAfter(DateTime.Today.AddDays(_certValidity));
            certGen.SetSubjectDN(pkcsr.GetCertificationRequestInfo().Subject);
            certGen.SetPublicKey(pkcsr.GetPublicKey());
            certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
              new AuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pkcsr.GetPublicKey())));
            certGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(
                KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment));
            ISignatureFactory signatureFactory =
                new Asn1SignatureFactory(HASH_ENCRYPTION_ALGORITHM, GetCAPrivKey(), new SecureRandom());
            return certGen.Generate(signatureFactory);
        }

        /// <summary>
        /// Tests if the x509 certificate has been signed with the server CA certificate.
        /// </summary>
        /// <param name="data">Serialized x509 certificate.</param>
        /// <returns>True if certificate has been signed by the server CA.</returns>
        /// <exception cref="CertificateIOException">Thrown when the 
        /// <see cref="data"/> is either null or zero length.</exception>
        public bool IsSignedByServer(byte[] data) {
            if (data == null || data.Length == 0)
                throw new Exception();
            X509Certificate issuer = GetCACert();
            X509Certificate certificate = DeserializeCert(data);
            try {
                certificate.Verify(issuer.GetPublicKey());
                return true;
            }
            catch (Exception) {
                return false;
            }
        }

        /// <summary>
        /// Tests if the x509 certificate has been signed with the server CA certificate.
        /// </summary>
        /// <param name="certificate">x509 certificate instance to validate.</param>
        /// <returns>True if certificate has been signed by the server CA.</returns>
        public bool IsSignedByServer(X509Certificate certificate) {
            X509Certificate issuer = GetCACert();
            try {
                certificate.Verify(issuer.GetPublicKey());
                return true;
            }
            catch (Exception) {
                return false;
            }
        }

        /// <summary>
        /// Returns the number of days the certificate remains valid.
        /// </summary>
        /// <param name="certificate">x509 certificate instance to validate.</param>
        /// <returns>Number of days.</returns>
        public static int GetRemainingDays(X509Certificate certificate) 
            => certificate.NotAfter.Subtract(DateTime.Now).Days;

        /// <summary>
        /// Test if the signed x509 certificate has been expired.
        /// </summary>
        /// <param name="data">PEM formatted certificate byte array.</param>
        /// <returns></returns>
        /// <exception cref="CertificateIOException">Thrown when the 
        /// <see cref="data"/> is either null or zero length.</exception>
        public static bool IsExpired(byte[] data) {
            if (data == null || data.Length == 0)
                throw new Exception();
            X509Certificate certificate = DeserializeCert(data);
            try {
                certificate.CheckValidity(DateTime.Now);
                return false;
            }
            catch (Exception) {
                return true;
            }
        }

        /// <summary>
        /// Test if the signed x509 certificate has been expired.
        /// </summary>
        /// <param name="certificate">x509 certificate instance to validate.</param>
        /// <returns></returns>
        public static bool IsExpired(X509Certificate certificate) {
            try {
                certificate.CheckValidity(DateTime.Now);
                return false;
            }
            catch (Exception) {
                return true;
            }
        }

        /// <summary>
        /// Serializes a <see cref="X509Certificate"/> instance.
        /// </summary>
        /// <param name="certificate">x509 certificate instance.</param>
        /// <returns>PEM formatted certificate byte array.</returns>
        public static byte[] SerializeCert(X509Certificate certificate) {
            if (certificate == null)
                throw new Exception();
            using (MemoryStream stream = new MemoryStream()) {
                using (StreamWriter writer = new StreamWriter(stream, Encoding.ASCII)) {
                    PemWriter pemWriter = new PemWriter(writer);
                    pemWriter.WriteObject(certificate);
                    pemWriter.Writer.Flush();
                    pemWriter.Writer.Close();
                    return stream.ToArray();
                }
            }
        }

        /// <summary>
        /// Deserializes a PEM formatted certificate byte array into
        /// a <see cref="X509Certificate"/> instance.
        /// </summary>
        /// <param name="data">PEM formatted certificate byte array.</param>
        /// <returns><see cref="X509Certificate"/> instance.</returns>
        /// <exception cref="CertificateIOException">Thrown when the 
        /// <see cref="data"/> is either null or zero length.</exception>
        public static X509Certificate DeserializeCert(byte[] data) {
            if (data == null || data.Length == 0)
                throw new Exception();
            using (MemoryStream stream = new MemoryStream(data)) {
                using (StreamReader reader = new StreamReader(stream)) {
                    PemReader pemReader = new PemReader(reader);
                    X509Certificate cert = (X509Certificate)pemReader.ReadObject();
                    pemReader.Reader.Close();

                    try {
                        cert.CheckValidity();
                        return cert;
                    }
                    catch (Exception) {
                        return null;
                    }
                }
            }
        }

        /// <summary>
        /// <see cref="IConfigurable"/>
        /// </summary>
        public void Configure() {
            _caCert = @"w:\fooCA.crt";
            _caPrivKey = @"w:\fooCA.pem";
            _certValidity = 10;
            _serialNumStart = new DateTime(1968, 1, 27);
            _isConfigured = true;
        }

        private bool _isConfigured = false;

        public bool IsConfigured => _isConfigured;

        #endregion Public method

        #region Private method

        /// <summary>
        /// Reads the server CA certificate from the file system and returns
        /// a <see cref="X509Certificate"/> instance.
        /// </summary>
        /// <returns><see cref="X509Certificate"/> instance.</returns>
        /// <exception cref="CryptoAssetException">Thrown when the certificate
        /// file could not be found.</exception>
        private X509Certificate GetCACert() {
            if (!File.Exists(_caCert))
                throw new Exception("CA certificate not found on storage!");
            X509CertificateParser certParser = new X509CertificateParser();
            using (Stream stream = new FileStream(_caCert, FileMode.Open)) {
                X509Certificate certificate = certParser.ReadCertificate(stream);
                return certificate;
            }
        }

        /// <summary>
        /// Reads the server CA private key from the file system and returns
        /// a <see cref="AsymmetricKeyParameter"/> instance.
        /// </summary>
        /// <returns><see cref="AsymmetricKeyParameter"/> instance.</returns>
        /// <exception cref="CryptoAssetException">Thrown when the key file
        /// could not be found.</exception>
        private AsymmetricKeyParameter GetCAPrivKey() {
            if (!File.Exists(_caPrivKey))
                throw new Exception("CA private key not found on storage!");
            AsymmetricCipherKeyPair keyPair;

            using (StreamReader reader = File.OpenText(_caPrivKey))
                keyPair = (AsymmetricCipherKeyPair)new PemReader(reader).ReadObject();

            return keyPair.Private;
        }

        //public static string SerializeToString(X509Certificate cert) {
        //    using (var memoryStream = new MemoryStream()) {
        //        using (var streamWriter = new StreamWriter(memoryStream)) {
        //            var pemWriter = new PemWriter(streamWriter);
        //            pemWriter.WriteObject(cert);
        //            pemWriter.Writer.Flush();
        //            return Encoding.ASCII.GetString(memoryStream.GetBuffer());
        //        }
        //    }
        //}

        /// <summary>
        /// Serializes a <see cref="Pkcs10CertificationRequest"/> certificate
        /// request (csr) instance.
        /// </summary>
        /// <param name="csr">Certificate request instance.</param>
        /// <returns>PEM formatted csr byte array.</returns>
        /// <exception cref="CsrIOException">Throw when the 
        /// <see cref="csr"/> is null.</exception>
        private static byte[] SerializeCsr(Pkcs10CertificationRequest csr) {
            if (csr == null)
                throw new Exception();
            using (MemoryStream stream = new MemoryStream()) {
                using (StreamWriter writer = new StreamWriter(stream, Encoding.ASCII)) {
                    PemWriter pemWriter = new PemWriter(writer);
                    pemWriter.WriteObject(csr);
                    pemWriter.Writer.Flush();
                    pemWriter.Writer.Close();
                    return stream.GetBuffer();
                }
            }
        }

        /// <summary>
        /// Deserializes a PEM formatted certificate request (csr) byte array 
        /// into a <see cref="Pkcs10CertificationRequest"/> instance.
        /// </summary>
        /// <param name="data">PEM formatted csr byte array.</param>
        /// <returns><see cref="Pkcs10CertificationRequest"/> instance.</returns>
        /// <exception cref="CsrIOException">Thrown when the 
        /// <see cref="data"/> is either null or zero length.</exception>
        private static Pkcs10CertificationRequest DeserializeCsr(byte[] data) {
            if (data == null || data.Length == 0)
                throw new Exception();
            using (MemoryStream stream = new MemoryStream(data)) {
                using (StreamReader reader = new StreamReader(stream)) {
                    PemReader pemReader = new PemReader(reader);
                    Pkcs10CertificationRequest csr = pemReader.ReadObject() as Pkcs10CertificationRequest;
                    pemReader.Reader.Close();
                    return csr;
                }
            }
        }

        #endregion Private method
    }
}
