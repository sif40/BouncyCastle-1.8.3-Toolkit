using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Text;

namespace ConsoleApp1
{
    public class Signer
    {
        /// <summary>
        /// Generates a signature of the data submitted.
        /// </summary>
        /// <param name="data">Data to sign.</param>
        /// <param name="entity"><inheritdoc cref="IUUID"/> of the entity to
        /// sign.</param>
        /// <param name="signer"><inheritdoc cref="IUUID"/> of the signing
        /// user.</param>
        /// <param name="keyPair">RSA key pair of the user who is going to
        /// sign.</param>
        /// <returns>Base 64 encoded signature as a string.</returns>
        public static EntitySignature GetSignature(byte[] data, IUUID entity, IUUID signer, RsaKeyPair keyPair)
            => new EntitySignature(entity, signer, SignData(data, keyPair));

        /// <summary>
        /// Generates a signature of the data submitted.
        /// </summary>
        /// <param name="data">Data to sign.</param>
        /// <param name="entity"><inheritdoc cref="IUUID"/> of the entity to
        /// sign.</param>
        /// <param name="signer"><inheritdoc cref="IUUID"/> of the signing
        /// user.</param>
        /// <param name="keyPair">RSA key pair of the user who is going to
        /// sign.</param>
        /// <returns><see cref="EntitySignature"/> instance containing the base
        /// 64 encoded signature.</returns>
        public static EntitySignature GetSignature(string data, IUUID entity, IUUID signer, RsaKeyPair keyPair)
            => new EntitySignature(entity, signer, SignData(Encoding.UTF8.GetBytes(data), keyPair));

        /// <summary>
        /// Method calculating the actual data signature.
        /// </summary>
        /// <param name="data">Data to calculate the signature from.</param>
        /// <param name="keyPair"><see cref="RsaKeyPair"/> instance containig
        /// the private key used to sign with.</param>
        /// <returns>Base 64 encoded signature as a string.</returns>
        private static string SignData(byte[] data, RsaKeyPair keyPair) {
            ISigner sign = SignerUtilities.GetSigner(EncryptionParameters.HASH_ENCRYPTION_ALGORITHM);
            sign.Init(true, keyPair.PrivateKey);
            sign.BlockUpdate(data, 0, data.Length);
            byte[] signature = sign.GenerateSignature();
            return signature.ToBase64String();
        }

        /// <summary>
        /// Verifies if the entity signature is authentic.
        /// </summary>
        /// <param name="data">Unsigned entity data to verify.</param>
        /// <param name="signature">Base 64 encoded signature to validate
        /// against.</param>
        /// <param name="certificate"><see cref="X509Certificate"/> of the
        /// signer.</param>
        /// <returns>True if the signature is authentic.</returns>
        public static bool ValidateSignature(byte[] data, string signature, X509Certificate certificate) {
            ISigner signer = SignerUtilities.GetSigner(EncryptionParameters.HASH_ENCRYPTION_ALGORITHM);
            byte[] sigBytes = Convert.FromBase64String(signature);
            signer.Init(false, certificate.GetPublicKey());
            signer.BlockUpdate(data, 0, data.Length);
            return signer.VerifySignature(sigBytes);
        }

        /// <summary>
        /// Verifies if the entity signature is authentic.
        /// </summary>
        /// <param name="data">Native string data to verify.</param>
        /// <param name="signature">Base 64 encoded signature to validate
        /// against.</param>
        /// <param name="certificate"><see cref="X509Certificate"/> of the
        /// signer.</param>
        /// <returns>True if the signature is authentic.</returns>
        public static bool ValidateSignature(string data, string signature, X509Certificate certificate) {
            ISigner signer = SignerUtilities.GetSigner(EncryptionParameters.HASH_ENCRYPTION_ALGORITHM);
            byte[] sigBytes = Convert.FromBase64String(signature);
            byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            signer.Init(false, certificate.GetPublicKey());
            signer.BlockUpdate(dataBytes, 0, dataBytes.Length);
            return signer.VerifySignature(sigBytes);
        }
    }
}
