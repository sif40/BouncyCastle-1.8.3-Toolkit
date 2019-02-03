using System;
using System.Collections;
using System.Globalization;
using System.Text;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {
            //RsaKeyPair keyRing = new RsaKeyPair("1234", true);
            //Guid guid = Guid.NewGuid();
            //byte[] pemCsr = Certificator.CreateCsr(keyRing,
            //                                       RegionInfo.CurrentRegion,
            //                                       "vd", "cheseaux-noréaz", "sigi", "sigi@nowhere", guid);
            //X509Certificate cert = new Certificator().SignCsr(pemCsr);
            //keyRing.Certificate = cert;
            //keyRing.Save(cert);

            RsaKeyPair keyRing = new RsaKeyPair("1234");
            
            //var remainingDays = Certificator.GetRemainingDays(keyRing.Certificate);
            //var IsExpired = Certificator.IsExpired(keyRing.Certificate);
            //var IsSignedByServer = new Certificator().IsSignedByServer(keyRing.Certificate);

            string plainMessage = "I already have an RSACryptoServiceProvider loaded with private/public keys. From some research " +
                                  "it's my understanding that I would need to do the faster, symmetric encryption to encrypt the data " +
                                  "and then the slower, asymmetric encryption using the certificate to encrypt the key. What I'm having " +
                                  "trouble with is weaving all the online examples together into an encrypt/decrypt function like for signing." +
                                  "This is a message to encrypt 1...2...3";
            //string plainMessage = "This is a message to encrypt...";

            var data = Encoding.UTF8.GetBytes(plainMessage);
            var res = Signer.GetSignature(data, null, null, keyRing);
            // positive test
            bool isValid = Signer.ValidateSignature(data, res.Signature, keyRing.Certificate);
            isValid = Signer.ValidateSignature(plainMessage, res.Signature, keyRing.Certificate);
            // negative test
            data[data.Length - 2] = 0;
            bool notValid = true;
            notValid = Signer.ValidateSignature(data, res.Signature, keyRing.Certificate);
            plainMessage = plainMessage.Replace('2', '9');
            plainMessage = plainMessage.Substring(0, plainMessage.Length-2);
            notValid = Signer.ValidateSignature(data, res.Signature, keyRing.Certificate);

            ArrayList encrytedMessages;
            string result = "";
            Encryptor encryptor = new Encryptor();

            // encrypt with pubKey and decrypt with privKey
            Console.WriteLine("ENCRYPT with PUBLIC KEY and DECRYPT with PRIVATE KEY");
            encrytedMessages = encryptor.RsaEncryptWithPublic(plainMessage, keyRing);
            foreach (var encrytedMessage in encrytedMessages) {
                result = encryptor.RsaDecryptWithPrivate((string)encrytedMessage, keyRing);
                Console.WriteLine(result);
            }

            // encrypt with privKey and decrypt with pubKey - THIS WORKS
            Console.WriteLine("ENCRYPT with PRIVATE KEY and DECRYPT with PUBLIC KEY");
            encrytedMessages = encryptor.RsaEncryptWithPrivate(plainMessage, keyRing);
            foreach (var encrytedMessage in encrytedMessages) {
                result = encryptor.RsaDecryptWithPublic((string)encrytedMessage, keyRing);
                Console.WriteLine(result);
            }

            Console.ReadLine();
        }
    }
}
