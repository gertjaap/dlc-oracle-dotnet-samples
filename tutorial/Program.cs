using System;
using System.IO;
using System.Security.Cryptography;
using Mit.Dci.DlcOracle;
using System.Threading;

namespace tutorial
{
    class Program
    {
        static Random rand = new Random();

        static byte[] privateKey;
        static void Main(string[] args)
        {
            privateKey = GetOrCreateKey();

            byte[] pubKey = Oracle.PublicKeyFromPrivateKey(privateKey);
            Console.WriteLine("Oracle Public Key: {0}", BitConverter.ToString(pubKey).Replace("-",""));

            while(true) {
                byte[] oneTimeSigningKey = Oracle.GenerateOneTimeSigningKey();
                byte[] rPoint = Oracle.PublicKeyFromPrivateKey(oneTimeSigningKey);
                Console.WriteLine("R-Point for next publication: {0}", BitConverter.ToString(rPoint).Replace("-",""));
               
                Thread.Sleep(600);

                // Value is a random number between 10000 and 20000
                long value = rand.Next(10000,20000);

                // Generate message to sign. Uses the same encoding as expected by LIT when settling the contract
                byte[] message = Oracle.GenerateNumericMessage(value);
                
                // Sign the message
                byte[] signature = Oracle.ComputeSignature(privateKey, oneTimeSigningKey, message);
               
                Console.WriteLine("Value: {0}\r\nSignature: {1}", value,
                                BitConverter.ToString(signature).Replace("-",""));
            }
        }
    
        static RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
        static byte[] GetOrCreateKey() {
            byte[] privKey;
            if(File.Exists("privkey.hex")) {
                privKey = File.ReadAllBytes("privkey.hex");
            } else {
                privKey = new byte[32];
                rngCsp.GetBytes(privKey);
                File.WriteAllBytes("privkey.hex", privKey);
            }
            return privKey;
        }
    }
}
