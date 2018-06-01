using System;
using System.IO;
using Mit.Dci.DlcOracle;

namespace Mit.Dci.DlcOracle.Samples.ConsoleApplication
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] privKey;
            if(File.Exists("privkey.hex")) {
                privKey = File.ReadAllBytes("privkey.hex");
            } else {
                privKey = Oracle.GenerateOneTimeSigningKey();
                File.WriteAllBytes("privkey.hex", privKey);
            }

            byte[] pubKey = Oracle.PublicKeyFromPrivateKey(privKey);
            Console.WriteLine("Oracle Public Key: {0}", BitConverter.ToString(pubKey).Replace("-",""));

            while(true) {
                byte[] privPoint = Oracle.GenerateOneTimeSigningKey();
                Console.WriteLine("PrivPoint for next publication: {0}", BitConverter.ToString(privPoint).Replace("-",""));
               byte[] rPoint = Oracle.PublicKeyFromPrivateKey(privPoint);
                Console.WriteLine("R-Point for next publication: {0}", BitConverter.ToString(rPoint).Replace("-",""));
                Console.Write("Enter number to publish (-1 to exit):");
                
                var input = Console.ReadLine();
                long value = 0;
                if(!long.TryParse(input, out value))
                {
                    Console.WriteLine("Couldn't parse input.");
                    continue;
                }

                if(value == -1) break;

                byte[] message = Oracle.GenerateNumericMessage(value);
                Console.WriteLine("Message: {0}", BitConverter.ToString(message).Replace("-",""));
                
                byte[] signature = Oracle.ComputeSignature(privKey, privPoint, message);
                byte[] sGFromSig = Oracle.PublicKeyFromPrivateKey(signature);
                byte[] sGFromPubKeysAndMessage = Oracle.ComputeSignaturePubKey(pubKey, rPoint, message);

                Console.WriteLine("Signature: {0}", BitConverter.ToString(signature).Replace("-",""));
                Console.WriteLine("sG from signature: {0}", BitConverter.ToString(sGFromSig).Replace("-",""));
                Console.WriteLine("sG from pubkeys  : {0}", BitConverter.ToString(sGFromPubKeysAndMessage).Replace("-",""));

            }
        }
    }
}