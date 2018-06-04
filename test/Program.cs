using System;
using System.IO;
using Mit.Dci.DlcOracle;
using System.Diagnostics;
using System.Linq;

namespace Mit.Dci.DlcOracle.Samples.ConsoleApplication
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] privKey = StringToByteArray(File.ReadAllText("testdata/privkey.hex").Trim());
            byte[] pubKey = Oracle.PublicKeyFromPrivateKey(privKey);
            
            string[] otsKeysHex = File.ReadAllLines("testdata/one-time-signing-keys.hex");
            string[] messagesHex = File.ReadAllLines("testdata/messages.hex");
            string[] sigsHex = File.ReadAllLines("testdata/signatures.hex");
            string[] sGsFromSigHex = File.ReadAllLines("testdata/signature-pubkeys-from-sig.hex");
            string[] sGsFromMsgHex = File.ReadAllLines("testdata/signature-pubkeys-from-message.hex");

            for(int i = 0; i < otsKeysHex.Length; i++) {
                byte[] privPoint = StringToByteArray(otsKeysHex[i]);
                byte[] rPoint = Oracle.PublicKeyFromPrivateKey(privPoint);
                byte[] message = StringToByteArray(messagesHex[i]);
                byte[] expectedSig = StringToByteArray(sigsHex[i]);
                byte[] expectedsG1 = StringToByteArray(sGsFromSigHex[i]);
                byte[] expectedsG2 = StringToByteArray(sGsFromMsgHex[i]);

                byte[] calculatedSig = Oracle.ComputeSignature(privKey, privPoint, message);
                byte[] calculatedsG1 = Oracle.PublicKeyFromPrivateKey(calculatedSig);
                byte[] calculatedsG2 = Oracle.ComputeSignaturePubKey(pubKey, rPoint, message);

                Debug.Assert(expectedsG1.SequenceEqual(expectedsG2), "sGs are not equal. This is an issue in the Go code that generated the testset.", string.Format("Failure in record {0}", i));
                Debug.Assert(calculatedSig.SequenceEqual(expectedSig), "Signature mismatch", string.Format("Failure in record {0} - Expected {1} - Got {2}", i, ByteArrayToString(expectedSig), ByteArrayToString(calculatedSig)));
                Debug.Assert(calculatedsG1.SequenceEqual(expectedsG1), "sG from signature is incorrect", string.Format("Failure in record {0} - Expected {1} - Got {2}", i, ByteArrayToString(expectedsG1), ByteArrayToString(calculatedsG1)));
                Debug.Assert(calculatedsG2.SequenceEqual(expectedsG2), "sG from pubkeys is incorrect", string.Format("Failure in record {0} - Expected {1} - Got {2}", i, ByteArrayToString(expectedsG2), ByteArrayToString(calculatedsG2)));

                if(i % 100 == 0) {
                    Console.Write("\rChecking signatures: {0}", i);
                }
            }

            Console.WriteLine("\rSuccesfully completed signature checking.");

        }

        private static byte[] StringToByteArray(string hex) {
            
                return Enumerable.Range(0, hex.Length)
                     .Where(x => x % 2 == 0)
                     .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                     .ToArray();
        }

         private static string ByteArrayToString(byte[] bytes) {
            return BitConverter.ToString(bytes).Replace("-","");
        }
    }
}