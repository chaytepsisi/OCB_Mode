using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OCB_Mode
{
    class OCB
    {
        static readonly int MAC_SIZE_BITS = 128;

        public static byte[] Encrypt(byte[] input, byte[] associatedData, byte[] key, byte[] nonce)
        {
            OcbBlockCipher ocb = new OcbBlockCipher(new AesEngine(), new AesEngine());
            AeadParameters parameters = new AeadParameters(
                new KeyParameter(key),
                MAC_SIZE_BITS,
                nonce,
                associatedData
            );
            ocb.Init(true, parameters);
            byte[] output = new byte[ocb.GetOutputSize(input.Length)];
            int length = ocb.ProcessBytes(input, 0, input.Length, output, 0);
            length += ocb.DoFinal(output, length);

            byte[] result = new byte[length];
            Array.Copy(output, 0, result, 0, length);
            return result;
        }
        public static byte[] Decrypt(byte[] cipherText, byte[] associatedData, byte[] key, byte[] nonce)
        {
            OcbBlockCipher ocb = new OcbBlockCipher(new AesEngine(), new AesEngine());
            AeadParameters parameters = new AeadParameters(
                new KeyParameter(key),
                MAC_SIZE_BITS,
                nonce,
                associatedData
            );
            ocb.Init(false, parameters);
            // Çıkış verisi
            byte[] output = new byte[ocb.GetOutputSize(cipherText.Length)];
            // Şifre çözme işlemi
            int length = ocb.ProcessBytes(cipherText, 0, cipherText.Length, output, 0);
            length += ocb.DoFinal(output, length);

            // Sonucu döndür
            byte[] result = new byte[length];
            Array.Copy(output, 0, result, 0, length);
            return result;
        }
    }
}
