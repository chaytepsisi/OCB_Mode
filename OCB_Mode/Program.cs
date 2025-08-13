
using OCB_Mode;

try
{
    byte[] plainText = Commons.StringToByteArray("0001020304050607");
    byte[] key = Commons.StringToByteArray("000102030405060708090A0B0C0D0E0F");
    byte[] nonce = Commons.StringToByteArray("BBAA99887766554433221101");
    byte[] associatedData = Commons.StringToByteArray("0001020304050607");

    // Şifreleme
    byte[] cipherText = OCB.Encrypt(plainText, associatedData, key, nonce);
    Console.WriteLine("Şifrelenmiş Veri: " + Commons.ByteArrayToString(cipherText));

    // Şifre çözme
    byte[] decryptedText = OCB.Decrypt(cipherText, associatedData, key, nonce);
    Console.WriteLine("Çözülmüş Veri: " + Commons.ByteArrayToString(decryptedText));
}
catch (Exception ex)
{
    Console.WriteLine("Hata: " + ex.Message);
}
