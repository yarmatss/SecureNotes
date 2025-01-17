using System.Security.Cryptography;

namespace SecureNotes.Web.Services;

public class EncryptionService : IEncryptionService
{
    private const int KeySize = 256;
    private const int BlockSize = 128;
    private const int Iterations = 100000;

    public async Task<(string encryptedContent, string iv, string salt)> EncryptAsync(string content, string password)
    {
        if (string.IsNullOrEmpty(content))
            throw new ArgumentNullException(nameof(content));
        if (string.IsNullOrEmpty(password))
            throw new ArgumentNullException(nameof(password));

        using var aes = Aes.Create();
        aes.KeySize = KeySize;
        aes.BlockSize = BlockSize;

        // Generuj losowe IV i sól
        aes.GenerateIV();
        byte[] salt = new byte[32];
        RandomNumberGenerator.Fill(salt);

        // Derywuj klucz z hasła
        using var deriveBytes = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256);
        aes.Key = deriveBytes.GetBytes(aes.KeySize / 8);

        using var msEncrypt = new MemoryStream();
        using (var encryptor = aes.CreateEncryptor())
        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
        using (var swEncrypt = new StreamWriter(csEncrypt))
        {
            await swEncrypt.WriteAsync(content);
        }

        return (
            Convert.ToBase64String(msEncrypt.ToArray()),
            Convert.ToBase64String(aes.IV),
            Convert.ToBase64String(salt)
        );
    }

    public async Task<string> DecryptAsync(string encryptedContent, string iv, string salt, string password)
    {
        using var aes = Aes.Create();
        aes.KeySize = KeySize;
        aes.BlockSize = BlockSize;
        aes.IV = Convert.FromBase64String(iv);

        byte[] saltBytes = Convert.FromBase64String(salt);
        using var deriveBytes = new Rfc2898DeriveBytes(password, saltBytes, Iterations, HashAlgorithmName.SHA256);
        aes.Key = deriveBytes.GetBytes(aes.KeySize / 8);

        using var msDecrypt = new MemoryStream(Convert.FromBase64String(encryptedContent));
        using var decryptor = aes.CreateDecryptor();
        using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
        using var srDecrypt = new StreamReader(csDecrypt);

        return await srDecrypt.ReadToEndAsync();
    }
}
