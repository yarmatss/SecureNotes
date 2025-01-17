namespace SecureNotes.Web.Services;

public interface ISigningService
{
    Task<(string publicKey, string encryptedPrivateKey, string iv, string salt)> GenerateKeyPairAsync(string password);
    Task<string> SignAsync(string content, string encryptedPrivateKey, string iv, string salt, string password);
    Task<bool> VerifyAsync(string content, string signature, string publicKey);
    Task<string> DecryptPrivateKeyAsync(string encryptedKey, string iv, string salt, string password);
}