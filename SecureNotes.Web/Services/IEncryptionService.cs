namespace SecureNotes.Web.Services;

public interface IEncryptionService
{
    Task<(string encryptedContent, string iv, string salt)> EncryptAsync(string content, string password);
    Task<string> DecryptAsync(string encryptedContent, string iv, string salt, string password);
}