using System.Security.Cryptography;
using System.Text;

namespace SecureNotes.Web.Services;

public class SigningService : ISigningService
{
    private readonly ILogger<SigningService> _logger;
    private readonly IEncryptionService _encryptionService;

    public SigningService(ILogger<SigningService> logger, IEncryptionService encryptionService)
    {
        _logger = logger;
        _encryptionService = encryptionService;
    }

    public async Task<(string publicKey, string encryptedPrivateKey, string iv, string salt)> GenerateKeyPairAsync(string hashedPassword)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = Convert.ToBase64String(ecdsa.ExportECPrivateKey());
        var publicKey = Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());

        var encryptionResult = await _encryptionService.EncryptAsync(privateKey, hashedPassword);
        return (publicKey, encryptionResult.encryptedContent, encryptionResult.iv, encryptionResult.salt);
    }

    public async Task<string> SignAsync(string content, string encryptedPrivateKey, string iv, string salt, string password)
    {
        var privateKey = await DecryptPrivateKeyAsync(encryptedPrivateKey, iv, salt, password);
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ecdsa.ImportECPrivateKey(Convert.FromBase64String(privateKey), out _);

        var contentBytes = Encoding.UTF8.GetBytes(content);
        var signature = ecdsa.SignData(contentBytes, HashAlgorithmName.SHA256);
        return Convert.ToBase64String(signature);
    }

    public async Task<bool> VerifyAsync(string content, string signature, string publicKey)
    {
        return await Task.Run(() =>
        {
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out _);

            var contentBytes = Encoding.UTF8.GetBytes(content);
            var signatureBytes = Convert.FromBase64String(signature);
            return ecdsa.VerifyData(contentBytes, signatureBytes, HashAlgorithmName.SHA256);
        });
    }

    public async Task<string> DecryptPrivateKeyAsync(string encryptedKey, string iv, string salt, string password)
    {
        return await _encryptionService.DecryptAsync(encryptedKey, iv, salt, password);
    }
}
