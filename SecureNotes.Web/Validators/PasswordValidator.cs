namespace SecureNotes.Web.Validators;

public class PasswordValidator
{
    private const double MinEntropy = 3.0;

    public static (bool IsValid, string Message, double Entropy) Validate(string? password)
    {
        if (string.IsNullOrEmpty(password))
            return (false, "Password is required", 0);

        var entropy = CalculateEntropy(password);
        var score = CalculateScore(password);

        if (password.Length < 12)
            return (false, "Password must have at least 12 characters", entropy);

        if (score < 3)
            return (false, "Password must have 3 of 4: capital letters, small letters, digits, special characters", entropy);

        if (entropy < MinEntropy)
            return (false, $"Password is too weak (entropy: {entropy:F2})", entropy);

        return (true, string.Empty, entropy);
    }

    private static double CalculateEntropy(string password)
    {
        var frequencies = password
            .GroupBy(c => c)
            .ToDictionary(g => g.Key, g => (double)g.Count() / password.Length);

        return -frequencies.Sum(f => f.Value * Math.Log2(f.Value));
    }

    private static int CalculateScore(string password)
    {
        int score = 0;
        if (password.Any(char.IsUpper)) score++;
        if (password.Any(char.IsLower)) score++;
        if (password.Any(char.IsDigit)) score++;
        if (password.Any(c => !char.IsLetterOrDigit(c))) score++;
        return score;
    }
}