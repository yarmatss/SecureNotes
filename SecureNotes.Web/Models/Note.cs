using SecureNotes.Web.Models.Enums;
using System.ComponentModel.DataAnnotations;

namespace SecureNotes.Web.Models;

public class Note : IValidatableObject
{
    public int Id { get; set; }

    [Required(ErrorMessage = "Title is required")]
    [StringLength(200, MinimumLength = 3, ErrorMessage = "Title must be between 3 and 200 characters")]
    [RegularExpression(@"^[a-zA-Z0-9\s\-_\.]+$", ErrorMessage = "Title can only contain letters, numbers, spaces and -_.")]
    public string Title { get; set; } = string.Empty;

    [Required(ErrorMessage = "Content is required")]
    [StringLength(50000, ErrorMessage = "Content cannot exceed 50000 characters")]
    public string Content { get; set; } = string.Empty;
    public bool IsEncrypted { get; set; }

    [StringLength(70000)]
    public string? EncryptedContent { get; set; }

    [Base64String(ErrorMessage = "InitVector must be a valid Base64 string")]
    [StringLength(32, ErrorMessage = "InitVector must be 32 characters")]
    public string? InitVector { get; set; }  // For AES encryption

    [Base64String(ErrorMessage = "Salt must be a valid Base64 string")]
    [StringLength(128)]
    public string? Salt { get; set; }  // For password-based key derivation

    public DateTime CreatedAt { get; set; }

    [DataType(DataType.DateTime)]
    public DateTime? ModifiedAt { get; set; }

    [Required(ErrorMessage = "Author ID is required")]
    public string AuthorId { get; set; } = string.Empty;

    [Base64String(ErrorMessage = "Signature must be a valid Base64 string")]
    public string? Signature { get; set; }  // Digital signature
    public NoteAccessLevel AccessLevel { get; set; }

    public virtual User Author { get; set; } = null!;
    public virtual ICollection<NoteShare> SharedWith { get; set; } = new List<NoteShare>();

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (IsEncrypted)
        {
            if (string.IsNullOrEmpty(EncryptedContent))
                yield return new ValidationResult("Encrypted content is required when note is encrypted",
                    new[] { nameof(EncryptedContent) });

            if (string.IsNullOrEmpty(InitVector))
                yield return new ValidationResult("InitVector is required when note is encrypted",
                    new[] { nameof(InitVector) });

            if (string.IsNullOrEmpty(Salt))
                yield return new ValidationResult("Salt is required when note is encrypted",
                    new[] { nameof(Salt) });
        }
    }
}