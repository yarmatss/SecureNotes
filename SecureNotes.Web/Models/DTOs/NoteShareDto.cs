using System.ComponentModel.DataAnnotations;

namespace SecureNotes.Web.Models.DTOs;

public class NoteShareDTO
{
    public int NoteId { get; set; }

    [Required(ErrorMessage = "Username is required")]
    [StringLength(100, ErrorMessage = "Username can't be longer than {1} characters")]
    [RegularExpression(@"^[a-zA-Z0-9@.\-_]+$", ErrorMessage = "Characters not allowed in the user name")]
    public string TargetUserName { get; set; } = string.Empty;
    public string? EncryptionPassword { get; set; }
}