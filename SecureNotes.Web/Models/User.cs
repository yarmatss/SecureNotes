using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace SecureNotes.Web.Models;

public class User : IdentityUser
{
    [Required]
    [Base64String]
    public string? SigningPublicKey { get; set; }

    [Required]
    [Base64String]
    public string? EncryptedSigningPrivateKey { get; set; }

    [Required]
    [Base64String]
    public string? PrivateKeyIV { get; set; }

    [Required]
    [Base64String]
    public string? PrivateKeySalt { get; set; }

    public virtual ICollection<Note> Notes { get; set; } = new List<Note>();
    public virtual ICollection<NoteShare> SharedWithMe { get; set; } = new List<NoteShare>();
}
