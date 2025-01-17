using SecureNotes.Web.Models.Enums;

namespace SecureNotes.Web.Models.DTOs;

public class NoteDTO
{
    public int Id { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;
    public bool IsEncrypted { get; set; }
    public NoteAccessLevel AccessLevel { get; set; }
    public string? CurrentPassword { get; set; }
    public string? NewPassword { get; set; }
    public bool ChangePassword { get; set; }
}
