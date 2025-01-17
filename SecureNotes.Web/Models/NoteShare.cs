using System.ComponentModel.DataAnnotations;

namespace SecureNotes.Web.Models;

public class NoteShare
{
    public int Id { get; set; }

    [Required(ErrorMessage = "Note ID is required")]
    public int NoteId { get; set; }

    [Required(ErrorMessage = "User ID is required")]
    public string UserId { get; set; } = string.Empty;

    public DateTime SharedAt { get; set; }

    public virtual Note Note { get; set; } = null!;
    public virtual User User { get; set; } = null!;
}
