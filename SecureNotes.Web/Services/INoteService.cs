using SecureNotes.Web.Models;
using SecureNotes.Web.Models.DTOs;

namespace SecureNotes.Web.Services;

public interface INoteService
{
    Task<Note> CreateAsync(NoteDTO noteDto, string userId);
    Task<Note?> GetAsync(int id, string userId, string? password = null);
    Task<IEnumerable<Note>> GetUserNotesAsync(string userId);
    Task<IEnumerable<Note>> GetSharedNotesAsync(string userId);
    Task<IEnumerable<Note>> GetPublicNotesAsync(string userId);
    Task<bool> UpdateAsync(NoteDTO noteDto, string userId);
    Task<bool> DeleteAsync(int id, string userId);
    Task<bool> ShareAsync(int noteId, string targetUserId, string ownerId, string password = null!);
    Task<bool> RemoveShareAsync(int shareId, string userId);
    Task<IEnumerable<NoteShare>> GetCurrentSharesAsync(int noteId, string userId);
}