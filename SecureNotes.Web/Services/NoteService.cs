using SecureNotes.Web.Data;
using SecureNotes.Web.Models.Enums;
using SecureNotes.Web.Models;
using Microsoft.EntityFrameworkCore;
using SecureNotes.Web.Models.DTOs;
using Microsoft.AspNetCore.Identity;
using System.Security;

namespace SecureNotes.Web.Services;

public class NoteService : INoteService
{
    private readonly ApplicationDbContext _context;
    private readonly ISigningService _signingService;
    private readonly IEncryptionService _encryptionService;
    private readonly UserManager<User> _userManager;
    private readonly ILogger<NoteService> _logger;

    public NoteService(
        ApplicationDbContext context,
        ISigningService signingService,
        IEncryptionService encryptionService,
        ILogger<NoteService> logger,
        UserManager<User> userManager)
    {
        _context = context;
        _signingService = signingService;
        _encryptionService = encryptionService;
        _logger = logger;
        _userManager = userManager;
    }

    public async Task<Note> CreateAsync(NoteDTO noteDto, string userId)
    {
        _logger.LogDebug("Creating note. IsEncrypted: {IsEncrypted}", noteDto.IsEncrypted);

        try
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                throw new ArgumentException("User not found");

            var note = new Note
            {
                Title = noteDto.Title,
                AuthorId = userId,
                CreatedAt = DateTime.UtcNow,
                IsEncrypted = noteDto.IsEncrypted,
                AccessLevel = noteDto.AccessLevel
            };

            var signingToken = await _userManager.GetAuthenticationTokenAsync(
                user, "SecureNotes", "SigningToken");

            if (noteDto.IsEncrypted)
            {
                var encryptionResult = await _encryptionService.EncryptAsync(
                    noteDto.Content,
                    noteDto.CurrentPassword!);

                note.EncryptedContent = encryptionResult.encryptedContent;
                note.InitVector = encryptionResult.iv;
                note.Salt = encryptionResult.salt;

                note.Signature = await _signingService.SignAsync(
                    note.EncryptedContent,
                    user.EncryptedSigningPrivateKey!,
                    user.PrivateKeyIV!,
                    user.PrivateKeySalt!,
                    signingToken!);

                _logger.LogDebug("Note encrypted and signed. Content length: {Length}",
                    note.EncryptedContent.Length);
            }
            else
            {
                note.Content = noteDto.Content;
                note.Signature = await _signingService.SignAsync(
                    noteDto.Content,
                    user.EncryptedSigningPrivateKey!,
                    user.PrivateKeyIV!,
                    user.PrivateKeySalt!,
                    signingToken!);

                _logger.LogDebug("Note signed. Content length: {Length}",
                    note.Content.Length);
            }

            await _context.Notes.AddAsync(note);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Note {NoteId} created successfully by user {UserId}",
                note.Id, userId);
            return note;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create note for user {UserId}", userId);
            throw;
        }
    }

    public async Task<Note?> GetAsync(int id, string userId, string? password = null)
    {
        var note = await _context.Notes
            .Include(n => n.Author)
            .Include(n => n.SharedWith)
            .FirstOrDefaultAsync(n => n.Id == id);

        if (note == null)
        {
            _logger.LogWarning("Note {NoteId} not found", id);
            return null;
        }

        bool canAccess = note.AuthorId == userId ||
                        note.AccessLevel == NoteAccessLevel.Public ||
                        note.SharedWith.Any(s => s.UserId == userId);

        if (!canAccess)
        {
            _logger.LogWarning("Unauthorized access attempt to note {NoteId} by user {UserId}", id, userId);
            return null;
        }

        var isValid = await _signingService.VerifyAsync(
            note.IsEncrypted ? note.EncryptedContent! : note.Content!,
            note.Signature!,
            note.Author.SigningPublicKey!);

        if (!isValid)
        {
            _logger.LogError("Invalid signature detected for note {NoteId}", id);
            return null;
        }

        if (note.IsEncrypted && !string.IsNullOrEmpty(password))
        {
            try
            {
                var decryptedContent = await _encryptionService.DecryptAsync(
                    note.EncryptedContent!,
                    note.InitVector!,
                    note.Salt!,
                    password);

                if (string.IsNullOrEmpty(decryptedContent))
                    return null;

                note.Content = decryptedContent;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to decrypt note {NoteId}", id);
                return null;
            }
        }

        return note;
    }

    public async Task<IEnumerable<Note>> GetUserNotesAsync(string userId)
    {
        return await _context.Notes
            .Include(n => n.Author)
            .Where(n => n.AuthorId == userId)
            .OrderByDescending(n => n.ModifiedAt ?? n.CreatedAt)
            .ToListAsync();
    }

    public async Task<IEnumerable<Note>> GetSharedNotesAsync(string userId)
    {
        return await _context.Notes
            .Include(n => n.Author)
            .Include(n => n.SharedWith)
            .Where(n => n.AuthorId != userId &&
                       n.SharedWith.Any(s => s.UserId == userId))
            .OrderByDescending(n => n.ModifiedAt ?? n.CreatedAt)
            .ToListAsync();
    }

    public async Task<IEnumerable<Note>> GetPublicNotesAsync(string userId)
    {
        return await _context.Notes
            .Include(n => n.Author)
            .Where(n => n.AuthorId != userId &&
                       n.AccessLevel == NoteAccessLevel.Public)
            .OrderByDescending(n => n.ModifiedAt ?? n.CreatedAt)
            .ToListAsync();
    }

    public async Task<bool> UpdateAsync(NoteDTO noteDto, string userId)
    {
        var user = await _userManager.FindByIdAsync(userId) ?? 
            throw new ArgumentException("User not found");
        var note = await _context.Notes
            .FirstOrDefaultAsync(n => n.Id == noteDto.Id && n.AuthorId == userId);

        if (note == null)
        {
            _logger.LogWarning("Note {NoteId} not found or not owned by user {UserId}",
                noteDto.Id, userId);
            return false;
        }

        var contentToVerify = note.IsEncrypted ? note.EncryptedContent! : note.Content;
        var isValidSignature = await _signingService.VerifyAsync(
            contentToVerify,
            note.Signature!,
            user.SigningPublicKey!);

        if (!isValidSignature)
        {
            _logger.LogWarning("Invalid signature detected for note {NoteId}", noteDto.Id);
            throw new SecurityException("Invalid note signature");
        }

        if (note.IsEncrypted)
        {
            if (string.IsNullOrEmpty(noteDto.CurrentPassword))
                throw new ArgumentException("Note password is required");

            var decrypted = await _encryptionService.DecryptAsync(
                note.EncryptedContent!,
                note.InitVector!,
                note.Salt!,
                noteDto.CurrentPassword);

            if (string.IsNullOrEmpty(decrypted))
                throw new ArgumentException("Invalid current password");

            var passwordToUse = noteDto.ChangePassword ? noteDto.NewPassword! : noteDto.CurrentPassword;
            var result = await _encryptionService.EncryptAsync(noteDto.Content, passwordToUse);

            note.EncryptedContent = result.encryptedContent;
            note.InitVector = result.iv;
            note.Salt = result.salt;
            note.Content = string.Empty;

            var signingToken = await _userManager.GetAuthenticationTokenAsync(
                user, "SecureNotes", "SigningToken");

            note.Signature = await _signingService.SignAsync(
                note.EncryptedContent,
                user.EncryptedSigningPrivateKey!,
                user.PrivateKeyIV!,
                user.PrivateKeySalt!,
                signingToken!);
        }
        else
        {
            note.Content = noteDto.Content;

            var signingToken = await _userManager.GetAuthenticationTokenAsync(
                user, "SecureNotes", "SigningToken");

            note.Signature = await _signingService.SignAsync(
                note.Content,
                user.EncryptedSigningPrivateKey!,
                user.PrivateKeyIV!,
                user.PrivateKeySalt!,
                signingToken!);
        }

        note.Title = noteDto.Title;
        note.ModifiedAt = DateTime.UtcNow;
        note.AccessLevel = noteDto.AccessLevel;

        await _context.SaveChangesAsync();
        _logger.LogInformation("Note {NoteId} updated successfully by user {UserId}",
            noteDto.Id, userId);

        return true;
    }

    public async Task<bool> DeleteAsync(int id, string userId)
    {
        _logger.LogDebug("Attempting to delete note {NoteId} by user {UserId}", id, userId);

        var note = await _context.Notes.FindAsync(id);
        if (note?.AuthorId != userId)
        {
            _logger.LogWarning("Unauthorized deletion attempt of note {NoteId} by user {UserId}",
                id, userId);
            return false;
        }

        try
        {
            _context.Notes.Remove(note);
            await _context.SaveChangesAsync();
            _logger.LogInformation("Note {NoteId} deleted by user {UserId}", id, userId);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to delete note {NoteId}", id);
            throw;
        }
    }

    public async Task<bool> ShareAsync(int noteId, string targetUserId, string ownerId, string password = null!)
    {
        _logger.LogDebug("Attempting to share note {NoteId} with user {TargetUserId}",
            noteId, targetUserId);

        var note = await _context.Notes.FindAsync(noteId);

        if (note == null ||
            note.AuthorId != ownerId ||
            note.AccessLevel != NoteAccessLevel.Shared)
        {
            _logger.LogWarning("Invalid share attempt for note {NoteId} by user {OwnerId}",
                noteId, ownerId);
            return false;
        }

        if (note.IsEncrypted)
        {
            try
            {
                var decrypted = await _encryptionService.DecryptAsync(
                    note.EncryptedContent!,
                    note.InitVector!,
                    note.Salt!,
                    password ?? throw new ArgumentNullException(nameof(password)));

                if (string.IsNullOrEmpty(decrypted))
                    return false;
            }
            catch
            {
                return false;
            }
        }

        var share = new NoteShare
        {
            NoteId = noteId,
            UserId = targetUserId,
            SharedAt = DateTime.UtcNow
        };

        try
        {
            await _context.NoteShares.AddAsync(share);
            await _context.SaveChangesAsync();
            _logger.LogInformation("Note {NoteId} shared with user {TargetUserId} by {OwnerId}",
                noteId, targetUserId, ownerId);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to share note {NoteId} with user {TargetUserId}",
                noteId, targetUserId);
            return false;
        }
    }

    public async Task<bool> RemoveShareAsync(int shareId, string userId)
    {
        var share = await _context.NoteShares
            .Include(ns => ns.Note)
            .FirstOrDefaultAsync(ns => ns.Id == shareId);

        if (share?.Note.AuthorId != userId) return false;

        _context.NoteShares.Remove(share);
        await _context.SaveChangesAsync();
        return true;
    }

    public async Task<IEnumerable<NoteShare>> GetCurrentSharesAsync(int noteId, string userId)
    {
        var note = await _context.Notes.FindAsync(noteId);
        if (note?.AuthorId != userId)
            return new List<NoteShare>();

        return await _context.NoteShares
            .Include(ns => ns.User)
            .Where(ns => ns.NoteId == noteId)
            .ToListAsync();
    }
}