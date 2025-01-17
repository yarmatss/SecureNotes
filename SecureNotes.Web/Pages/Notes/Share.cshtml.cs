using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SecureNotes.Web.Models;
using SecureNotes.Web.Models.DTOs;
using SecureNotes.Web.Models.Enums;
using SecureNotes.Web.Services;

namespace SecureNotes.Web.Pages.Notes;

[Authorize]
public class ShareModel : PageModel
{
    private readonly INoteService _noteService;
    private readonly UserManager<User> _userManager;
    private readonly ILogger<ShareModel> _logger;

    public ShareModel(INoteService noteService, UserManager<User> userManager, ILogger<ShareModel> logger)
    {
        _noteService = noteService;
        _userManager = userManager;
        _logger = logger;
    }

    [BindProperty]
    public NoteShareDTO ShareDTO { get; set; } = new();
    public Note? Note { get; set; }
    public IEnumerable<NoteShare> CurrentShares { get; set; } = new List<NoteShare>();

    [TempData]
    public string? StatusMessage { get; set; }

    public async Task<IActionResult> OnGetAsync(int id)
    {
        var userId = _userManager.GetUserId(User);
        Note = await _noteService.GetAsync(id, userId!);

        if (Note == null ||
            Note.AuthorId != userId ||
            Note.AccessLevel != NoteAccessLevel.Shared)
            return NotFound();

        CurrentShares = await _noteService.GetCurrentSharesAsync(id, userId!);
        ShareDTO.NoteId = id;
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
            return await LoadPage();

        var userId = _userManager.GetUserId(User);
        Note = await _noteService.GetAsync(ShareDTO.NoteId, userId!);

        if (Note == null)
            return NotFound();

        var targetUser = await _userManager.FindByNameAsync(ShareDTO.TargetUserName);
        if (targetUser == null)
        {
            ModelState.AddModelError(string.Empty, "User not found");
            return await LoadPage();
        }

        var result = await _noteService.ShareAsync(
            ShareDTO.NoteId,
            targetUser.Id,
            userId!,
            ShareDTO.EncryptionPassword!);

        if (!result)
        {
            ModelState.AddModelError(string.Empty,
                Note.IsEncrypted ? "Invalid password" : "Unable to share note");
            return await LoadPage();
        }

        StatusMessage = "Note shared successfully.";
        return RedirectToPage(new { id = ShareDTO.NoteId });
    }

    public async Task<IActionResult> OnPostRemoveAsync(int shareId, int noteId)
    {
        var userId = _userManager.GetUserId(User);

        // Sprawdü czy notatka istnieje
        var note = await _noteService.GetAsync(noteId, userId!);
        if (note == null)
            return NotFound();

        var result = await _noteService.RemoveShareAsync(shareId, userId!);
        StatusMessage = result ? "Share removed successfully." : "Unable to remove share.";

        return RedirectToPage(new { id = noteId });
    }

    private async Task<IActionResult> LoadPage()
    {
        var userId = _userManager.GetUserId(User);
        Note = await _noteService.GetAsync(ShareDTO.NoteId, userId!);
        CurrentShares = await _noteService.GetCurrentSharesAsync(ShareDTO.NoteId, userId!);
        return Page();
    }
}