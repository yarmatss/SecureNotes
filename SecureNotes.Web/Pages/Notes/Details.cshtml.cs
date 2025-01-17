using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SecureNotes.Web.Models;
using SecureNotes.Web.Models.Enums;
using SecureNotes.Web.Services;

namespace SecureNotes.Web.Pages.Notes;

[Authorize]
public class DetailsModel : PageModel
{
    private readonly INoteService _noteService;
    private readonly UserManager<User> _userManager;
    private readonly ILogger<DetailsModel> _logger;

    public DetailsModel(
        INoteService noteService,
        UserManager<User> userManager,
        ILogger<DetailsModel> logger)
    {
        _noteService = noteService ?? throw new ArgumentNullException(nameof(noteService));
        _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public Note? Note { get; set; }

    [BindProperty]
    public string? DecryptionPassword { get; set; }

    public bool IsEncrypted => Note?.IsEncrypted ?? false;
    public bool IsDecrypted { get; set; }
    public bool CanBeShared => Note?.AccessLevel == NoteAccessLevel.Shared;

    [TempData]
    public string? ErrorMessage { get; set; }

    public async Task<IActionResult> OnGetAsync(int id)
    {
        if (_userManager == null || User == null)
            return RedirectToPage("/Account/Login");

        var userId = _userManager.GetUserId(User);
        Note = await _noteService.GetAsync(id, userId!);

        if (Note == null)
            return NotFound();

        return Page();
    }

    public async Task<IActionResult> OnPostDecryptAsync(int id)
    {
        await Task.Delay(1000);

        if (string.IsNullOrEmpty(DecryptionPassword))
        {
            ModelState.AddModelError(string.Empty, "Password is required");
            return await LoadNote(id);
        }

        var userId = _userManager.GetUserId(User);
        Note = await _noteService.GetAsync(id, userId!, DecryptionPassword);

        if (Note == null || Note.IsEncrypted && string.IsNullOrEmpty(Note.Content))
        {
            ModelState.AddModelError(string.Empty, "Invalid decryption password");
            return await LoadNote(id);
        }

        IsDecrypted = true;
        return Page();
    }

    private async Task<IActionResult> LoadNote(int id)
    {
        var userId = _userManager.GetUserId(User);
        Note = await _noteService.GetAsync(id, userId!);

        if (Note == null)
            return NotFound();

        return Page();
    }

    public async Task<IActionResult> OnPostDeleteAsync(int id)
    {
        var userId = _userManager.GetUserId(User);
        var result = await _noteService.DeleteAsync(id, userId!);

        if (!result)
        {
            ErrorMessage = "Unable to delete note.";
            return await LoadNote(id);
        }

        return RedirectToPage("./Index");
    }
}