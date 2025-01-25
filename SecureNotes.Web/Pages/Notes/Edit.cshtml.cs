using Ganss.Xss;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SecureNotes.Web.Models;
using SecureNotes.Web.Models.DTOs;
using SecureNotes.Web.Services;
using SecureNotes.Web.Validators;

namespace SecureNotes.Web.Pages.Notes;

[Authorize]
public class EditModel : PageModel
{
    private readonly INoteService _noteService;
    private readonly UserManager<User> _userManager;
    private readonly ILogger<EditModel> _logger;
    private readonly IHtmlSanitizer _sanitizer;
    private readonly IMarkdownService _markdownService;

    [BindProperty]
    public NoteDTO Note { get; set; } = new();
    public bool IsDecrypted { get; set; }
    public bool RequiresPassword => Note.IsEncrypted && !IsDecrypted;

    public EditModel(INoteService noteService, 
                    UserManager<User> userManager, 
                    ILogger<EditModel> logger,
                    IHtmlSanitizer htmlSanitizer,
                    IMarkdownService markdownService)
    {
        _noteService = noteService;
        _userManager = userManager;
        _logger = logger;
        _sanitizer = htmlSanitizer;
        _markdownService = markdownService;
    }

    public async Task<IActionResult> OnGetAsync(int id)
    {
        var userId = _userManager.GetUserId(User);
        var note = await _noteService.GetAsync(id, userId!);

        if (note == null || note.AuthorId != userId)
            return NotFound();

        Note = new NoteDTO
        {
            Id = note.Id,
            Title = note.Title,
            Content = note.IsEncrypted ? string.Empty : _markdownService.ConvertHtmlToMarkdown(note.Content),
            IsEncrypted = note.IsEncrypted,
            AccessLevel = note.AccessLevel
        };

        if (!note.IsEncrypted)
        {
            IsDecrypted = true;
        }

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        try
        {
            if (!ModelState.IsValid)
                return Page();

            if (Note.ChangePassword)
            {
                var (isValid, message, _) = PasswordValidator.Validate(Note.NewPassword ?? string.Empty);
                if (!isValid)
                {
                    ModelState.AddModelError("Note.NewPassword", message);
                    return Page();
                }
            }

            Note.Content = _sanitizer.Sanitize(
                _markdownService.RenderHtml(Note.Content)
            );

            var userId = _userManager.GetUserId(User);
            var success = await _noteService.UpdateAsync(Note, userId!);

            if (!success)
            {
                ModelState.AddModelError(string.Empty, "Error while updating note.");
                return Page();
            }

            return RedirectToPage("./MyNotes");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating note");
            ModelState.AddModelError(string.Empty, "Error updating note. Please try again.");
            return Page();
        }
    }

    public async Task<IActionResult> OnPostVerifyPasswordAsync([FromBody] DecryptRequest request)
    {
        await Task.Delay(1000);

        if (string.IsNullOrEmpty(request.Password))
            return new JsonResult(new { success = false, error = "Password is required" });

        var userId = _userManager.GetUserId(User);
        var note = await _noteService.GetAsync(request.Id, userId!, request.Password);

        if (note == null || string.IsNullOrEmpty(note.Content))
            return new JsonResult(new { success = false, error = "Invalid password" });

        return new JsonResult(new
        {
            success = true,
            content = _markdownService.ConvertHtmlToMarkdown(note.Content),
            title = note.Title
        });
    }
}

public class DecryptRequest
{
    public int Id { get; set; }
    public string Password { get; set; } = string.Empty;
}