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
public class CreateModel : PageModel
{
    private readonly INoteService _noteService;
    private readonly UserManager<User> _userManager;
    private readonly ILogger<CreateModel> _logger;
    private readonly IHtmlSanitizer _htmlSanitizer;
    private readonly IMarkdownService _markdownService;

    [BindProperty]
    public NoteDTO Note { get; set; } = new();

    public CreateModel(
        INoteService noteService,
        UserManager<User> userManager,
        ILogger<CreateModel> logger,
        IMarkdownService markdownService,
        IHtmlSanitizer htmlSanitizer)
    {
        _noteService = noteService;
        _userManager = userManager;
        _logger = logger;
        _markdownService = markdownService;
        _htmlSanitizer = htmlSanitizer;
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
            return Page();

        try
        {
            var userId = _userManager.GetUserId(User);

            if (Note.IsEncrypted)
            {
                var (isValid, message, _) = PasswordValidator.Validate(Note.CurrentPassword ?? string.Empty);
                if (!isValid)
                {
                    ModelState.AddModelError("Note.CurrentPassword", message);
                    return Page();
                }
            }

            Note.Content = _htmlSanitizer.Sanitize(
                _markdownService.RenderHtml(Note.Content)
            );

            await _noteService.CreateAsync(Note, userId!);
            return RedirectToPage("./MyNotes");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating note");
            ModelState.AddModelError(string.Empty, "Error creating note. Please try again.");
            return Page();
        }
    }
}