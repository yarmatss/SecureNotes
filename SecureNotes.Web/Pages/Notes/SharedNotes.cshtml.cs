using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SecureNotes.Web.Models;
using SecureNotes.Web.Services;

namespace SecureNotes.Web.Pages.Notes;

[Authorize]
public class SharedNotesModel : PageModel
{
    private readonly INoteService _noteService;
    private readonly UserManager<User> _userManager;

    public IEnumerable<Note> Notes { get; set; } = [];

    public SharedNotesModel(INoteService noteService, UserManager<User> userManager)
    {
        _noteService = noteService;
        _userManager = userManager;
    }

    public async Task<IActionResult> OnGetAsync()
    {
        var userId = _userManager.GetUserId(User);
        if (!string.IsNullOrEmpty(userId))
        {
            Notes = await _noteService.GetSharedNotesAsync(userId);
        }
        return Page();
    }
}
