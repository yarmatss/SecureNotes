using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SecureNotes.Web.Models;
using SecureNotes.Web.Services;

namespace SecureNotes.Web.Pages.Notes;

[Authorize]
public class MyNotesModel : PageModel
{
    private readonly INoteService _noteService;
    private readonly UserManager<User> _userManager;

    public IEnumerable<Note> Notes { get; set; } = [];

    [TempData]
    public string? StatusMessage { get; set; }

    public MyNotesModel(INoteService noteService, UserManager<User> userManager)
    {
        _noteService = noteService;
        _userManager = userManager;
    }

    public async Task<IActionResult> OnGetAsync()
    {
        var userId = _userManager.GetUserId(User);
        if (!string.IsNullOrEmpty(userId))
        {
            Notes = await _noteService.GetUserNotesAsync(userId);
        }
        return Page();
    }

    public async Task<IActionResult> OnPostDeleteAsync(int id)
    {
        var userId = _userManager.GetUserId(User);
        var result = await _noteService.DeleteAsync(id, userId!);

        StatusMessage = result ? "Note deleted successfully." : "Error deleting note.";
        return RedirectToPage();
    }
}