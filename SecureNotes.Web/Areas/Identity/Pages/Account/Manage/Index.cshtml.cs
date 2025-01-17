// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;


public class IndexModel : PageModel
{
    public IActionResult OnGet()
    {
        return RedirectToPage("./ChangePassword");
    }
}
