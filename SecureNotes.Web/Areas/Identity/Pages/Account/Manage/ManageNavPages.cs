﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using Microsoft.AspNetCore.Mvc.Rendering;

namespace SecureNotes.Web.Areas.Identity.Pages.Account.Manage;
public static class ManageNavPages
{
    public static string Index => "ChangePassword";
    public static string ChangePassword => "ChangePassword";
    public static string TwoFactorAuthentication => "TwoFactorAuthentication";
    public static string IndexNavClass(ViewContext viewContext) => PageNavClass(viewContext, Index);
    public static string ChangePasswordNavClass(ViewContext viewContext) => PageNavClass(viewContext, ChangePassword);
    public static string TwoFactorAuthenticationNavClass(ViewContext viewContext) => PageNavClass(viewContext, TwoFactorAuthentication);

    public static string PageNavClass(ViewContext viewContext, string page)
    {
        var activePage = viewContext.ViewData["ActivePage"] as string
            ?? System.IO.Path.GetFileNameWithoutExtension(viewContext.ActionDescriptor.DisplayName);
        return string.Equals(activePage, page, StringComparison.OrdinalIgnoreCase) ? "active" : null;
    }
}
