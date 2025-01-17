namespace SecureNotes.Web.Services;

public interface IMarkdownService
{
    string RenderHtml(string markdown);
    string ConvertHtmlToMarkdown(string html);
}
