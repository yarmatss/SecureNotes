using Markdig;
using ReverseMarkdown;

namespace SecureNotes.Web.Services;

public class MarkdownService : IMarkdownService
{
    private readonly MarkdownPipeline _pipeline;

    public MarkdownService()
    {
        _pipeline = new MarkdownPipelineBuilder()
            .UseAdvancedExtensions()
            .UseBootstrap()
            .Build();
    }

    public string ConvertHtmlToMarkdown(string html)
    {
        if (string.IsNullOrEmpty(html))
            return string.Empty;

        var converter = new ReverseMarkdown.Converter(new ReverseMarkdown.Config
        {
            UnknownTags = Config.UnknownTagsOption.PassThrough,
            GithubFlavored = true,
            RemoveComments = true,
            SmartHrefHandling = true
        });

        return converter.Convert(html);
    }

    public string RenderHtml(string markdown)
    {
        if (string.IsNullOrEmpty(markdown))
            return string.Empty;

        return Markdown.ToHtml(markdown, _pipeline);
    }
}
