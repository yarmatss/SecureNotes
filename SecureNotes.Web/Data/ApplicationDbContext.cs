using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SecureNotes.Web.Models;

namespace SecureNotes.Web.Data;

public class ApplicationDbContext : IdentityDbContext<User>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public DbSet<Note> Notes => Set<Note>();
    public DbSet<NoteShare> NoteShares => Set<NoteShare>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<Note>(entity =>
        {
            entity.HasOne(n => n.Author)
                  .WithMany(u => u.Notes)
                  .HasForeignKey(n => n.AuthorId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<NoteShare>(entity =>
        {
            entity.HasOne(ns => ns.Note)
                  .WithMany(n => n.SharedWith)
                  .HasForeignKey(ns => ns.NoteId)
                  .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(ns => ns.User)
                  .WithMany(u => u.SharedWithMe)
                  .HasForeignKey(ns => ns.UserId)
                  .OnDelete(DeleteBehavior.Restrict);
        });

        builder.Entity<Note>()
               .HasIndex(n => n.AuthorId);

        builder.Entity<NoteShare>()
               .HasIndex(ns => new { ns.NoteId, ns.UserId })
               .IsUnique();

        builder.Entity<Note>()
           .HasIndex(n => n.AccessLevel);
    }
}
