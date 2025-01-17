using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecureNotes.Web.Data.Migrations
{
    /// <inheritdoc />
    public partial class UpdatedUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "SigningPrivateKey",
                table: "AspNetUsers",
                newName: "PrivateKeySalt");

            migrationBuilder.AddColumn<string>(
                name: "EncryptedSigningPrivateKey",
                table: "AspNetUsers",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "PrivateKeyIV",
                table: "AspNetUsers",
                type: "nvarchar(max)",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "EncryptedSigningPrivateKey",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "PrivateKeyIV",
                table: "AspNetUsers");

            migrationBuilder.RenameColumn(
                name: "PrivateKeySalt",
                table: "AspNetUsers",
                newName: "SigningPrivateKey");
        }
    }
}
