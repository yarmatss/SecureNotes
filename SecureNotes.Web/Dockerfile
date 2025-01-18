FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
WORKDIR /app

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src
COPY ["SecureNotes.Web/SecureNotes.Web.csproj", "SecureNotes.Web/"]
RUN dotnet restore "./SecureNotes.Web/SecureNotes.Web.csproj"
COPY . .
WORKDIR "/src/SecureNotes.Web"
RUN dotnet build "./SecureNotes.Web.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "./SecureNotes.Web.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "SecureNotes.Web.dll"]