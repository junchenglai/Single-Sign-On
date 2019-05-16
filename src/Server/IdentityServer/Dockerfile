FROM mcr.microsoft.com/dotnet/core/aspnet:2.1-stretch-slim AS base
WORKDIR /app
EXPOSE 5000

FROM mcr.microsoft.com/dotnet/core/sdk:2.1-stretch AS build
WORKDIR /src
COPY ["src/Server/IdentityServer/IdentityServer.csproj", "src/Server/IdentityServer/"]
RUN dotnet restore "src/Server/IdentityServer/IdentityServer.csproj"
COPY . .
WORKDIR "/src/src/Server/IdentityServer"
RUN dotnet build "IdentityServer.csproj" -c Release -o /app

FROM build AS publish
RUN dotnet publish "IdentityServer.csproj" -c Release -o /app

FROM base AS final
WORKDIR /app
COPY --from=publish /app .
ENTRYPOINT ["dotnet", "IdentityServer.dll"]
