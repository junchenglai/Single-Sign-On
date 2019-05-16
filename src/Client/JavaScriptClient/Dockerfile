FROM mcr.microsoft.com/dotnet/core/aspnet:2.1-stretch-slim AS base
WORKDIR /app
EXPOSE 5003

FROM mcr.microsoft.com/dotnet/core/sdk:2.1-stretch AS build
WORKDIR /src
COPY ["src/Client/JavaScriptClient/JavaScriptClient.csproj", "src/Client/JavaScriptClient/"]
RUN dotnet restore "src/Client/JavaScriptClient/JavaScriptClient.csproj"
COPY . .
WORKDIR "/src/src/Client/JavaScriptClient"
RUN dotnet build "JavaScriptClient.csproj" -c Release -o /app

FROM build AS publish
RUN dotnet publish "JavaScriptClient.csproj" -c Release -o /app

FROM base AS final
WORKDIR /app
COPY --from=publish /app .
ENTRYPOINT ["dotnet", "JavaScriptClient.dll"]
