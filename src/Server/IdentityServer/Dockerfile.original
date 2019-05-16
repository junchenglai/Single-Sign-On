FROM microsoft/dotnet:2.1-aspnetcore-runtime
WORKDIR /app
COPY . .
EXPOSE 5000
ENTRYPOINT ["dotnet", "IdentityServer.dll"]

#FROM microsoft/dotnet:2.1-aspnetcore-runtime AS base
#WORKDIR /app
#EXPOSE 62474
#EXPOSE 44324
#
#FROM microsoft/dotnet:2.1-sdk AS build
#WORKDIR /src
#COPY src/Server/IdentityServer/IdentityServer.csproj src/Server/IdentityServer/
#RUN dotnet restore src/Server/IdentityServer/IdentityServer.csproj
#COPY . .
#WORKDIR /src/src/Server/IdentityServer
#RUN dotnet build IdentityServer.csproj -c Release -o /app
#
#FROM build AS publish
#RUN dotnet publish IdentityServer.csproj -c Release -o /app
#
#FROM base AS final
#WORKDIR /app
#COPY --from=publish /app .
#ENTRYPOINT ["dotnet", "IdentityServer.dll"]
#