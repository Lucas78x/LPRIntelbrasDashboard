# Etapa base
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 8080
EXPOSE 8081

# Etapa de build
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src

# Copiar o csproj e restaurar as dependências
COPY ["LPRIntelbrasDashboard/LPRIntelbrasDashboard.csproj", "LPRIntelbrasDashboard/"]
RUN dotnet restore "LPRIntelbrasDashboard/LPRIntelbrasDashboard.csproj"

# Copiar todo o código
COPY . .
WORKDIR "/src/LPRIntelbrasDashboard"
RUN dotnet build "LPRIntelbrasDashboard.csproj" -c $BUILD_CONFIGURATION -o /app/build

# Etapa de publicação
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "LPRIntelbrasDashboard.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

# Etapa final
FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "LPRIntelbrasDashboard.dll"]
