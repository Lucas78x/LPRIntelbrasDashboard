# Use a imagem base do .NET SDK 8.0 para compilar o projeto
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build

WORKDIR /src

# Copia o arquivo de solução e restaura as dependências
COPY ["LPRIntelbrasDashboard.sln", "./"]
COPY ["LPRIntelbrasDashboard/LPRIntelbrasDashboard.csproj", "LPRIntelbrasDashboard/"]
RUN dotnet restore "LPRIntelbrasDashboard/LPRIntelbrasDashboard.csproj"

# Copia o código-fonte e compila
COPY . .
WORKDIR "/src/LPRIntelbrasDashboard"
RUN dotnet build "LPRIntelbrasDashboard.csproj" -c Release -o /app/build

# Publica a aplicação para a pasta /app/publish
RUN dotnet publish "LPRIntelbrasDashboard.csproj" -c Release -o /app/publish

# Define a imagem de produção para a execução com .NET 8.0
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

# Copia os arquivos compilados do build
COPY --from=build /app/publish .

ENTRYPOINT ["dotnet", "LPRIntelbrasDashboard.dll"]
