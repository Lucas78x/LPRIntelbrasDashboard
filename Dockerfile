# Use a imagem base do .NET SDK 8.0 para compilar o projeto
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build

WORKDIR /src

# Copia o arquivo de solução e o projeto
COPY LPRIntelbrasDashboard.sln ./
COPY LPRIntelbrasDashboard/LPRIntelbrasDashboard.csproj LPRIntelbrasDashboard/

# Restaura as dependências
RUN dotnet restore LPRIntelbrasDashboard/LPRIntelbrasDashboard.csproj

# Copia o código fonte e compila
COPY LPRIntelbrasDashboard/ LPRIntelbrasDashboard/
WORKDIR /src/LPRIntelbrasDashboard
RUN dotnet build -c Release -o /app/build

# Publica o projeto
RUN dotnet publish -c Release -o /app/publish

# Define a imagem base de runtime
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app

# Copia os arquivos publicados para o container
COPY --from=build /app/publish .

# Expor as portas HTTP e HTTPS
EXPOSE 80
EXPOSE 443

# Inicia a aplicação
ENTRYPOINT ["dotnet", "LPRIntelbrasDashboard.dll"]
