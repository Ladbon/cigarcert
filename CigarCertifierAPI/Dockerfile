# Stage 1: Base Runtime
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
WORKDIR /app
EXPOSE 5000
EXPOSE 5001

# Stage 2: Build
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

# Copy only the project file and restore dependencies (improves caching)
COPY ./CigarCertifierAPI/CigarCertifierAPI.csproj ./CigarCertifierAPI/
RUN dotnet restore ./CigarCertifierAPI/CigarCertifierAPI.csproj

# Copy the entire project and build it
COPY ./CigarCertifierAPI ./CigarCertifierAPI
WORKDIR /src/CigarCertifierAPI
RUN dotnet build -c Release -o /app/build

# Stage 3: Publish
FROM build AS publish
RUN dotnet publish -c Release -o /app/publish /p:UseAppHost=false

# Stage 4: Final Image
FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .

# Set the entrypoint
ENTRYPOINT ["dotnet", "CigarCertifierAPI.dll"]