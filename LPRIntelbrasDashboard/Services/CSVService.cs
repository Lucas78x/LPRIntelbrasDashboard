using CsvHelper;
using LPRIntelbrasDashboard.Jobs;
using LPRIntelbrasDashboard.Models;
using Microsoft.AspNetCore.SignalR;
using System.Formats.Asn1;
using System.Globalization;
using System.Text;

namespace LPRIntelbrasDashboard.Services
{


    public interface ICSVService
    {
        Task ProcessCSV(string filePath, string ipAddress);
        Task MergeCSVs();
    }

    public class CSVService : ICSVService
    {
        private readonly IHubContext<LPRHub> _hubContext;

        public CSVService(IHubContext<LPRHub> hubContext)
        {
            _hubContext = hubContext;
        }

        public async Task ProcessCSV(string filePath, string ipAddress)
        {
            try
            {
                // Define the region based on the IP address
                string region = GetRegion(ipAddress);

                string outputPath = ipAddress == "192.168.13.103"
                    ? await TransformToDefaultCSV2(filePath, region)
                    : await TransformToDefaultCSV(filePath, region);

                File.Delete(filePath);
                await MergeCSVs();
                await _hubContext.Clients.All.SendAsync("ReceiveMessage", $"Arquivo {region} processado com sucesso.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erro ao processar CSV: {ex.Message}");
            }
        }

        public async Task MergeCSVs()
        {
            string dataFolder = Path.Combine(Directory.GetCurrentDirectory(), "Data");
            string outputPath = Path.Combine(dataFolder, "MergedData.csv");
            var registros = new List<RegistroCSV>();
            var uniqueRecords = new HashSet<string>();


            foreach (var subfolder in Directory.GetDirectories(dataFolder))
            {
                if (subfolder.EndsWith("MergeFolder") && subfolder.Contains("MergedData")) continue;

                foreach (var file in Directory.GetFiles(subfolder, "*.csv"))
                {
                    if (!file.Contains("processed")) continue;
                    using (var reader = new StreamReader(file, Encoding.GetEncoding(1252)))
                    using (var csv = new CsvReader(reader, CultureInfo.InvariantCulture))
                    {
                        var records = csv.GetRecords<RegistroCSV>().ToList();

                        foreach (var record in records)
                        {
                            string uniqueKey = $"{record.NPlaca}-{record.DataHora}-{record.CorVeiculo}";
                            if (uniqueRecords.Add(uniqueKey))
                            {
                                registros.Add(record);
                            }
                        }
                    }
                }
            }

            using (var writer = new StreamWriter(outputPath))
            using (var csvWriter = new CsvWriter(writer, CultureInfo.InvariantCulture))
            {
                await csvWriter.WriteRecordsAsync(registros);
            }
        }

        private async Task<string> TransformToDefaultCSV(string inputPath, string region)
        {
            string outputPath = inputPath.Replace(".csv", "_processed.csv");

            using (var reader = new StreamReader(inputPath, Encoding.UTF8))
            using (var csv = new CsvReader(reader, CultureInfo.InvariantCulture))
            using (var writer = new StreamWriter(outputPath, false, Encoding.GetEncoding(1252)))
            using (var csvWriter = new CsvWriter(writer, CultureInfo.InvariantCulture))
            {
                var registros = csv.GetRecords<RegistroOriginal>().Select(reg => new RegistroCSV
                {
                    Índice = reg.No.ToString(),
                    Pista = reg.Lane.ToString(),
                    TamKB = Math.Round(reg.Length / 1024.0, 2).ToString(),
                    DataHora = reg.Time.ToString("dd/MM/yyyy HH:mm:ss"),
                    NPlaca = reg.PlateNumber ?? "",
                    Marca = "Desconhecido",
                    CorPlaca = reg.PlateColor == "Unknown" ? "Desconhecido" : reg.PlateColor,
                    CorVeiculo = reg.VehicleColor == "Unknown" ? "Desconhecido" : reg.VehicleColor,
                    VelocKmH = reg.Speed.ToString(),
                    Região = region, // Assign the region here
                    TipoEvento = reg.Event == "TrafficJunction" ? "ANPR" : "",
                    TamanhoVeiculo = ""
                });

                await csvWriter.WriteRecordsAsync(registros);
            }

            return outputPath;
        }

        private async Task<string> TransformToDefaultCSV2(string inputPath, string region)
        {
            string outputPath = inputPath.Replace(".csv", "_processed.csv");
            var random = new Random();

            using (var reader = new StreamReader(inputPath, Encoding.UTF8))
            using (var csv = new CsvReader(reader, CultureInfo.InvariantCulture))
            using (var writer = new StreamWriter(outputPath, false, Encoding.GetEncoding(1252)))
            using (var csvWriter = new CsvWriter(writer, CultureInfo.InvariantCulture))
            {
                var registros = csv.GetRecords<RegistroOriginal2>().Select(reg => new RegistroCSV
                {
                    Índice = random.Next(0, 1000000).ToString(),
                    Pista = "",
                    TamKB = "",
                    DataHora = reg.Hora ?? "",
                    NPlaca = reg.NumeroPlaca ?? "",
                    Marca = "",
                    CorPlaca = "",
                    CorVeiculo = "",
                    VelocKmH = "",
                    Região = region, // Assign the region here
                    TipoEvento = "",
                    TamanhoVeiculo = ""
                });

                await csvWriter.WriteRecordsAsync(registros);
            }

            return outputPath;
        }

        public string GetRegion(string ipAddress)
        {
            // Mapeamento dos IPs para os respectivos nomes
            Dictionary<string, string> ipsToBackup = new Dictionary<string, string>
                    {
                        { "192.168.9.100", "ASCON GUARAJUBA" },
                        { "192.168.9.101", "ASCON GENIPABU" },
                        { "192.168.13.103", "SOL" }
                    };


            if (ipsToBackup.ContainsKey(ipAddress))
            {
                return ipsToBackup[ipAddress];
            }
            else
            {
                return string.Empty;
            }
        }
    }
}
