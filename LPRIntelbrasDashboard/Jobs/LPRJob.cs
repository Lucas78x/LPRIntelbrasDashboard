using LPRIntelbrasDashboard.Services;

namespace LPRIntelbrasDashboard.Jobs
{
    public class LPRJob
    {
        private readonly ILPRService _lprService;
        private readonly ILogger<LPRJob> _logger;

        public LPRJob(ILPRService lprService, ILogger<LPRJob> logger)
        {
            _lprService = lprService;
            _logger = logger;
        }

        public async Task ExportDataFromDevices()
        {
            string[] ipsToBackup = { "192.168.9.100", "192.168.9.101", "192.168.13.103" };

            foreach (var ip in ipsToBackup)
            {
                try
                {
                    _logger.LogInformation($"Iniciando exportação para {ip}");
                    bool success = await _lprService.ExportDataFromDevice(ip);

                    if (success)
                        _logger.LogInformation($"Exportação concluída para {ip}");
                    else
                        _logger.LogError($"Falha na exportação para {ip}");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, $"Erro durante exportação para {ip}");
                }
            }
        }
    }
}
