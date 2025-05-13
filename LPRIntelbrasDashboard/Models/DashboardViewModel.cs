namespace LPRIntelbrasDashboard.Models
{
    public class DashboardViewModel
    {
        public List<RegistroCSV> Registros { get; set; }

        public int TotalPlacas => Registros?.Count ?? 0;

        public List<string> Regioes => Registros?
            .Where(r => !string.IsNullOrEmpty(r.Região))
            .Select(r => r.Região)
            .Distinct()
            .ToList();

        public List<RegistroCSV> GetPorRegiao(string regiao)
            => Registros?.Where(r => r.Região == regiao).ToList();

        public string FiltroPlaca { get; set; }
        public string Regiao { get; set; }
        public string Data { get; set; }
    }


}
