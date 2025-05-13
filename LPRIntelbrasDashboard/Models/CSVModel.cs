using CsvHelper.Configuration.Attributes;

namespace LPRIntelbrasDashboard.Models
{
    public class Data
    {
        public string fileName { get; set; }
        public string csvPath { get; set; }
    }
    public class RegistroCSV
    {
        [Name("Índice")]
        public string Índice { get; set; }
        [Name("Pista")]
        public string Pista { get; set; }
        [Name("Tam. (KB)")]
        public string TamKB { get; set; }
        [Name("Hora")]
        public string DataHora { get; set; }
        [Name("Nº placa")]
        public string NPlaca { get; set; }
        [Name("Marca")]
        public string Marca { get; set; }
        [Name("Cor placa")]
        public string CorPlaca { get; set; }
        [Name("Cor veículo")]
        public string CorVeiculo { get; set; }
        [Name("Veloc.km/h")]
        public string VelocKmH { get; set; }
        [Name("Região")]
        public string Região { get; set; }
        [Name("Tipo evento")]
        public string TipoEvento { get; set; }
        [Name("Tam. Veíc.")]
        public string TamanhoVeiculo { get; set; }

        public override string ToString()
        {
            return $"{Índice},{Pista},{TamKB},{DataHora:dd/MM/yyyy HH:mm:ss},{NPlaca},{Marca},{CorPlaca},{CorVeiculo},{VelocKmH},{Região},{TipoEvento},{TamanhoVeiculo}";
        }
    }
    public class RegistroOriginal
    {
        public int No { get; set; }
        public int Lane { get; set; }
        public long Length { get; set; }
        public DateTime Time { get; set; }
        public string PlateNumber { get; set; }
        public string PlateColor { get; set; }
        public string VehicleColor { get; set; }
        public int Speed { get; set; }
        public string Event { get; set; }
    }
    public class RegistroOriginal2
    {
        [Name("Lista de Bloqueados")]
        public string ListaDeBloqueados { get; set; }
        [Name("Região")]
        public string Regiao { get; set; }
        [Name("Direção")]
        public string Direcao { get; set; }
        [Name("Nº placa")]
        public string NumeroPlaca { get; set; }
        [Name("Lista permis.")]
        public string ListaPermissao { get; set; }
        [Name("Hora")]
        public string Hora { get; set; }
        [Name("Direção veíc")]
        public string DirecaoVeiculo { get; set; }
    }
}
