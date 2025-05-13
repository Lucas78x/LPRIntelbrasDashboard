namespace LPRIntelbrasDashboard.DTO
{
    public class Alerta
    {
        public int Id { get; set; }
        public string Placa { get; set; }
        public string Nome { get; set; }
        public int UsuarioId { get; set; }
        public UsuarioDTO Usuario { get; set; }
    }
}
