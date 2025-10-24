using AutoMapper;
using LPRIntelbrasDashboard.DTO;
using LPRIntelbrasDashboard.Models;

namespace LPRIntelbrasDashboard.Profiles
{
    public class UsuarioProfile : Profile
    {
        public UsuarioProfile()
        {
            CreateMap<AlertaModel, Alerta>()
                .ReverseMap();
     
        }
    }
}
