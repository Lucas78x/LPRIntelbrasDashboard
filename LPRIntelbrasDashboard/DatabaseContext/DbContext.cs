using LPRIntelbrasDashboard.DTO;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

public class UsuarioDbContext : IdentityDbContext<UsuarioDTO, IdentityRole<int>, int>
{
    public UsuarioDbContext(DbContextOptions<UsuarioDbContext> options) : base(options) { }

    public DbSet<Alerta> Alertas { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<Alerta>(entity =>
        {
            entity.HasKey(a => a.Id);

            entity.Property(a => a.Placa)
                .IsRequired()
                .HasMaxLength(10);

            entity.Property(a => a.Nome)
                .IsRequired()
                .HasMaxLength(100);

            entity.HasOne(a => a.Usuario)
                .WithMany(u => u.Alertas)
                .HasForeignKey(a => a.UsuarioId)
                .OnDelete(DeleteBehavior.Cascade);
        });
    }
}
