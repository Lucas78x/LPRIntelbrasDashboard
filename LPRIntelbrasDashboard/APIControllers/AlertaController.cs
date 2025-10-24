using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using LPRIntelbrasDashboard.DTO;
using LPRIntelbrasDashboard.Models;
using System.Security.Claims;
using AutoMapper;


[ApiController]
[Route("api/v1/[controller]")]
[Authorize]
public class AlertaController : ControllerBase
{
    private readonly UsuarioDbContext _context;
    private readonly ILogger<AlertasController> _logger;
    private readonly IMapper _mapper;

    public AlertaController(UsuarioDbContext context, ILogger<AlertasController> logger, IMapper mapper)
    {
        _context = context;
        _logger = logger;
        _mapper = mapper;
    }

    /// <summary>
    /// Cria um novo alerta
    /// </summary>
    [HttpPost("criar")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> CriarAlerta([FromBody] AlertaModel alerta)
    {
        try
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
                return Unauthorized("Usuário não autenticado");

            var alertaDto = _mapper.Map<Alerta>(alerta);

            alertaDto.UsuarioId = int.Parse(userId);
            _context.Alertas.Add(alertaDto);

            await _context.SaveChangesAsync();

            _logger.LogInformation($"Alerta criado: {alerta.Placa} por usuário {userId}");
            return CreatedAtAction(nameof(ObterPorId), new { id = alerta.Id }, alerta);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao criar alerta");
            return StatusCode(500, "Erro interno no servidor");
        }
    }

    /// <summary>
    /// Lista todos os alertas do usuário autenticado
    /// </summary>
    [HttpGet("listar")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> ListarAlertas()
    {
        try
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var alertas = _mapper.Map<AlertaModel>(await _context.Alertas
                .Include(a => a.Usuario)
                .Where(a => a.UsuarioId.ToString() == userId)
                .ToListAsync());

            return Ok(alertas);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao listar alertas");
            return StatusCode(500, "Erro interno no servidor");
        }
    }

    /// <summary>
    /// Obtém um alerta específico
    /// </summary>
    [HttpGet("{id}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> ObterPorId(int id)
    {
        var alerta = await _context.Alertas.FindAsync(id);
        if (alerta == null)
            return NotFound("Alerta não encontrado");

        return Ok(alerta);
    }

    /// <summary>
    /// Edita um alerta existente
    /// </summary>
    [HttpPut("editar/{id}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> EditarAlerta(int id, [FromBody] Alerta alertaAtualizado)
    {
        try
        {
            var alerta = await _context.Alertas.FindAsync(id);
            if (alerta == null)
                return NotFound("Alerta não encontrado");

            alerta.Placa = alertaAtualizado.Placa;
            alerta.Nome = alertaAtualizado.Nome;

            _context.Alertas.Update(alerta);
            await _context.SaveChangesAsync();

            _logger.LogInformation($"Alerta {id} atualizado com sucesso");
            return NoContent();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao editar alerta");
            return StatusCode(500, "Erro interno no servidor");
        }
    }

    /// <summary>
    /// Exclui um alerta
    /// </summary>
    [HttpDelete("deletar/{id}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> DeletarAlerta(int id)
    {
        try
        {
            var alerta = await _context.Alertas.FindAsync(id);
            if (alerta == null)
                return NotFound("Alerta não encontrado");

            _context.Alertas.Remove(alerta);
            await _context.SaveChangesAsync();

            _logger.LogInformation($"Alerta {id} deletado com sucesso");
            return NoContent();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao deletar alerta");
            return StatusCode(500, "Erro interno no servidor");
        }
    }
}

