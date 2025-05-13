using CsvHelper;
using LPRIntelbrasDashboard.Models;
using Microsoft.AspNetCore.SignalR;
using System.Globalization;
using System.Text;

public class LPRHub : Hub
{
    public async Task SendMessage(string message)
    {
        await Clients.All.SendAsync("ReceiveMessage", message);
    }
}
