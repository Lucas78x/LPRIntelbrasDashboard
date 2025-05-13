// Conexão SignalR
const connection = new signalR.HubConnectionBuilder()
    .withUrl('/LPRHub')
    .build();

let charts = {};
let dataRecords = [];
let regionPlates = {}; // Armazenamento das placas por região

// Início: conecta e carrega dados
async function init() {
    try {
        await connection.start();
        console.log('SignalR conectado');
        await connection.invoke('SubscribeToUpdates');
    } catch (err) {
        console.error('Erro ao conectar SignalR', err);
        setTimeout(init, 5000);
        return;
    }
    loadData();
}

// Recebe dados em tempo real
connection.on('ReceiveDashboardData', payload => {
    updateDashboard(payload);
});

// Chama API REST para dados iniciais
async function loadData() {
    try {
        const res = await fetch('/Dashboard/GetDashboardData');
        const json = await res.json();
        if (json.success) {
            console.log(json.data);
            updateDashboard(json.data);
        }
    } catch (err) {
        console.error('Falha ao carregar dados', err);
    }
}

defaults = { type: 'line', options: { responsive: true, maintainAspectRatio: false } };

// Atualiza UI com os dados
function updateDashboard(data) {
    // Métricas
    console.log(data);
    document.getElementById('totalVehicles').innerText = data.totalVehicles || 0;
    document.getElementById('avgSpeed').innerText = (data.avgSpeed || 0) + ' km/h';
    document.getElementById('topColor').innerText = data.topColor?.Name || 'Desconhecido';
    const sample = document.getElementById('topColorSample');
    if (sample) sample.style.backgroundColor = data.topColor?.Hex || '#a5a5a5';
    document.getElementById('topLocation').innerText = data.topLocation || 'N/A';
    document.getElementById('lastUpdateTime').innerText = data.lastUpdate || '-';

    // Gráficos
    renderChart('flow', 'flowChart', 'line', data.flow.labels, data.flow.values);
    renderChart('color', 'colorChart', 'pie', data.colorDistribution.map(x => x.Name), data.colorDistribution.map(x => x.Count));
    renderChart('plates', 'platesChart', 'bar', data.topPlates.map(x => x.Plate), data.topPlates.map(x => x.Count));

    // Tabela
    dataRecords = data.records;  // Armazena os registros para busca
    renderTable(data.records);

    // Atualizar Placas por Região
    updateRegionsSummary(data.records);
}

function renderChart(key, canvasId, type, labels, data) {
    if (!charts[key]) {
        const ctx = document.getElementById(canvasId).getContext('2d');
        charts[key] = new Chart(ctx, { type, data: { labels, datasets: [{ data }] }, options: { responsive: true } });
    } else {
        charts[key].data.labels = labels;
        charts[key].data.datasets[0].data = data;
        charts[key].update();
    }
}

function renderTable(records) {
    const tbody = document.querySelector('#recordsTable tbody');
    tbody.innerHTML = '';
    records.forEach(r => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${r.índice}</td>
            <td>${r.nPlaca}</td>
            <td>${r.dataHora}</td>
            <td>${r.região || 'N/A'}</td>
            <td>${r.corVeiculo}</td>
            <td>${r.velocKmH}</td>
        `;
        tbody.appendChild(tr);
    });
}

// Atualiza o resumo das placas por região
function updateRegionsSummary(records) {
    regionPlates = {}; // Resetando a contagem
    records.forEach(record => {
        const region = record.região || 'Desconhecido';
        if (!regionPlates[region]) {
            regionPlates[region] = 0;
        }
        regionPlates[region]++;
    });

    const regionsSummary = document.getElementById('regionsSummary');
    regionsSummary.innerHTML = ''; // Limpa o conteúdo atual
    for (const region in regionPlates) {
        const regionDiv = document.createElement('div');
        regionDiv.classList.add('region-card');
        regionDiv.innerHTML = `
            <strong>${region}</strong>: ${regionPlates[region]} placas
        `;
        regionsSummary.appendChild(regionDiv);
    }
}

// Busca instantânea
document.getElementById('searchInput').addEventListener('input', e => {
    const term = e.target.value.toLowerCase();
    const filtered = dataRecords.filter(r => r.NPlaca.toLowerCase().includes(term));
    renderTable(filtered);
});

// Inicializa
init();
