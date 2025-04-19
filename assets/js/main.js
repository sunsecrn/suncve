const resultadosPorPagina = 20;

let optionSearch = "CVEs";
let dadosJSON = {};
let cweMap = {};
let scoreMap = {};
let CVEsPocList = []
let repositoriesJSON = {}
let repositoriesCVEsJSON = {}
let cvesPocListInGithub = []
let cvesPocAdvisories = []
let resultadosFiltrados = [];

let resultadosRenderizados = 0;
let paginaAtual = 1;

const resultadoContainer = document.getElementById("resultado");


carregarJsonComprimido('/index/descriptions.json.gz');
getRepositories()
carregarCWEMap()
carregarScoreMap()
