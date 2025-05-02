const resultadosPorPagina = 20;

let optionSearch = "CVEs";
let dadosJSON = {};
let cweMap = {};
let scoreMap = {};
let cweDetailsMap = {};
let CVEsPocList = []
let repositoriesJSON = {}
let repositoriesCVEsJSON = {}
let cvesPocListInGithub = []
let cvesPocAdvisories = []
let resultadosFiltrados = [];
let exportDataValues = [];
let resultadosRenderizados = 0;
let paginaAtual = 1;
let pathRoot = "/suncve"

const resultadoContainer = document.getElementById("resultado");


carregarJsonComprimido(pathRoot+'/index/descriptions.json.gz');
getRepositories()
carregarCWEMap()
carregarScoreMap()
carregarCweDetailsMap()
