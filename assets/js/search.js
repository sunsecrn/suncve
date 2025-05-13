const webServerLanguages = [
    "HTML",
    "CSS",
    "PHP",
    "Twig",
    "Blade",
    "Smarty",
    "ERB",
    "Jinja2"
];
const linguagensComuns = ["JavaScript", "Python", "Ruby", "PHP", "Go", "Java", "C#", "Rust", "C++", "TypeScript"];

let debounceTimer;
document.getElementById("busca").addEventListener("input", (e) => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
        if (optionSearch == "CVEs") {
            searchDescriptions(e.target.value, { cwe: getSelectedFilters("cwe"), score: getSelectedFilters("score"), options: getSelectedFilters("options"), langMain: getSelectedFilters("cve_lang_main") });
        }
        if (optionSearch == "Repositórios") {
            searchRepositories(e.target.value, { lang: getSelectedFilters("lang"), webserver: getSelectedFilters("options_repo").length, repoLength: parseInt(document.querySelector("#repo-length").value) || 0 });
        }
    }, 500);
});

// Ativar/desativar botões toggle
document.addEventListener("click", (e) => {
    if (e.target.classList.contains("toggle-btn")) {
        e.target.classList.toggle("active");
        if (optionSearch === "CVEs") {
            searchDescriptions(document.getElementById("busca").value, { cwe: getSelectedFilters("cwe"), score: getSelectedFilters("score"), options: getSelectedFilters("options"), langMain: getSelectedFilters("cve_lang_main") });
        }
        if (optionSearch == "Repositórios") {
            searchRepositories(document.getElementById("busca").value, { lang: getSelectedFilters("lang"), webserver: getSelectedFilters("options_repo").length, repoLength: parseInt(document.querySelector("#repo-length").value) || 0 });
        }
    }
});

document.getElementById("busca-cwe").addEventListener("input", e => {
    allCweKeys = Object.keys(cweMap);
    const termo = e.target.value.toLowerCase();
    const container = document.getElementById("cwe-results");
    container.innerHTML = "";

    const encontrados = allCweKeys.filter(cwe =>
        cwe.toLowerCase().includes(termo) ||
        cweDetailsMap[cwe]?.toLowerCase().includes(termo)
    );

    if (encontrados.length === 0) {
        container.innerHTML = `<p class="text-xs text-[#888] p-2">Nenhuma CWE encontrada.</p>`;
        return;
    }

    encontrados.slice(0, 100).forEach((cwe, index) => {
        const wrapper = document.createElement("div");
        wrapper.className = `toggle-cwe text-sm px-3 py-2 cursor-pointer transition-all duration-200 ${index % 2 === 0 ? "bg-[#1f1f1f]" : "bg-[#2a2a2a]"
            }`;
        wrapper.setAttribute("data-group", "cwe");
        wrapper.textContent = `${cwe}: ${cweDetailsMap[cwe] || "Sem descrição"}`;

        wrapper.addEventListener("click", () => {
            wrapper.classList.toggle("active");
            searchDescriptions(document.getElementById("busca").value, { cwe: getSelectedFilters("cwe"), score: getSelectedFilters("score"), options: getSelectedFilters("options"), langMain: getSelectedFilters("cve_lang_main") });
        });
        container.appendChild(wrapper);
    });
});

function selectOptionSearch(value) {
    document.getElementById("dropdownValue").textContent = value;
    document.getElementById("dropdownMenu").classList.add("hidden");
    optionSearch = value;

    // Alterna filtros
    document.getElementById("filtros-cves").classList.toggle("hidden", value !== "CVEs");
    document.getElementById("filtros-repos").classList.toggle("hidden", value !== "Repositórios");

    resultadoContainer.innerHTML = `<div class="col-span-full text-center text-sm text-[#c4bfb5]">Base carregada. Agora busque algo.</div>`;

    if (optionSearch === "CVEs") {
        searchDescriptions(document.getElementById("busca").value, { cwe: getSelectedFilters("cwe"), score: getSelectedFilters("score"), options: getSelectedFilters("options"), langMain: getSelectedFilters("cve_lang_main") });
    } else {
        searchRepositories(document.getElementById("busca").value, { lang: getSelectedFilters("lang"), webserver: getSelectedFilters("options_repo").length, repoLength: parseInt(document.querySelector("#repo-length").value) || 0 });
    }
}

async function searchDescriptions(texto, filter = { cwe: [], score: [], options: [], langMain: [] }) {
    resultadoContainer.className = "w-full max-w-4xl grid grid-cols-1 gap-6 mb-10";
    resultadoContainer.innerHTML = "";
    //if (!texto.trim()) {
    //  resultadoContainer.innerHTML = `<div class="col-span-full text-center text-sm text-[#c4bfb5]">Digite algo para buscar.</div>`;
    //  return;
    //}

    const cvesPermitidosPorCWE = new Set();
    const cvesPermitidosPorScore = new Set();
    const cvesPermitidosLangMain = new Set();
    var cvesPermitidosPorOptions = new Set();

    // Coleta os CVEs permitidos a partir das CWEs selecionadas
    if (filter.cwe.length > 0) {
        filter.cwe.forEach(cwe => {
            const relacionados = cweMap[cwe] || [];
            relacionados.forEach(cve => cvesPermitidosPorCWE.add(cve));
        });
    }

    if (filter.langMain.length > 0) {
        filter.langMain.forEach(lm => {
            Object.entries(repositoriesJSON).forEach(([key, value]) => {
                if (value.language === lm) {
                    const relacionados = repositoriesCVEsJSON[key]?.listCVEs || [];
                    relacionados.forEach(cve => cvesPermitidosLangMain.add(cve));
                }
            });
        });
    }

    if (filter.score.length > 0) {
        filter.score.forEach(sc => {
            const relacionados = scoreMap[sc] || [];
            relacionados.forEach(cve => cvesPermitidosPorScore.add(cve));
        });
    }

    if (filter.options.length > 0) {
        const conjuntosPorFiltro = [];

        filter.options.forEach(opt => {
            const set = new Set();

            if (opt === "Repositorie") {
                Object.values(repositoriesCVEsJSON).forEach(repo => {
                    repo.listCVEs?.forEach(cve => set.add(cve));
                });
            }

            if (opt === "Commit") {
                Object.values(repositoriesCVEsJSON).forEach(repo => {
                    repo.commitsCVEs?.forEach(cve => set.add(cve));
                });
            }

            if (opt === "Advisorie") {
                cvesPocAdvisories.forEach(cve => set.add(cve));
            }

            if (opt === "WEB Apps") {
                Object.entries(repositoriesJSON).forEach(([key, value]) => {
                    const langs = Object.keys(value.langs);
                    if (webServerLanguages.some(lang => langs.includes(lang))) {
                        const relacionados = repositoriesCVEsJSON[key]?.listCVEs || [];
                        relacionados.forEach(cve => set.add(cve));
                    }
                });
            }

            if (opt === "POC") {
                cvesPocAdvisories.forEach(cve => set.add(cve));
                cvesPocListInGithub.forEach(cve => set.add(cve));
            }

            conjuntosPorFiltro.push(set);
        });

        // Faz interseção entre os filtros
        if (conjuntosPorFiltro.length > 0) {
            cvesPermitidosPorOptions = new Set(
                [...conjuntosPorFiltro[0]].filter(cve =>
                    conjuntosPorFiltro.every(set => set.has(cve))
                )
            );
        }
    }

    const encontrados = Object.entries(dadosJSON).filter(([chave, _]) =>
        chave.toLowerCase().includes(texto.toLowerCase())
    );

    resultadosFiltrados = [];
    exportDataValues = [];
    for (const [chave, valor] of encontrados) {
        valor.forEach((v) => {
            exportDataValues.push(v);
        })
        for (const v of valor) {
            if (filter.cwe.length > 0 && !cvesPermitidosPorCWE.has(v)) continue;
            if (filter.score.length > 0 && !cvesPermitidosPorScore.has(v)) continue;
            if (filter.options.length > 0 && !cvesPermitidosPorOptions.has(v)) continue;
            if (filter.langMain.length > 0 && !cvesPermitidosLangMain.has(v)) continue;

            resultadosFiltrados.push(v);
        }
    }

    if (resultadosFiltrados.length === 0) {
        resultadoContainer.innerHTML = `<div class="col-span-full text-center text-sm text-red-400">Nenhum resultado com os filtros selecionados.</div>`;
        document.getElementById("paginacao").innerHTML = "";
        return;
    }

    paginaAtual = 1;
    renderPaginaAtual();

}

async function searchRepositories(texto, filter = { lang: [], webserver: false, repoLength: 0 }) {
    resultadoContainer.className = "w-full max-w-6xl grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6"

    resultadoContainer.innerHTML = "";
    //if (!texto.trim()) {
    //  resultadoContainer.innerHTML = `<div class="col-span-full text-center text-sm text-[#c4bfb5]">Digite algo para buscar.</div>`;
    //  return;
    //}

    const encontrados = Object.entries(repositoriesJSON).filter(([chave, valor]) => {
        const langs = Object.keys(valor.langs);
        const repoLength = Math.round(Object.values(valor.langs).reduce((acc, val) => acc + val, 0) / 1024 / 1024)
        const contemTexto = chave.toLowerCase().includes(texto.toLowerCase());
        const linguagemAceita = filter.lang.length === 0 || filter.lang.includes(valor.language);
        const webserverOption = filter.webserver.length === 0 || webServerLanguages.some(lang => langs.includes(lang))
        const repoLengthAceito = filter.repoLength === 0 || repoLength <= filter.repoLength;

        return contemTexto && linguagemAceita && repoLengthAceito && webserverOption;
    });

    console.log("encontrados:", encontrados)
    if (encontrados.length > 0) {
        exportDataValues = [];
        const limitados = encontrados.sort(([, a], [, b]) => b.stargazers - a.stargazers).slice(0, resultadosPorPagina);
        encontrados.forEach(async ([chave, valor], index) => {
            exportDataValues.push(chave);
        });
        limitados.forEach(async ([chave, valor], index) => {
            let cvssColor = "#a8a29e"; // default
            let borderColor = "#3f3f46"; // fallback neutro
            const repositoryName = chave.replace("https://github.com/", "").replace(/\/$/, "");

            // Alternância de fundo
            const backgrounds = ["#1c1c1c", "#202020", "#2a2a2a"];
            const baseColor = backgrounds[0];

            const card = document.createElement("div");
            card.className = "bg-[#1c1c1c] rounded-lg p-6 shadow hover:shadow-lg transition flex flex-col items-center justify-between text-center relative";

            card.style.backgroundColor = baseColor;
            card.style.borderLeft = `4px solid ${borderColor}`;

            card.innerHTML = `
            <div class="flex flex-col items-center text-center w-full">
              <!-- Avatar -->
              <div class="mb-3 relative flex flex-col items-center">
                <img src="${valor.avatar}" alt="Avatar"
                  class="w-20 h-20 rounded-lg object-cover shadow-md" />
              
                <!-- Estrelas abaixo do avatar -->
                <div class="mt-2 flex items-center gap-1 text-sm text-[#d6b85a] bg-[#2a2a2a] px-2 py-1 rounded-full font-medium shadow-sm">
                  <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-4 h-4" viewBox="0 0 24 24">
                    <path d="M12 17.27L18.18 21l-1.64-7.03L22 9.24l-7.19-.61L12 2 9.19 8.63 2 9.24l5.46 4.73L5.82 21z"/>
                  </svg>
                  ${formatNumbers(valor.stargazers)}
                </div>
              </div>
            
              <!-- Nome do repositório -->
              <h3 class="text-base font-semibold text-[#f0eada] truncate max-w-full mb-1">
                <a href="${chave}" target="_blank">${repositoryName}</a>
              </h3>
            
              <!-- Linguagem -->
              <div class="flex items-center gap-2 text-sm text-[#c4bfb5] mb-3">
                <img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/${valor.language?.toLowerCase()}/${valor.language?.toLowerCase()}-original.svg" 
                     alt="${valor.language}" class="w-5 h-5" />
                <span>${valor.language}</span>
              </div>
            
              <!-- CVE Info -->
              <div class="w-full bg-[#2c2c2c] rounded-md px-3 py-2 text-left text-sm mb-2">
                <div class="flex justify-between items-center cursor-pointer" onclick="toggleDetails(this.nextElementSibling)">
                  <span class="text-[#f87171] font-semibold">🛡️ CVEs:</span>
                  <span class="text-[#f87171] font-bold underline">${repositoriesCVEsJSON[chave]?.listCVEs?.length || 0}</span>
                </div>
                <ul class="cve-list hidden mt-2 ml-2 text-xs text-[#e5e5e5] list-disc pl-4">
                  ${(repositoriesCVEsJSON[chave]?.listCVEs || [])
                    .map(cve => `<li><a href="/suncve/cves/${cve}.json" target="_blank" class="text-[#60a5fa] hover:underline">${cve}</a></li>`)
                    .join('')
                }
                </ul>
              
                <div class="flex justify-between items-center mt-2 cursor-pointer" onclick="toggleDetails(this.nextElementSibling)">
                  <span class="text-[#60a5fa] font-semibold">🔧 Commits de correção:</span>
                  <span class="text-[#60a5fa] font-bold underline">${repositoriesCVEsJSON[chave]?.commitsCVEs?.length || 0}</span>
                </div>
                <ul class="commit-list hidden mt-2 ml-2 text-xs text-[#e5e5e5] list-disc pl-4">
                  ${(repositoriesCVEsJSON[chave]?.commitsCVEs || [])
                    .map(url => `<li><a href="/suncve/cves/${url}.json" target="_blank" class="text-[#60a5fa] hover:underline">${url.split('/').pop().slice(0, 8)}</a></li>`)
                    .join('')
                }
                </ul>

                <div class="flex justify-between items-center mt-2 cursor-pointer" onclick="toggleDetails(this.nextElementSibling)">
                  <span class="text-[#dd8f2b] font-semibold">☀️ Sunsec CodeQL:</span>
                  <span class="text-[#dd8f2b] font-bold underline">${repositoriesWorklog[repositoryName]?.length || 0}</span>
                </div>
                <ul class="commit-list hidden mt-2 ml-2 text-xs text-[#e5e5e5] list-disc pl-4">
                  ${(repositoriesWorklog[repositoryName] || [])
                    .map(worklogInfo => `<li><p class="text-[#dd8f2b]">${worklogInfo.user} | ${worklogInfo.date}</p></li>`)
                    .join('')
                }
                </ul>
              </div>  
  
            </div>
          `;


            resultadoContainer.appendChild(card);

        });

        if (encontrados.length > resultadosPorPagina) {
            const aviso = document.createElement("div");
            aviso.className = "col-span-full text-center text-yellow-400 text-sm mt-4";
            aviso.textContent = `⚠️ Mostrando apenas os primeiros ${resultadosPorPagina} de ${encontrados.length} resultados. Refine sua busca para mais precisão.`;
            resultadoContainer.appendChild(aviso);
        }

    } else {
        resultadoContainer.innerHTML = `<div class="col-span-full text-center text-sm text-red-400">Nenhum repositório encontrada.</div>`;
    }
}

function popularLinguagens(langs, containerId) {
    const container = document.getElementById(containerId);
    container.innerHTML = "";

    langs.forEach(lang => {
        const btn = document.createElement("button");
        btn.className = "toggle-btn";
        btn.setAttribute("data-group", containerId === "repo-lang-list" ? "lang" : "cve_lang_main");
        btn.textContent = lang;
        container.appendChild(btn);
    });
}

// Exemplo de linguagens populares
popularLinguagens(linguagensComuns, "cve-lang-list");
popularLinguagens(linguagensComuns, "repo-lang-list");
