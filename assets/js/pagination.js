async function renderPaginaAtual() {
    resultadoContainer.innerHTML = "";
    const inicio = (paginaAtual - 1) * resultadosPorPagina;
    const fim = inicio + resultadosPorPagina;
    const pageItems = resultadosFiltrados.slice(inicio, fim);

    let index = 0;
    for (const cveId of pageItems) {
        const infoCVE = await getInfoCVE(cveId);
        const cvssScore = parseFloat(infoCVE.cvss?.[0]?.baseScore || 0);
        const cwe = infoCVE.cwe || "";

        // Define cores
        let cvssColor = "#a8a29e", borderColor = "#3f3f46";
        if (cvssScore >= 9.0) { cvssColor = "#ef4444"; borderColor = "#ef4444"; }
        else if (cvssScore >= 7.0) { cvssColor = "#f97316"; borderColor = "#f97316"; }
        else if (cvssScore >= 4.0) { cvssColor = "#eab308"; borderColor = "#eab308"; }
        else if (cvssScore > 0) { cvssColor = "#22c55e"; borderColor = "#22c55e"; }

        const backgrounds = ["#1c1c1c", "#202020", "#2a2a2a"];
        const baseColor = backgrounds[resultadosRenderizados % backgrounds.length];

        const card = document.createElement("div");
        card.className = `p-4 rounded-lg shadow hover:shadow-lg transition text-sm border-l-4 relative group`;
        card.style.backgroundColor = baseColor;
        card.style.borderLeft = `4px solid ${borderColor}`;

        const contentWrapper = document.createElement("div");
        contentWrapper.className = "card-content-wrapper overflow-hidden max-h-[100px] transition-all duration-300 ease-in-out";

        const hasPocList = Array.isArray(infoCVE.pocList) && infoCVE.pocList.length > 0;
        const hasAdvisorie = !!infoCVE.github?.pocAdvisorie?.url;
        const hasRepo = !!infoCVE.github?.repo;
        const tags = [];

        if (hasPocList)
            tags.push(`<span class="bg-[#3b3b3b] text-green-400 text-xs px-2 py-0.5 rounded">PoCs: ${infoCVE.pocList.length}</span>`);

        if (hasAdvisorie)
            tags.push(`<span class="bg-[#3b3b3b] text-blue-400 text-xs px-2 py-0.5 rounded">Advisorie</span>`);

        if (hasRepo)
            tags.push(`<span class="bg-[#3b3b3b] text-yellow-300 text-xs px-2 py-0.5 rounded">Repo</span>`);

        if (Array.isArray(infoCVE.github?.commits) && infoCVE.github.commits.length > 0)
            tags.push(`<span class="bg-[#3b3b3b] text-purple-400 text-xs px-2 py-0.5 rounded">Commit</span>`);

        contentWrapper.innerHTML = `
          <div class="flex items-start justify-between mb-2">
            <h2 class="text-lg font-semibold text-[#f0eada]">${infoCVE["cveId"]}</h2>
            <div class="flex flex-wrap gap-1">${tags.join('')}</div>
          </div>
        
          <pre class="whitespace-pre-wrap text-[#d6d3cd] text-base mb-2">${infoCVE["description"]?.[0] || ""}</pre>
        
          <div class="flex flex-wrap gap-2 mb-3">
            <span class="bg-[#2d2a26] text-[#e7e5e4] text-xs px-2 py-1 rounded">CWE: ${infoCVE.cwe || "N/A"}</span>
            <span class="bg-[#2d2a26] text-[${cvssColor}] font-semibold text-xs px-2 py-1 rounded">CVSS Score: ${cvssScore}</span>
            <span class="bg-[#2d2a26] text-[#e7e5e4] text-xs px-2 py-1 rounded">Publicado: ${infoCVE.published}</span>
            ${infoCVE.github?.info?.language ? `
              <span class="bg-[#2d2a26] text-[#38bdf8] text-xs px-2 py-1 rounded flex items-center gap-1">
                <img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/${infoCVE.github.info.language.toLowerCase()}/${infoCVE.github.info.language.toLowerCase()}-original.svg" class="w-4 h-4" />
                ${infoCVE.github.info.language}
              </span>` : ""
            }
          </div>
        
          ${hasRepo ? `
            <pre class="text-[#a8a29e] text-sm mb-2">🔗 Repositório: <a href="${infoCVE.github.repo}" class="text-[#60a5fa] hover:underline" target="_blank">${infoCVE.github.repo}</a></pre>` : ""
            }
          
          ${hasAdvisorie ? `
            <pre class="text-[#a8a29e] text-sm mb-2">🔍 Advisorie: <a href="${infoCVE.github.pocAdvisorie.url}" class="text-[#60a5fa] hover:underline" target="_blank">${infoCVE.github.pocAdvisorie.url}</a><br/> Kw: <span class="text-[#34d399]">${infoCVE.github.pocAdvisorie.kw}</span></pre>` : ""
            }
          
          ${hasPocList ? `
            <div class="mb-2">
              <p class="text-xs font-semibold text-[#c4bfb5] mb-1">💥 PoCs encontrados:</p>
              <ul class="list-disc ml-4 text-sm text-[#a8a29e]">
                ${infoCVE.pocList.map(poc => `
                  <li><a href="${poc}" target="_blank" class="text-[#60a5fa] hover:underline">${poc}</a></li>
                `).join("")}
              </ul>
            </div>` : ""
            }
          
          ${Array.isArray(infoCVE.github?.commits) && infoCVE.github.commits.length > 0 ? `
            <div class="mb-2">
              <p class="text-xs font-semibold text-[#c4bfb5] mb-1">🔧 Commits:</p>
              <ul class="list-disc ml-4 text-sm text-[#a8a29e]">
                ${infoCVE.github.commits.map(commit => `
                  <li><a href="${commit}" target="_blank" class="text-[#60a5fa] hover:underline">${commit.split("/").pop().slice(0, 8)}</a></li>
                `).join("")}
              </ul>
            </div>` : ""
            }
          
          ${Array.isArray(infoCVE.references) && infoCVE.references.length > 0 ? `
            <div class="mb-2">
              <p class="text-xs font-semibold text-[#c4bfb5] mb-1">📚 Referências:</p>
              <ul class="list-disc ml-4 text-sm text-[#a8a29e]">
                ${infoCVE.references.map(ref => `
                  <li><a href="${ref}" target="_blank" class="text-[#60a5fa] hover:underline">${ref}</a></li>
                `).join("")}
              </ul>
            </div>` : ""
            }
        `;


        const toggleBtn = document.createElement("button");
        toggleBtn.innerHTML = "▼";
        toggleBtn.className = "absolute bottom-1 right-2 text-[#a8a29e] text-xs bg-[#1c1c1c] px-1 rounded cursor-pointer group-hover:opacity-100 opacity-0 transition-opacity";
        toggleBtn.onclick = () => {
            const isOpen = contentWrapper.classList.contains("max-h-[100px]");
            contentWrapper.classList.toggle("max-h-[100px]");
            contentWrapper.classList.toggle("max-h-[1000px]");
            toggleBtn.innerHTML = isOpen ? "▲" : "▼";
        };

        card.appendChild(contentWrapper);
        card.appendChild(toggleBtn);
        resultadoContainer.appendChild(card);
        resultadosRenderizados++;

    }

    const totalPaginas = Math.ceil(resultadosFiltrados.length / resultadosPorPagina);
    renderizarPaginacao(totalPaginas);
}

function renderizarPaginacao(totalPaginas) {
    const paginacaoEl = document.getElementById("paginacao");
    paginacaoEl.innerHTML = "";

    if (totalPaginas <= 1) return;

    const anterior = document.createElement("button");
    anterior.innerText = "◀ Anterior";
    anterior.disabled = paginaAtual === 1;
    anterior.className = "px-3 py-1 bg-[#2a2a2a] rounded hover:bg-[#3a3a3a] disabled:opacity-30";
    anterior.onclick = () => {
        paginaAtual--;
        renderPaginaAtual();
    };

    const proximo = document.createElement("button");
    proximo.innerText = "Próximo ▶";
    proximo.disabled = paginaAtual === totalPaginas;
    proximo.className = "px-3 py-1 bg-[#2a2a2a] rounded hover:bg-[#3a3a3a] disabled:opacity-30";
    proximo.onclick = () => {
        paginaAtual++;
        renderPaginaAtual();
    };

    paginacaoEl.appendChild(anterior);
    paginacaoEl.appendChild(document.createTextNode(`Página ${paginaAtual} de ${totalPaginas}`));
    paginacaoEl.appendChild(proximo);
}
