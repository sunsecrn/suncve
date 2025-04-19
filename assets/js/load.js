async function carregarJsonComprimido(url) {
    const response = await fetch(url);
    const compressed = new Uint8Array(await response.arrayBuffer());
    const decompressed = pako.ungzip(compressed, { to: 'string' });
    dadosJSON = JSON.parse(decompressed);
    resultadoContainer.innerHTML = `<div class="col-span-full text-center text-sm text-[#c4bfb5]">Base carregada. Agora busque algo.</div>`;
}

async function carregarCWEMap() {
    try {
        const response = await fetch("/index/cwes.json");
        if (!response.ok) throw new Error("Falha ao carregar cwes.json");
        cweMap = await response.json();
    } catch (e) {
        console.error("Erro ao carregar cwes.json:", e);
        cweMap = {};
    }
}

async function carregarScoreMap() {
    try {
        const response = await fetch("/index/score.json");
        if (!response.ok) throw new Error("Falha ao carregar cwes.json");
        scoreMap = await response.json();
    } catch (e) {
        console.error("Erro ao carregar cwes.json:", e);
        scoreMap = {};
    }
}