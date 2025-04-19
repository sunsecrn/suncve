async function getInfoCVE(cveID) {
    try {
        const response = await fetch(`/cves/${cveID}.json`);
        if (!response.ok) return {};
        const data = await response.json();
        return data;
    } catch (erro) {
        return {};
    }
}

async function getRepositories() {
    try {
        var response = await fetch("/index/repositories.json");
        if (!response.ok) return {};
        repositoriesJSON = await response.json();

        response = await fetch("/index/cves_repositories.json");
        if (!response.ok) return {};
        repositoriesCVEsJSON = await response.json();

        response = await fetch("/index/cves_poc_advisories.json");
        if (!response.ok) return {};
        cvesPocAdvisories = await response.json();

        response = await fetch("/index/cves_poc_list_in_github.json");
        if (!response.ok) return {};
        cvesPocListInGithub = await response.json();

    } catch (erro) {
        return {};
    }
}

