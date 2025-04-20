function toggleModal() {
    const modal = document.getElementById('filterModal');
    modal.classList.toggle('hidden');
    modal.classList.toggle('flex');
}

function toggleDetails(ulElement) {
    if (!ulElement) return;
    ulElement.classList.toggle("hidden");
}

function toogleOptionSearch() {
    document.getElementById("dropdownMenu").classList.toggle("hidden");
}

function formatNumbers(num) {
    if (num < 1000) return num.toString();
    if (num < 1_000_000) { return (num / 1000).toFixed(1).replace('.0', '') + 'k'; }
    return (num / 1_000_000).toFixed(1).replace('.0', '') + 'M';
}

function getSelectedFilters(group) {
    const buttons = document.querySelectorAll(`[data-group="${group}"].active`);
    return Array.from(buttons).map(btn =>
        btn.textContent.trim().split(":")[0] // só pega o CWE-ID (ex: CWE-79)
    );
}
