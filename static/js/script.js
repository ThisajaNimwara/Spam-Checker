document.addEventListener('DOMContentLoaded', () => {
    // Tab switching
    window.switchTab = (tab) => {
        document.getElementById('paste-form').classList.add('hidden');
        document.getElementById('upload-form').classList.add('hidden');
        document.getElementById(`${tab}-form`).classList.remove('hidden');

        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.toggle('active', btn.onclick.toString().includes(tab));
        });
    };

    // Paste Email Form
    document.getElementById('analyzePasteBtn').addEventListener('click', async () => {
        const emailText = document.getElementById('emailInput').value.trim();
        if (!emailText) {
            alert('Please paste an email!');
            return;
        }
        analyzeEmail({ email_text: emailText });
    });

    // Upload File Form
    document.getElementById('uploadForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const fileInput = document.getElementById('emailFile');
        const file = fileInput.files[0];
        if (!file) {
            alert('Please select an .eml or .msg file!');
            return;
        }
        if (!file.name.toLowerCase().endsWith('.eml') && !file.name.toLowerCase().endsWith('.msg')) {
            alert('Invalid file type. Only .eml and .msg are supported.');
            return;
        }

        const formData = new FormData();
        formData.append('email_file', file);
        analyzeEmail(formData, true);
    });

    // Analyze function
    async function analyzeEmail(data, isFile = false) {
        const resultDiv = document.getElementById('result');
        const loadingDiv = document.getElementById('loading');
        resultDiv.classList.add('hidden');
        loadingDiv.classList.remove('hidden');

        try {
            const options = isFile ? {
                method: 'POST',
                body: data
            } : {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            };
            const response = await fetch('/predict', options);
            const result = await response.json();

            if (result.error) {
                alert(result.error);
                return;
            }

            const label = result.label;
            document.getElementById('label').textContent = label;
            document.getElementById('confidence').textContent = result.confidence;

            resultDiv.classList.remove('hidden', 'spam', 'ham');
            resultDiv.classList.add(label.includes('Spam') ? 'spam' : 'ham');

            const detailsDiv = document.getElementById('details');
            detailsDiv.innerHTML = `
                <p>- Your Model: ${result.details.model}%</p>
                <p>- Rspamd: ${result.details.rspamd}%</p>
                <p>- SpamAssassin: ${result.details.spamassassin}%</p>
                <p>- SpamCheck API: ${result.details.spamcheck}%</p>
                <p>- VirusTotal (URLs): ${result.details.virustotal}%</p>
            `;
            detailsDiv.classList.add('hidden');

            document.getElementById('toggleDetails').textContent = 'Show Details';
        } catch (error) {
            alert('Error analyzing email: ' + error);
        } finally {
            loadingDiv.classList.add('hidden');
        }
    }

    // Toggle details
    document.getElementById('toggleDetails').addEventListener('click', () => {
        const detailsDiv = document.getElementById('details');
        const isHidden = detailsDiv.classList.contains('hidden');
        detailsDiv.classList.toggle('hidden');
        document.getElementById('toggleDetails').textContent = isHidden ? 'Hide Details' : 'Show Details';
    });
});