document.addEventListener('DOMContentLoaded', () => {
    const app = {
        state: {
            action: 'hide',
            hostFile: null,
            fileToHide: null,
            publicKey: null,
            outputFile: null
        },
        
        init() {
            this.bindElements();
            this.bindEvents();
        },
        
        bindElements() {
            this.elements = {
                actionButton: document.querySelector('#actionButton'),
                hostFileInput: document.querySelector('#hostFile'),
                fileToHideInput: document.querySelector('#fileToHide'),
                publicKeyInput: document.querySelector('#publicKey'),
                outputFileInput: document.querySelector('#outputFile'),
                form: document.querySelector('#mainForm')
            };
        },
        
        bindEvents() {
            this.elements.actionButton.addEventListener('click', (e) => this.toggleAction(e));
            this.elements.hostFileInput.addEventListener('change', (e) => this.handleHostFile(e));
            this.elements.fileToHideInput.addEventListener('change', (e) => this.handleFileToHide(e));
            this.elements.publicKeyInput.addEventListener('change', (e) => this.handlePublicKey(e));
            this.elements.outputFileInput.addEventListener('change', (e) => this.handleOutputFile(e));
            this.elements.form.addEventListener('submit', (e) => this.handleSubmit(e));
        },
        
        toggleAction(e) {
            e.preventDefault();
            this.state.action = this.state.action === 'hide' ? 'unhide' : 'hide';
            this.updateUI();
        },
        
        updateUI() {
            // Update button label
            this.elements.actionButton.textContent = this.state.action === 'hide' ? 'Unhide File' : 'Hide File';
            
            // Toggle visibility of relevant sections
            document.querySelectorAll('.form-section').forEach(el => {
                el.style.display = this.state.action === 'hide' ? 'block' : 'none';
            });
        },
        
        handleHostFile(e) {
            this.state.hostFile = e.target.files[0];
        },
        
        handleFileToHide(e) {
            this.state.fileToHide = e.target.files[0];
        },
        
        handlePublicKey(e) {
            this.state.publicKey = e.target.files[0];
        },
        
        handleOutputFile(e) {
            this.state.outputFile = e.target.files[0];
        },
        
        async handleSubmit(e) {
            e.preventDefault();
            
            if (this.state.action === 'hide') {
                await this.hideAndEncryptFile();
            } else {
                await this.unhideAndDecryptFile();
            }
        },
        
        async hideAndEncryptFile() {
            const formData = new FormData();
            formData.append('host_file', this.state.hostFile);
            formData.append('file_to_hide', this.state.fileToHide);
            formData.append('public_key', this.state.publicKey);

            try {
                const response = await fetch('/hide/', {
                    method: 'POST',
                    body: formData
                });
                
                if (response.ok) {
                    const blob = await response.blob();
                    this.downloadFile(blob, `stego_${this.state.hostFile.name}`);
                    this.showAlert('File hidden and encrypted successfully!', 'success');
                } else {
                    this.showAlert('Error hiding and encrypting file', 'error');
                }
            } catch (error) {
                this.showAlert(`An error occurred: ${error.message}`, 'error');
            }
        },
        
        async unhideAndDecryptFile() {
            const formData = new FormData();
            formData.append('host_file', this.state.hostFile);
            formData.append('private_key', this.state.publicKey);
            formData.append('output_file', this.state.outputFile);

            try {
                const response = await fetch('/unhide/', {
                    method: 'POST',
                    body: formData
                });
                
                if (response.ok) {
                    const blob = await response.blob();
                    this.downloadFile(blob, 'extracted_file');
                    this.showAlert('File decrypted and extracted successfully!', 'success');
                } else {
                    this.showAlert('Error unhiding and decrypting file', 'error');
                }
            } catch (error) {
                this.showAlert(`An error occurred: ${error.message}`, 'error');
            }
        },
        
        downloadFile(blob, filename) {
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        },
        
        showAlert(message, type = 'info') {
            const alertBox = document.createElement('div');
            alertBox.className = `alert alert-${type}`;
            alertBox.textContent = message;
            
            const container = document.querySelector('.container');
            container.insertBefore(alertBox, container.firstChild);
            
            setTimeout(() => {
                alertBox.remove();
            }, 5000);
        }
    };

    app.init();
});