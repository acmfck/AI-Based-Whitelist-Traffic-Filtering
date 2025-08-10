// 通用工具函数
const Utils = {
    // 格式化文件大小
    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },

    // 格式化时间
    formatTime(seconds) {
        if (seconds < 60) {
            return seconds.toFixed(2) + ' 秒';
        } else if (seconds < 3600) {
            const minutes = Math.floor(seconds / 60);
            const remainingSeconds = (seconds % 60).toFixed(0);
            return `${minutes}分${remainingSeconds}秒`;
        } else {
            const hours = Math.floor(seconds / 3600);
            const minutes = Math.floor((seconds % 3600) / 60);
            return `${hours}小时${minutes}分钟`;
        }
    },

    // 显示提示消息
    showMessage(message, type = 'info', duration = 3000) {
        const messageDiv = document.createElement('div');
        messageDiv.className = `alert alert-${type}`;
        messageDiv.style.position = 'fixed';
        messageDiv.style.top = '20px';
        messageDiv.style.right = '20px';
        messageDiv.style.zIndex = '9999';
        messageDiv.style.minWidth = '300px';
        messageDiv.textContent = message;
        
        document.body.appendChild(messageDiv);
        
        setTimeout(() => {
            messageDiv.remove();
        }, duration);
    }
};

// 文件上传处理类
class FileUploader {
    constructor(options) {
        this.uploadArea = options.uploadArea;
        this.fileInput = options.fileInput;
        this.progressBar = options.progressBar;
        this.progressFill = options.progressFill;
        this.onFileSelect = options.onFileSelect;
        this.onUploadProgress = options.onUploadProgress;
        this.onUploadComplete = options.onUploadComplete;
        this.onUploadError = options.onUploadError;
        
        this.init();
    }
    
    init() {
        // 点击上传区域触发文件选择
        this.uploadArea.addEventListener('click', () => {
            this.fileInput.click();
        });
        
        // 拖拽上传功能
        this.uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            this.uploadArea.classList.add('dragover');
        });
        
        this.uploadArea.addEventListener('dragleave', () => {
            this.uploadArea.classList.remove('dragover');
        });
        
        this.uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            this.uploadArea.classList.remove('dragover');
            
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                this.fileInput.files = files;
                this.handleFileSelect();
            }
        });
        
        // 文件选择处理
        this.fileInput.addEventListener('change', () => {
            this.handleFileSelect();
        });
    }
    
    handleFileSelect() {
        const file = this.fileInput.files[0];
        if (file && this.onFileSelect) {
            this.onFileSelect(file);
        }
    }
    
    upload(file, url) {
        const formData = new FormData();
        formData.append('file', file);
        
        // 显示进度条
        if (this.progressBar) {
            this.progressBar.style.display = 'block';
        }
        
        // 模拟进度更新
        let progress = 0;
        const progressInterval = setInterval(() => {
            progress += Math.random() * 10;
            if (progress > 90) progress = 90;
            this.updateProgress(progress);
        }, 200);
        
        return fetch(url, {
            method: 'POST',
            body: formData
        })
        .then(response => {
            clearInterval(progressInterval);
            this.updateProgress(100);
            
            if (response.ok) {
                if (this.onUploadComplete) {
                    this.onUploadComplete(response);
                }
                return response;
            } else {
                throw new Error('上传失败');
            }
        })
        .catch(error => {
            clearInterval(progressInterval);
            if (this.onUploadError) {
                this.onUploadError(error);
            }
            throw error;
        });
    }
    
    updateProgress(percent) {
        if (this.progressFill) {
            this.progressFill.style.width = percent + '%';
        }
        if (this.onUploadProgress) {
            this.onUploadProgress(percent);
        }
    }
    
    reset() {
        this.fileInput.value = '';
        if (this.progressBar) {
            this.progressBar.style.display = 'none';
        }
        if (this.progressFill) {
            this.progressFill.style.width = '0%';
        }
    }
}

// API 客户端类
class ApiClient {
    constructor(baseUrl = '') {
        this.baseUrl = baseUrl;
    }
    
    async uploadFile(file) {
        const formData = new FormData();
        formData.append('file', file);
        
        const response = await fetch(`${this.baseUrl}/api/upload`, {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return await response.json();
    }
    
    async getStatus(taskId) {
        const response = await fetch(`${this.baseUrl}/api/status/${taskId}`);
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return await response.json();
    }
    
    getDownloadUrl(filename) {
        return `${this.baseUrl}/download/${filename}`;
    }
}

// 文件验证工具
class FileValidator {
    static validatePcapFile(file) {
        const validExtensions = ['.pcap', '.pcapng'];
        const maxSize = 100 * 1024 * 1024; // 100MB
        
        // 检查文件扩展名
        const fileName = file.name.toLowerCase();
        const hasValidExtension = validExtensions.some(ext => fileName.endsWith(ext));
        
        if (!hasValidExtension) {
            return {
                valid: false,
                error: '请选择有效的PCAP文件格式 (.pcap 或 .pcapng)'
            };
        }
        
        // 检查文件大小
        if (file.size > maxSize) {
            return {
                valid: false,
                error: '文件大小超过100MB限制'
            };
        }
        
        return { valid: true };
    }
}

// 动画效果工具
const AnimationUtils = {
    fadeIn(element, duration = 300) {
        element.style.opacity = '0';
        element.style.display = 'block';
        
        let start = null;
        function animate(timestamp) {
            if (!start) start = timestamp;
            const progress = timestamp - start;
            
            element.style.opacity = Math.min(progress / duration, 1);
            
            if (progress < duration) {
                requestAnimationFrame(animate);
            }
        }
        
        requestAnimationFrame(animate);
    },
    
    fadeOut(element, duration = 300) {
        let start = null;
        function animate(timestamp) {
            if (!start) start = timestamp;
            const progress = timestamp - start;
            
            element.style.opacity = Math.max(1 - (progress / duration), 0);
            
            if (progress < duration) {
                requestAnimationFrame(animate);
            } else {
                element.style.display = 'none';
            }
        }
        
        requestAnimationFrame(animate);
    },
    
    slideDown(element, duration = 300) {
        element.style.height = '0px';
        element.style.overflow = 'hidden';
        element.style.display = 'block';
        
        const targetHeight = element.scrollHeight;
        let start = null;
        
        function animate(timestamp) {
            if (!start) start = timestamp;
            const progress = timestamp - start;
            
            element.style.height = Math.min((progress / duration) * targetHeight, targetHeight) + 'px';
            
            if (progress < duration) {
                requestAnimationFrame(animate);
            } else {
                element.style.height = 'auto';
                element.style.overflow = 'visible';
            }
        }
        
        requestAnimationFrame(animate);
    }
};

// 页面加载完成后的初始化
document.addEventListener('DOMContentLoaded', function() {
    // 添加页面加载动画
    const cards = document.querySelectorAll('.card, .feature-card');
    cards.forEach((card, index) => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(20px)';
        
        setTimeout(() => {
            card.style.transition = 'all 0.6s ease';
            card.style.opacity = '1';
            card.style.transform = 'translateY(0)';
        }, index * 100);
    });
    
    // 平滑滚动
    const links = document.querySelectorAll('a[href^="#"]');
    links.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const targetId = this.getAttribute('href');
            const targetElement = document.querySelector(targetId);
            
            if (targetElement) {
                targetElement.scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
    });
});

// 导出到全局作用域
window.Utils = Utils;
window.FileUploader = FileUploader;
window.ApiClient = ApiClient;
window.FileValidator = FileValidator;
window.AnimationUtils = AnimationUtils;
