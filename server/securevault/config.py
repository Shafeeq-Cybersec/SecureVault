"""Tunable constants for the scanning engine."""

GITHUB_API = "https://api.github.com"
USER_AGENT = "SecureVault-Scanner"

# Networking / quota friendliness
CONCURRENCY = 6          # max simultaneous GitHub content requests
REQUEST_TIMEOUT = 20.0   # seconds per HTTP request

# File filtering
MAX_FILE_SIZE = 1_000_000   # bytes; larger blobs are skipped (and the Contents
                            # API won't inline them anyway)
MAX_LINE_LENGTH = 2_000     # skip absurdly long lines (minified bundles)

# Directory names that never contain user secrets worth scanning.
SKIP_DIRS = {
    "node_modules", ".git", "vendor", "dist", "build", ".next", "out",
    "__pycache__", ".venv", "venv", "env", ".idea", ".vscode",
    "bower_components", "coverage", ".cache", ".pytest_cache", "target",
}

# Lockfiles: huge, noisy, and don't hold secrets.
SKIP_FILENAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "composer.lock", "gemfile.lock", "cargo.lock", "go.sum",
}

# Binary / non-text extensions: never worth a content fetch.
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tif", ".tiff",
    ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z", ".bz2", ".xz",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".webm", ".wav", ".flac",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".class", ".jar", ".war", ".exe", ".dll", ".so", ".dylib", ".bin",
    ".o", ".a", ".obj", ".lib", ".pyc", ".pyo", ".wasm",
    ".map", ".sum", ".lock", ".ds_store", ".psd", ".ai", ".sketch",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
}
