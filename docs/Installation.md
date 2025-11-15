# Installation

Install from GitHub (no PyPI):

```bash
pip install "pkg-auth @ git+https://github.com/OWNER/REPO.git@pkg_auth-vX.Y.Z"
```

Extras (FastAPI / Strawberry):

```bash
pip install "pkg-auth[fastapi] @ git+https://github.com/OWNER/REPO.git@pkg_auth-vX.Y.Z"
pip install "pkg-auth[strawberry] @ git+https://github.com/OWNER/REPO.git@pkg_auth-vX.Y.Z"
```

Replace OWNER/REPO and X.Y.Z with your repository and the package tag (e.g. pkg_auth-v0.2.0).

Monorepo note: if the package lives in a subdirectory, append
`#subdirectory=path/to/pkg` to the URL.

## Install from a Release asset (public repos)

If your repository is public, you can install the wheel directly from the Release page:

```bash
pip install "https://github.com/OWNER/REPO/releases/download/pkg_auth-vX.Y.Z/pkg_auth-X.Y.Z-py3-none-any.whl"
```

Use the exact wheel filename shown on the Release; names typically use underscores for the project name (pkg_auth-...).
