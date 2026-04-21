# PyInstaller — Security Operations Suite (one-file GUI, no console)
# Build: pyinstaller --noconfirm SecuritySuite.spec
# Output: dist/SecuritySuite.exe

from PyInstaller.utils.hooks import collect_all, collect_submodules

block_cipher = None

datas, binaries, hi_custom = collect_all("customtkinter")

hiddenimports = list(hi_custom)
hiddenimports += collect_submodules("threat_analyzer")
hiddenimports += collect_submodules("cloud_scanner")
hiddenimports += collect_submodules("mini_ares")
hiddenimports += collect_submodules("phishing_detector")
hiddenimports += collect_submodules("network_traffic_analyzer")
hiddenimports += collect_submodules("scapy")
hiddenimports += [
    "sklearn.ensemble",
    "sklearn.preprocessing",
    "numpy",
    "dateutil",
    "rich",
    "httpx",
    "httpcore",
    "certifi",
    "boto3",
    "botocore",
    "azure.identity",
    "azure.mgmt.network",
    "azure.mgmt.storage",
    "azure.core",
    "fastapi",
    "starlette",
    "starlette.routing",
    "uvicorn",
    "pydantic",
    "anyio",
    "sniffio",
    "h11",
]

a = Analysis(
    ["run_gui.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["matplotlib", "pandas"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="SecuritySuite",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
)
