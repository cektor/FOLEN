from setuptools import setup, find_packages

setup(
    name="folen",
    version="1.0",
    packages=find_packages(),
    install_requires=[
        'pycryptodome',  # Eğer AES gibi şifreleme kullanıyorsanız
        'requests',       # HTTP istekleri için
        'numpy',          # Matematiksel hesaplamalar için (varsa)
        'pillow',         # Görsel işleme için (varsa .png dosyaları kullanıyorsanız)
        'pyqt5',          # Eğer PyQt5 kullanıyorsanız
        'setuptools',     # Setuptools'un var olması gerekebilir
        # Eklediğiniz diğer bağımlılıklar
    ],
    package_data={
        'folen': ['*.png', '*.desktop'],
    },
    data_files=[
        ('share/applications', ['folen.desktop']),
        ('~/.local/share', ['folenlo.png']),
    ],
)

