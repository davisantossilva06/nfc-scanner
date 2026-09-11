[app]

# Nome que aparece no celular
title = NFC Scanner

# Identificacao do pacote (pode deixar assim ou trocar por algo seu)
package.name = nfcscanner
package.domain = org.davi.nfc

# Codigo-fonte na mesma pasta deste arquivo
source.dir = .
source.include_exts = py,png,jpg,kv,atlas

version = 0.1

# Dependencias: python, interface Kivy e a ponte Java (pyjnius)
requirements = python3,kivy,pyjnius

orientation = portrait
fullscreen = 0

# ---- ANDROID ----
# A UNICA permissao necessaria: NFC
android.permissions = android.permission.NFC

# Sobe a API alvo; minapi 21 cobre praticamente todo aparelho atual
android.api = 33
android.minapi = 21

# Arquitetura. arm64-v8a cobre a grande maioria dos celulares.
# Para incluir aparelhos antigos, use: arm64-v8a, armeabi-v7a
android.archs = arm64-v8a

android.allow_backup = 1

# Aceita as licencas do SDK automaticamente (necessario no CI)
android.accept_sdk_license = True

[buildozer]
log_level = 2
warn_on_root = 1
