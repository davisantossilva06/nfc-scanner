# -*- coding: utf-8 -*-
"""
NFC Scanner - app Kivy/Android que le tags NFC via reader mode.

Abra o app, encoste o cartao: o dump aparece na tela (rolagem) e o app
fica esperando a proxima tag. Compilado com Buildozer -> vira APK.

O que extrai de cada tag:
  UID + fabricante, ATQA/SAK, tecnologias, GET_VERSION (NTAG213/215/216),
  NDEF decodificado (Texto/URI/MIME/AAR/Smart Poster), dump de paginas
  (Ultralight/NTAG) e de setores (MIFARE Classic com chaves padrao).
"""

from kivy.app import App
from kivy.clock import Clock
from kivy.metrics import dp
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.core.clipboard import Clipboard

from jnius import autoclass, cast, PythonJavaClass, java_method

import time

# ==================================================== DECODER (puro Python)

SAK_TABLE = {
    0x00: "NTAG / MIFARE Ultralight (Type 2)", 0x08: "MIFARE Classic 1K",
    0x09: "MIFARE Mini", 0x10: "MIFARE Plus 2K (SL2)", 0x11: "MIFARE Plus 4K (SL2)",
    0x18: "MIFARE Classic 4K", 0x19: "MIFARE Classic 2K",
    0x20: "ISO 14443-4 (DESFire / JCOP / HCE)",
    0x28: "SmartMX emulando Classic 1K", 0x38: "SmartMX emulando Classic 4K",
}
ATQA_TABLE = {
    0x0044: "Ultralight / NTAG (UID 7B)", 0x0004: "MIFARE Classic 1K (UID 4B)",
    0x0002: "MIFARE Classic 4K (UID 4B)", 0x0344: "DESFire / Plus (UID 7B)",
    0x0304: "MIFARE Plus (UID 4B)",
}
FABRICANTE = {
    0x04: "NXP Semiconductors", 0x02: "STMicroelectronics", 0x05: "Infineon",
    0x07: "Texas Instruments", 0x16: "EM Microelectronic",
    0x1D: "Shanghai Fudan", 0x28: "Samsung",
}
TNF = {
    0x00: "Vazio", 0x01: "NFC Forum Well-Known", 0x02: "MIME Media",
    0x03: "URI Absoluta", 0x04: "Externo", 0x05: "Desconhecido",
    0x06: "Inalterado (chunk)", 0x07: "Reservado",
}
URI_PREFIX = [
    "", "http://www.", "https://www.", "http://", "https://", "tel:", "mailto:",
    "ftp://anonymous:anonymous@", "ftp://ftp.", "ftps://", "sftp://", "smb://",
    "nfs://", "ftp://", "dav://", "news:", "telnet://", "imap:", "rtsp://",
    "urn:", "pop:", "sip:", "sips:", "tftp:", "btspp://", "btl2cap://",
    "btgoep://", "tcpobex://", "irdaobex://", "file://", "urn:epc:id:",
    "urn:epc:tag:", "urn:epc:pat:", "urn:epc:raw:", "urn:epc:", "urn:nfc:",
]


def hexs(b, sep=":"):
    return sep.join("%02X" % x for x in b)


def printable(b):
    return "".join(chr(x) if 32 <= x < 127 else "." for x in b)


def hexdump(dados, largura=8):
    out = []
    for i in range(0, len(dados), largura):
        bl = dados[i:i + largura]
        out.append("  %04X  %-*s |%s|" % (i, largura * 3,
                   " ".join("%02X" % x for x in bl), printable(bl)))
    return out


def descreve_uid(uid):
    L = ["UID        : %s  (%d bytes)" % (hexs(uid), len(uid))]
    if len(uid) == 4:
        L.append("Formato    : UID simples (4B)")
        if uid[0] == 0x08:
            L.append("ATENCAO    : 0x08 = UID aleatorio")
    elif len(uid) == 7:
        L.append("Formato    : UID duplo (7B) padrao NXP")
        if uid[0] in FABRICANTE:
            L.append("Fabricante : 0x%02X - %s" % (uid[0], FABRICANTE[uid[0]]))
    elif len(uid) == 10:
        L.append("Formato    : UID triplo (10B)")
    return L


def parse_ndef(dados, nivel=0):
    regs, i, n = [], 0, len(dados)
    while i < n:
        cab = dados[i]; i += 1
        mb, me = bool(cab & 0x80), bool(cab & 0x40)
        cf, sr, il = bool(cab & 0x20), bool(cab & 0x10), bool(cab & 0x08)
        tnf = cab & 0x07
        if i >= n:
            break
        tlen = dados[i]; i += 1
        if sr:
            plen = dados[i]; i += 1
        else:
            plen = int.from_bytes(dados[i:i + 4], "big"); i += 4
        ilen = 0
        if il:
            ilen = dados[i]; i += 1
        tipo = dados[i:i + tlen]; i += tlen
        rid = dados[i:i + ilen]; i += ilen
        payload = dados[i:i + plen]; i += plen
        regs.append({"mb": mb, "me": me, "cf": cf, "sr": sr, "tnf": tnf,
                     "tipo": tipo, "id": rid, "payload": payload, "nivel": nivel})
        if me:
            break
    return regs


def decodifica_payload(reg):
    tnf, tipo, p = reg["tnf"], reg["tipo"], reg["payload"]
    L = []
    if tnf == 0x01 and tipo == b"T":
        if not p:
            return ["    (texto vazio)"]
        st = p[0]; ln = st & 0x3F
        lang = p[1:1 + ln].decode("ascii", "replace")
        txt = p[1 + ln:].decode("utf-16" if st & 0x80 else "utf-8", "replace")
        L += ["    Tipo    : Texto (RTD_TEXT)", "    Idioma  : %s" % lang,
              "    TEXTO   : %s" % txt]
    elif tnf == 0x01 and tipo == b"U":
        pref = URI_PREFIX[p[0]] if p and p[0] < len(URI_PREFIX) else ""
        L += ["    Tipo    : URI (RTD_URI)",
              "    URI     : %s" % (pref + p[1:].decode("utf-8", "replace"))]
    elif tnf == 0x01 and tipo == b"Sp":
        L.append("    Tipo    : Smart Poster")
        for sub in parse_ndef(p, reg["nivel"] + 1):
            L += formata_registro(sub, "      ")
    elif tnf == 0x02:
        mime = tipo.decode("ascii", "replace")
        L.append("    MIME    : %s" % mime)
        if mime.startswith("text/") or mime == "application/json":
            L.append("    CONTEUDO: %s" % p.decode("utf-8", "replace"))
        elif mime == "application/vnd.bluetooth.ep.oob":
            L.append("    BT MAC  : %s (OOB)" % hexs(bytes(reversed(p[2:8]))))
        else:
            L.append("    Binario : %d bytes" % len(p))
            L += hexdump(p[:48])
    elif tnf == 0x03:
        L.append("    URI Abs.: %s" % p.decode("utf-8", "replace"))
    elif tnf == 0x04:
        t = tipo.decode("ascii", "replace")
        L.append("    Ext.    : %s" % t)
        if t == "android.com:pkg":
            L.append("    AAR     : app -> %s" % p.decode("utf-8", "replace"))
        else:
            L.append("    CONTEUDO: %s" % p.decode("utf-8", "replace"))
    else:
        L.append("    Payload : %d bytes" % len(p))
        if p:
            L += hexdump(p[:48])
    return L


def formata_registro(reg, ind="  "):
    fl = [f for f, c in (("MB", reg["mb"]), ("ME", reg["me"]),
                         ("CF", reg["cf"]), ("SR", reg["sr"])) if c]
    L = ["%sTNF     : 0x%02X %s [%s]" % (ind, reg["tnf"],
         TNF.get(reg["tnf"], "?"), " ".join(fl)),
         "%sTipo    : %s" % (ind, reg["tipo"].decode("ascii", "replace") or "-")]
    L += decodifica_payload(reg)
    return L


def parse_tlv(dados):
    ach, i = [], 0
    while i < len(dados):
        t = dados[i]
        if t == 0x00:
            i += 1; continue
        if t == 0xFE:
            ach.append(("Terminator", b"")); break
        i += 1
        if i >= len(dados):
            break
        ln = dados[i]; i += 1
        if ln == 0xFF:
            ln = int.from_bytes(dados[i:i + 2], "big"); i += 2
        val = dados[i:i + ln]; i += ln
        nome = {0x01: "Lock Control", 0x02: "Memory Control",
                0x03: "NDEF Message", 0xFD: "Proprietary"}.get(t, "TLV 0x%02X" % t)
        ach.append((nome, val))
    return ach


NTAG_PAG = {45: "NTAG213", 135: "NTAG215", 231: "NTAG216",
            16: "Ultralight", 44: "Ultralight C / NTAG203"}


def decode_type2(dados):
    L = []
    if len(dados) < 16:
        return L
    pgs = len(dados) // 4
    L.append("Modelo(aprox): %s (%d paginas)" % (NTAG_PAG.get(pgs, "?"), pgs))
    cc = dados[12:16]
    L.append("CC (pag 3) : %s" % hexs(cc, " "))
    if cc[0] == 0xE1:
        L.append("NDEF magic : E1 v%d.%d, %d bytes, %s" % (cc[1] >> 4, cc[1] & 0xF,
                 cc[2] * 8, "so leitura" if cc[3] == 0x0F else "leitura/escrita"))
    L.append("--- paginas ---")
    for p in range(pgs):
        pg = dados[p * 4:(p + 1) * 4]
        nota = "UID/lock" if p <= 2 else ("CC" if p == 3 else "")
        L.append("[%03d] %s |%s| %s" % (p, hexs(pg, " "), printable(pg), nota))
    L.append("--- TLV / NDEF ---")
    achou = False
    for nome, val in parse_tlv(dados[16:]):
        L.append("TLV: %s (%d bytes)" % (nome, len(val)))
        if nome == "NDEF Message" and val:
            achou = True
            for r in parse_ndef(val):
                L += formata_registro(r)
    if not achou:
        L.append("(sem NDEF valido)")
    return L


def montar_relatorio(tag):
    """Le o maximo do objeto android.nfc.Tag e devolve texto pronto."""
    L = []
    L.append("=" * 40)
    L.append("TAG  %s" % time.strftime("%H:%M:%S"))
    L.append("=" * 40)

    try:
        uid = jb(tag.getId())
        L += descreve_uid(uid)
    except Exception as e:
        L.append("UID: erro %s" % e)

    try:
        techs = [str(t) for t in tag.getTechList()]
        L.append("Tecnologias: " + ", ".join(t.split(".")[-1] for t in techs))
    except Exception:
        techs = []

    def tem(nome):
        return any(t.endswith(nome) for t in techs)

    if tem("NfcA"):
        try:
            NfcA = autoclass('android.nfc.tech.NfcA')
            a = NfcA.get(tag)
            atqa = jb(a.getAtqa())
            sak = a.getSak() & 0xFF
            av = (atqa[1] << 8 | atqa[0]) if len(atqa) == 2 else 0
            L.append("ATQA : 0x%04X - %s" % (av, ATQA_TABLE.get(av, "?")))
            L.append("SAK  : 0x%02X - %s" % (sak, SAK_TABLE.get(sak, "?")))
            try:
                a.connect()
                L.append("TxMax: %d bytes" % a.getMaxTransceiveLength())
                try:
                    ver = jb(a.transceive([0x60]))
                    if len(ver) >= 8:
                        prod = {0x03: "Ultralight EV1", 0x04: "NTAG"}.get(ver[2], "0x%02X" % ver[2])
                        tam = {0x0B: "213(144B)", 0x0F: "215(504B)", 0x11: "216(888B)",
                               0x0E: "UL EV1(48B)"}.get(ver[6], "0x%02X" % ver[6])
                        L.append("GET_VERSION: %s %s (%s)" % (prod, tam, hexs(ver, " ")))
                except Exception:
                    pass
                a.close()
            except Exception:
                pass
        except Exception as e:
            L.append("NfcA: erro %s" % e)

    if tem("IsoDep"):
        try:
            d = autoclass('android.nfc.tech.IsoDep').get(tag)
            hist = jb(d.getHistoricalBytes())
            hi = jb(d.getHiLayerResponse())
            if hist:
                L.append("IsoDep ATS: %s" % hexs(hist, " "))
            if hi:
                L.append("IsoDep HiL: %s" % hexs(hi, " "))
        except Exception:
            pass

    if tem("NfcF"):
        try:
            f = autoclass('android.nfc.tech.NfcF').get(tag)
            L.append("NfcF Manuf=%s Sys=%s" % (hexs(jb(f.getManufacturer()), " "),
                     hexs(jb(f.getSystemCode()), " ")))
        except Exception:
            pass
    if tem("NfcV"):
        try:
            v = autoclass('android.nfc.tech.NfcV').get(tag)
            L.append("NfcV DSFID=0x%02X Flags=0x%02X" %
                     (v.getDsfId() & 0xFF, v.getResponseFlags() & 0xFF))
        except Exception:
            pass

    if tem("Ndef"):
        try:
            nd = autoclass('android.nfc.tech.Ndef').get(tag)
            L.append("NDEF: tipo=%s max=%d escrevivel=%s" %
                     (nd.getType(), nd.getMaxSize(), nd.isWritable()))
            msg = nd.getCachedNdefMessage()
            if msg is None:
                nd.connect(); msg = nd.getNdefMessage(); nd.close()
            if msg is not None:
                raw = jb(msg.toByteArray())
                L.append("--- Mensagem NDEF (%d bytes) ---" % len(raw))
                for r in parse_ndef(raw):
                    L += formata_registro(r)
        except Exception as e:
            L.append("Ndef: erro %s" % e)
    elif tem("NdefFormatable"):
        L.append("NDEF: formatavel, sem dados")

    if tem("MifareUltralight"):
        try:
            m = autoclass('android.nfc.tech.MifareUltralight').get(tag)
            m.connect()
            dump = bytearray()
            p = 0
            while p < 231:
                try:
                    dump += jb(m.readPages(p)); p += 4
                except Exception:
                    break
            m.close()
            if dump:
                L.append("--- DUMP Ultralight/NTAG (%d bytes) ---" % len(dump))
                L += decode_type2(bytes(dump))
        except Exception as e:
            L.append("Ultralight: erro %s" % e)

    if tem("MifareClassic"):
        try:
            MC = autoclass('android.nfc.tech.MifareClassic')
            m = MC.get(tag)
            L.append("Classic: %d bytes, %d setores, %d blocos" %
                     (m.getSize(), m.getSectorCount(), m.getBlockCount()))
            chaves = []
            for nome in ("KEY_DEFAULT", "KEY_NFC_FORUM",
                         "KEY_MIFARE_APPLICATION_DIRECTORY"):
                try:
                    chaves.append(getattr(MC, nome))
                except Exception:
                    pass
            m.connect()
            lidos = 0
            for s in range(m.getSectorCount()):
                ok = False
                for k in chaves:
                    try:
                        if m.authenticateSectorWithKeyA(s, k):
                            ok = True; break
                    except Exception:
                        pass
                if not ok:
                    continue
                first = m.sectorToBlock(s)
                for bl in range(m.getBlockCountInSector(s)):
                    try:
                        b = jb(m.readBlock(first + bl))
                        L.append("[%03d] %s |%s|" %
                                 (first + bl, hexs(b, " "), printable(b)))
                        lidos += 1
                    except Exception:
                        pass
            m.close()
            if not lidos:
                L.append("(nenhum setor abriu com chaves padrao)")
        except Exception as e:
            L.append("Classic: erro %s" % e)

    L.append("")
    return "\n".join(L)


def jb(arr):
    if arr is None:
        return b""
    return bytes((int(v) & 0xFF) for v in arr)


# ==================================================== PONTE ANDROID / UI

PythonActivity = autoclass('org.kivy.android.PythonActivity')
NfcAdapter = autoclass('android.nfc.NfcAdapter')

_keep = []  # segura proxies Java vivos contra o GC


def run_on_ui_thread(func):
    activity = PythonActivity.mActivity

    class _R(PythonJavaClass):
        __javainterfaces__ = ['java/lang/Runnable']
        __javacontext__ = 'app'

        @java_method('()V')
        def run(self):
            try:
                func()
            except Exception as e:
                print("ui-thread erro:", e)

    r = _R()
    _keep.append(r)
    activity.runOnUiThread(r)


class NFCApp(App):
    def build(self):
        self.title = "NFC Scanner"
        self.buffer = ""
        root = BoxLayout(orientation="vertical")

        self.status = Label(text="iniciando...", size_hint_y=None, height=dp(38),
                            color=(0.6, 1, 0.6, 1))
        root.add_widget(self.status)

        self.scroll = ScrollView()
        self.out = Label(text="encoste um cartao NFC...", size_hint_y=None,
                         halign="left", valign="top", padding=(dp(8), dp(8)),
                         color=(0.85, 1, 0.85, 1), font_size=dp(12))
        self.out.bind(width=lambda *_: setattr(self.out, "text_size",
                      (self.out.width - dp(16), None)))
        self.out.bind(texture_size=lambda *_: setattr(self.out, "height",
                      self.out.texture_size[1] + dp(16)))
        self.scroll.add_widget(self.out)
        root.add_widget(self.scroll)

        row = BoxLayout(size_hint_y=None, height=dp(50))
        b1 = Button(text="Limpar"); b1.bind(on_release=self.limpar)
        b2 = Button(text="Copiar"); b2.bind(on_release=self.copiar)
        row.add_widget(b1); row.add_widget(b2)
        root.add_widget(row)

        self.adapter = None
        self.callback = None
        return root

    def on_start(self):
        try:
            act = PythonActivity.mActivity
            self.adapter = NfcAdapter.getDefaultAdapter(act)
        except Exception as e:
            self.set_status("erro adaptador: %s" % e)
            return
        if self.adapter is None:
            self.set_status("este aparelho nao tem NFC")
            return

        app = self

        class ReaderCallback(PythonJavaClass):
            __javainterfaces__ = ['android/nfc/NfcAdapter$ReaderCallback']
            __javacontext__ = 'app'

            @java_method('(Landroid/nfc/Tag;)V')
            def onTagDiscovered(self, tag):
                try:
                    texto = montar_relatorio(tag)
                except Exception as e:
                    texto = "erro ao ler tag: %s" % e
                Clock.schedule_once(lambda dt: app.mostrar(texto), 0)

        self.callback = ReaderCallback()
        _keep.append(self.callback)
        self.enable_reader()

    def on_resume(self):
        self.enable_reader()
        return True

    def on_pause(self):
        self.disable_reader()
        return True

    def enable_reader(self):
        if not self.adapter or not self.callback:
            return
        if not self.adapter.isEnabled():
            self.set_status("NFC DESLIGADO - ligue nas configuracoes")
            return
        flags = 1 | 2 | 4 | 8 | 16 | 256  # A,B,F,V,barcode + sem som

        def _do():
            try:
                self.adapter.enableReaderMode(PythonActivity.mActivity,
                                              self.callback, flags, None)
                self.set_status("pronto - encoste o cartao")
            except Exception as e:
                self.set_status("erro reader: %s" % e)

        run_on_ui_thread(_do)

    def disable_reader(self):
        if not self.adapter:
            return

        def _do():
            try:
                self.adapter.disableReaderMode(PythonActivity.mActivity)
            except Exception:
                pass

        run_on_ui_thread(_do)

    def mostrar(self, texto):
        self.buffer += texto + "\n"
        if len(self.buffer) > 60000:
            self.buffer = self.buffer[-60000:]
        self.out.text = self.buffer
        Clock.schedule_once(lambda dt: setattr(self.scroll, "scroll_y", 0), 0)

    def set_status(self, txt):
        self.status.text = txt

    def limpar(self, *_):
        self.buffer = ""
        self.out.text = "limpo. encoste um cartao..."

    def copiar(self, *_):
        try:
            Clipboard.copy(self.buffer)
            self.set_status("copiado para a area de transferencia")
        except Exception as e:
            self.set_status("erro ao copiar: %s" % e)


if __name__ == "__main__":
    NFCApp().run()
