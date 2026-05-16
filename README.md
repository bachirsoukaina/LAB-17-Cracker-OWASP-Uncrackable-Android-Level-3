
```
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   🔐  LAB 17 · OWASP UNCRACKABLE LEVEL 3                        ║
║       LE SECRET DU NATIF                                         ║
║                                                                  ║
║   ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓         ║
║                                                                  ║
║   Auteure  →  Soukaina Bachir · MLIAEdu                          ║
║   Niveau   →  ████████████████░░░░  Avancé                      ║
║   Statut   →  [ RÉSOLU ✓ ]                                       ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
```



---

## ◈ SURFACE D'ATTAQUE

```
┌─────────────────────────────────────────────────────────┐
│  COUCHES DE PROTECTION IDENTIFIÉES                       │
├─────────────────────────────────────────────────────────┤
│  [1]  Vérification CRC des bibliothèques natives         │
│  [2]  Détection de root (multi-couches : 3 méthodes)     │
│  [3]  Obfuscation native + anti-debug                    │
│  [4]  Vérification de mot de passe dans libfoo.so        │
└─────────────────────────────────────────────────────────┘
```

---

## ░░ PHASE 1 — RECONNAISSANCE JAVA · `Jadx-GUI`

### `MainActivity.verifyLibs()` — Gardien de l'intégrité

La méthode `verifyLibs()` calcule les **CRC** de chaque fichier critique :
- `libfoo.so` (multiples architectures)
- `classes.dex`

Si une incohérence est détectée → `tampered = 31337` → application fermée de force.


<img width="1907" height="771" alt="1" src="https://github.com/user-attachments/assets/a5b85a55-e992-4bb6-87fa-187a78015ed3" />


---

### `onCreate()` — La chaîne de vérifications

Trois boucliers successifs doivent tous passer :

```
  RootDetection.checkRoot1()  ──►
  RootDetection.checkRoot2()  ──►  FAILURE → "Rooting or tampering detected."
  RootDetection.checkRoot3()  ──►
  IntegrityCheck.isDebuggable()
  tampered != 0 ?
```

<img width="1920" height="975" alt="2" src="https://github.com/user-attachments/assets/90474ba2-3828-443c-8320-c984d46b3adc" />


### Le point névralgique : `verify(View view)`

```java
String input = ((EditText) findViewById(R.id.edit_text)).getText().toString();
if (this.check.check_code(input)) {
    alertDialogCreate.setText("Success!");
}
```

> ⚑ `check_code()` est une méthode **native** — la logique réelle vit dans `libfoo.so`.

---

## ░░ PHASE 2 — DÉCOMPILATION · `apktool`

```bash
apktool d UnCrackable-Level3.apk -o uncrackable3
```

<img width="847" height="256" alt="apktool" src="https://github.com/user-attachments/assets/17220e49-6a93-4498-a964-de3aea27b910" />


L'APK est ouvert. Les fichiers Smali sont désormais accessibles et modifiables.

---

## ░░ PHASE 3 — CHIRURGIE SMALI · Neutralisation des popups root

**Cible :** `uncrackable3/smali/sg/vantagepoint/uncrackable3/MainActivity.smali`

Rechercher le marqueur `showDialog` (≈ ligne 126).

### Avant

```smali
:cond_0
const-string v0, "Rooting or tampering detected."
invoke-direct {p0, v0}, Lsg/vantagepoint/uncrackable3/MainActivity;->showDialog(Ljava/lang/String;)V
```

### Après

```smali
:cond_0
return-void
```

### Neutralisation de `showDialog` elle-même

```smali
.method private showDialog(Ljava/lang/String;)V
    .locals 3
    return-void
.end method
```

### Recompilation + Installation

```bash
apktool b uncrackable3 -o Uncrackable-Level3-patched.apk
```

<img width="863" height="171" alt="apktool2" src="https://github.com/user-attachments/assets/d3c8f7a2-a670-412a-8a91-a6b4de1df5df" />


```bash
adb install -r UnCrackable-Level3-patched.apk
```

<img width="722" height="83" alt="adb" src="https://github.com/user-attachments/assets/8d8d77d3-2b81-4923-a90c-6d9953d923e7" />


---

## ░░ PHASE 4 — DISSECTION NATIVE · `Ghidra`

### Localisation du point d'entrée JNI

```
Java_sg_vantagepoint_uncrackable3_CodeCheck_check_code
        └──► FUN_001012c0   ← la vraie fonction
```

### L'obfuscation comme leurre

La fonction est volontairement parasitée par :

```
┌──────────────────────────────────────────────┐
│  LEURRES IDENTIFIÉS                           │
│                                              │
│  ► Calculs LCG  (0x41c64e6d + 0x3039)        │
│  ► malloc(0x10) répété en boucle             │
│  ► Construction de listes chaînées opaques   │
│                                              │
│  → Signature : O-LLVM / Tigress              │
└──────────────────────────────────────────────┘
```

### Les 24 octets qui comptent vraiment

En fin de `FUN_001012c0`, trois constantes apparaissent :

```
┌────────────────────────────────────────────────────────┐
│  OFFSET    DONNÉES (little-endian)                     │
├────────────────────────────────────────────────────────┤
│  +0x00  │  1d 08 11 13  0f 17 49 15                   │
│  +0x08  │  0d 00 03 19  5a 1d 13 15                   │
│  +0x10  │  08 0e 5a 00  17 08 13 14                   │
└────────────────────────────────────────────────────────┘
  Total : 24 octets encodés
```

---

## ░░ PHASE 5 — DÉCODAGE · `Python`

Le buffer est chiffré par **XOR** avec la clé répétitive : `"pizzapizzapizzapizzapizzapizza"`

```python
# decode_key.py  ·  Soukaina Bachir

encoded = bytes.fromhex("1d0811130f1749150d0003195a1d1315080e5a0017081314")
xor_key = b"pizzapizzapizzapizzapizzapizza"

secret = bytes(a ^ b for a, b in zip(encoded, xor_key))
print("▶ Clé secrète trouvée :", secret.decode())
```

**Résultat :**

<img width="576" height="48" alt="resultat" src="https://github.com/user-attachments/assets/956ea794-ca08-45f4-95af-1b6e1a98c797" />


```
▶ Clé secrète trouvée : making owasp great again
```

---

## ░░ PHASE 6 — VALIDATION FINALE

Saisie dans l'application :

```
┌─────────────────────────────────────────────┐
│  INPUT  →  making owasp great again         │
│  OUTPUT →  ✓  "This is the correct secret." │
└─────────────────────────────────────────────┘
```

<img width="168" height="308" alt="success" src="https://github.com/user-attachments/assets/505ff252-b877-4039-8737-b72a92fd2487" />


---

## ◈ SYNTHÈSE DES ÉTAPES

| `#` | Phase | Action | Outil |
|-----|-------|---------|-------|
| `01` | Reconnaissance | Analyse statique Java | **Jadx-GUI** |
| `02` | Décompilation | Extraction des fichiers | **apktool** |
| `03` | Patch Smali | Suppression des popups root | Éditeur texte |
| `04` | Recompilation | Build + signature APK | **apktool + apksigner** |
| `05` | Déploiement | Installation sur device | **adb** |
| `06` | Analyse native | Reverse de `libfoo.so` | **Ghidra** |
| `07` | Extraction | Localisation des constantes | **Ghidra Byte Viewer** |
| `08` | Décodage | XOR avec clé connue | **Python** |
| `09` | Validation | Test du mot de passe | Application Android |

---

## ◈ LEÇONS RETENUES

```
 ▸  01  La vérification native complique l'analyse — elle ne l'arrête pas.

 ▸  02  L'obfuscation (LCG, malloc, listes chaînées) est un LEURRE.
        Les données utiles se cachent en fin de fonction d'init.

 ▸  03  XOR + clé répétitive = classique des CTF.
        Reconnaître le pattern accélère le décodage.

 ▸  04  Patcher le Smali est plus rapide que de recompiler tout le projet.

 ▸  05  Toujours chercher ce qui reste quand on retire le bruit.
```

---

## ◈ FLAG

```
╔══════════════════════════════════════════════════╗
║                                                  ║
║   🏁  making owasp great again                   ║
║                                                  ║
╚══════════════════════════════════════════════════╝
```

---

<div align="center">

*Writeup rédigé par **Soukaina Bachir** · MLIAEdu*  
*"La sécurité par l'obscurité n'est pas de la sécurité."*

</div>
