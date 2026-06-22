# CallFlow

Application autonome de gestion d'appels, separee du CRM.

## Ce que fait deja cette version

- base de contacts
- composeur simple
- annuaire equipe avec agents, extensions et roles
- journal d'appels
- affectation des appels par agent
- comptes-rendus d'appels
- bibliotheque de fichiers
- documents rattaches a un contact
- integration MicroSIP pour lancer un vrai appel depuis Windows en un clic
- integration FreePBX/WebRTC prete a configurer pour de vrais appels navigateur
- page de tests poste pour verifier micro, casque et acces WSS avant mise en prod

## Appels reels avec MicroSIP

Si MicroSIP est installe sur le PC, CallFlow peut lancer l'appel directement :

- depuis la fiche contact
- depuis la liste des contacts
- depuis le composeur

Option de configuration locale :

- `MICROSIP_EXECUTABLE`

Exemple :

```text
MICROSIP_EXECUTABLE=C:\Users\julie\AppData\Local\MicroSIP\MicroSIP.exe
```

CallFlow expose aussi un annuaire compatible avec le champ `Directory of users` de MicroSIP :

```text
http://127.0.0.1:5055/api/microsip/directory
```

## Appels reels avec FreePBX

Pour la voix reelle, configure un fichier `logiciel_appels/.env` a partir de
`logiciel_appels/.env.example` puis renseigne :

- `FREEPBX_WSS_URL`
- `FREEPBX_SIP_DOMAIN`
- `FREEPBX_DISPLAY_NAME`
- `FREEPBX_DEFAULT_EXTENSION`
- `FREEPBX_DEFAULT_AUTH_USER`
- `FREEPBX_OUTBOUND_PREFIX`

Ensuite chaque agent ouvre l'onglet `FreePBX` dans l'application pour charger :

- son extension
- son login SIP si different de l'extension
- son mot de passe SIP
- son nom affiche

Le mot de passe SIP reste stocke localement dans le navigateur de l'agent.

Avant les premiers appels reels, ouvre aussi l'onglet `Tests` pour verifier :

- acces microphone navigateur
- lecture casque / haut-parleurs
- profil agent charge sur le PC
- acces WSS vers le PBX

## Prerequis FreePBX / Asterisk

- HTTPS/WSS actif sur le PBX, typiquement `wss://ton-pbx:8089/ws`
- transport PJSIP WebSocket securise
- extension configuree avec auth + endpoint + AOR compatibles WebRTC
- certificat TLS fiable pour eviter les blocages navigateur

## Demarrage

Depuis `C:\mini_crm` :

```powershell
python .\logiciel_appels\app.py
```

Puis ouvrir :

```text
http://127.0.0.1:5055
```

## Donnees

- base SQLite : `logiciel_appels\data\logiciel_appels.sqlite3`
- fichiers : `logiciel_appels\uploads\`
