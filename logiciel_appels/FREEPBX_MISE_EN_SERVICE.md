# Mise En Service FreePBX

Ce document reprend l'ordre de mise en service pour que les appels partent
depuis les PC avec casque micro.

## Cote FreePBX / Asterisk

1. Donner un nom DNS stable au PBX, par exemple `pbx.tondomaine.fr`.
2. Installer un certificat TLS valide sur le PBX.
3. Verifier que le HTTPS Asterisk ecoute sur `8089`.
4. Verifier que l'URI WebSocket `/ws` est disponible.
5. Verifier le transport `PJSIP WSS`.
6. Creer une extension `PJSIP` par agent.
7. Configurer le trunk SIP operateur.
8. Configurer la route sortante.

## Commandes de controle Asterisk

```text
http show status
pjsip show endpoints
pjsip show registrations
core show channels
```

Ce qu'il faut retrouver :

- HTTPS actif sur `8089`
- URI `/ws` visible
- extensions `PJSIP` en etat enregistrable
- trunk SIP fonctionnel

## Cote CallFlow

1. Renseigner `logiciel_appels/.env`.
2. Creer les agents dans l'onglet `Equipe`.
3. Ouvrir `FreePBX` sur chaque PC agent.
4. Choisir l'agent et saisir le mot de passe SIP localement.
5. Ouvrir l'onglet `Tests`.
6. Tester micro, casque et WSS.
7. Ouvrir le `Composeur`.
8. Tester d'abord un appel interne, puis un appel externe.

## Exemple de `.env`

```env
FREEPBX_WSS_URL=wss://pbx.example.com:8089/ws
FREEPBX_SIP_DOMAIN=pbx.example.com
FREEPBX_DISPLAY_NAME=Equipe CallFlow
FREEPBX_DEFAULT_EXTENSION=
FREEPBX_DEFAULT_AUTH_USER=
FREEPBX_OUTBOUND_PREFIX=
SIPJS_SDK_IMPORT_URL=https://cdn.jsdelivr.net/npm/sip.js@0.21.2/+esm
```

## Ce que CallFlow ne peut pas faire tout seul

CallFlow prepare le poste agent et le composeur navigateur, mais ne peut pas :

- installer FreePBX a ta place
- creer le trunk SIP chez l'operateur
- ouvrir les ports sur ton firewall
- fournir le certificat TLS du PBX

Ces points doivent etre faits sur le serveur telephonie ou chez l'operateur SIP.
