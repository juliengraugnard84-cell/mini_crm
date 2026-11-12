# Mini CRM local

Ouvrir le raccourci **Mini CRM local** sur le bureau. Il lance le serveur en arrière-plan et ouvre http://127.0.0.1:5055.

Les identifiants de connexion sont dans `instance/local_crm/ACCES_LOCAL.txt`. Le compte administrateur permet de saisir les dossiers ; choisir **Commercial local** en attendant de créer les comptes habituels dans l'administration.

La version locale conserve les nouvelles saisies dans une base PostgreSQL distincte, sur ce PC. Les anciennes copies SQLite restent intactes. Les dossiers précédemment saisis sur Render ne sont disponibles localement qu'après une synchronisation réussie.

Les pièces jointes des dossiers et les documents CSPE sont enregistrés dans `instance/local_crm/documents`. Les notifications email sont désactivées.

## Sauvegarde

Dans le bandeau « Version locale », cliquer sur **Télécharger une sauvegarde**. L'archive ZIP contient `database.dump` et les pièces jointes. Des sauvegardes sont aussi créées au démarrage dans `instance/local_crm/backups`. Copier régulièrement une archive sur une clé USB ou un autre support.

Le fichier `sauvegarder_local.bat` crée également une sauvegarde. Les mots de passe locaux restent dans `instance/local_crm` : ne pas partager ce dossier publiquement.

## Après le rétablissement de Render

Conserver les sauvegardes locales. Ne pas remplacer la base Render avec l'archive locale.

### Synchroniser dossiers, documents et chiffre d'affaires

1. Réactiver le service et la base Render, puis déployer sur Render cette version du CRM (elle contient la passerelle sécurisée des pièces jointes).
2. Ouvrir le bouton **Synchroniser avec Render** dans le bandeau de la version locale.
3. Renseigner l'adresse HTTPS du CRM Render. Le fichier `instance/render_database_url.txt` contient l'adresse externe PostgreSQL : il reste privé et n'est jamais affiché sur la page.
4. Cliquer sur **Tester la connexion**, puis associer **Commercial local** au bon compte commercial de Render.
5. Cliquer sur **Synchroniser dossiers, CA et documents**. Les transferts sont bidirectionnels et lancés par l'administrateur, pas automatiquement en arrière-plan.

Chaque dossier, cotation, point de livraison et ligne de CA possède un identifiant stable pour éviter de les recréer à chaque transfert. Les identifiants numériques et commerciaux sont remappés entre les bases. Les comptes ne partagent pas leurs mots de passe. Les dossiers ayant les mêmes raison sociale et SIRET sont rapprochés seulement si la correspondance est unique ; leurs différences demandent une décision. Les rapprochements ambigus interrompent le transfert.

Si un même enregistrement a été modifié différemment des deux côtés, choisir la version à conserver sur la page, puis relancer. Aucune suppression n'est propagée automatiquement.

Les références à des commerciaux supprimés sur Render sont conservées dans des comptes locaux « Ancien compte Render n°… », sans changer leur attribution historique. Les anciennes cotations ou suivis dont la fiche source a disparu sont copiés intégralement dans **Historique à rapprocher**, accessible depuis le panneau de synchronisation. Ils ne sont ni supprimés de Render, ni attribués à une fiche inventée. Le compteur du rapport indique ces éléments séparément des dossiers actifs.

Les pièces jointes des dossiers CRM et CSPE sont transférées entre le disque local et le stockage S3 du CRM hébergé, par HTTPS signé. Leur contenu est comparé pour éviter les doublons. Les ressources partagées, documents globaux et pièces jointes du chat ne sont pas des pièces jointes de dossier et ne font pas partie de cette synchronisation.

Une sauvegarde de chaque base précède les transferts. Si la phase documentaire échoue après les données, le panneau affiche **documents à reprendre** : relancer complète les fichiers sans dupliquer les dossiers ni le CA. Les copies locales et distantes sont conservées.

## Démarrage manuel et redémarrage du PC

Le raccourci fonctionne aussi après redémarrage de l'ordinateur. Autre possibilité : ouvrir `run_local.bat` et garder sa fenêtre ouverte. L'application et sa base n'écoutent que sur `127.0.0.1` et ne sont pas accessibles aux autres ordinateurs.
