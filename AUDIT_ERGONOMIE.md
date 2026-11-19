# Audit ergonomique du CRM — 19 novembre 2026

## Périmètre et méthode

Audit du code des interfaces : inventaire des templates, navigation par rôle, accueil, dossiers et fiches clients, cotations, agenda, revenus, commissions, relevés, ressources et administration. Vérification des parcours et des liens à partir des routes Flask. Aucun dossier réel, revenu ou document supprimé ou fusionné.

Les pages anciennes sans référence évidente sont conservées : l'absence de référence dans `app.py` ne prouve pas leur inutilité, certaines fonctionnalités étant enregistrées dans d'autres modules. Les doublons supprimés sont des blocs d'interface dont le remplacement est déjà présent.

## Corrections réalisées

| Constat | Correction |
| --- | --- |
| Menu sans hiérarchie, pages financières difficiles à retrouver | Quatre groupes : Au quotidien, Revenus, Équipe et suivi, Ressources et réglages. Liens directs vers les relevés et les taux pour l'admin. |
| Deux entrées de cotations côté admin | Une seule entrée « Cotations à traiter », avec le compteur des demandes. Le parcours commercial reste distinct. |
| Mauvais repérage de la page active sur les nouveaux écrans | État actif basé sur l'endpoint ; indication accessible `aria-current`. |
| Navigation longue avant le contenu sur mobile | Menu dépliable, état accessible annoncé, fermeture avec Échap et retour du focus. |
| Titres de page répétés dans le bandeau supérieur | Bandeau de contexte « Espace administration » / « Mon espace commercial ». Le relevé garde son titre dans ce bandeau car son contenu commence par la préparation du relevé. |
| Compteurs doublés sur l'accueil | Suppression du deuxième jeu de compteurs dans le bandeau. Conservation des indicateurs et du suivi des dossiers. |
| Accueil et agenda chargés de slogans | Message d'accueil personnalisé et libellés orientés vers les actions ; retrait des badges décoratifs et du bloc « Style / Agenda refondu ». |
| Descriptions et aides cachées par le thème global | Réaffichage avec couleur lisible et taille cohérente. |
| Certains formulaires sans marges, boutons d'export peu visibles | Correction ciblée des espacements et des boutons secondaires. |
| Trois anciennes copies de blocs dans la fiche client | Suppression de l'ancien en-tête, de la fiche entreprise dupliquée et de l'historique dupliqué, déjà masqués par CSS. |
| Formulaire de modification du client toujours ouvert | Formulaire dépliable ; le bouton « Modifier » ouvre directement la bonne section. |
| Suppression mise au même niveau que les actions courantes | Déplacement dans « Actions avancées », avec confirmation existante conservée. |
| Sélecteur de statut imbriqué dans le lien vers le dossier | Séparation du lien sur le nom et du formulaire de statut ; nom accessible du sélecteur. |
| Page CA alourdie par la saisie manuelle et les formulaires de contrat | Saisie manuelle et modifications de contrat repliables ; fournisseur et montants restent visibles. |
| Vocabulaire disparate | « Dossiers clients », « Agenda et relances », « Dossiers à relancer », « Historique du dossier ». |
| Relevés difficiles à lire | Préparation, résultat et exports regroupés ; totaux visibles ; données incomplètes séparées ; explications repliables ; tableau défilant et état vide explicite. |

## Fonctions conservées volontairement

- CA, commissions et relevés : ces pages répondent à trois besoins distincts (production, rémunération, justificatifs).
- Dossiers CSPE : workflow séparé des contrats d'énergie.
- Ressources partagées et bibliothèque documentaire : périmètres différents, pas un doublon confirmé.
- Demandes de modification et alertes de doublons : tâches administratives avec actions métier.
- Historique du dossier et listes de cotations/documents : traçabilité utile.
- Réglages des taux : visibles uniquement par l'administrateur ; contrôles serveur inchangés.

## Vérifications et limites

- 92 tests automatisés passent, dont compilation de tous les templates, navigation par rôle, lien actif et absence de formulaire imbriqué dans un lien de carte dossier.
- Vérification de syntaxe JavaScript et `git diff --check` sans erreur.
- Rendu HTML de démonstration de l'accueil et des relevés généré sans données réelles.
- La capture visuelle via navigateur local n'a pas pu être réalisée : le lancement d'Edge a échoué dans l'environnement de test. Les fichiers CSS prévoient les formats bureau et mobile ; leur rendu final reste à contrôler dans le navigateur après déploiement.
- Aucun audit de données de production, aucune suppression de doublons de clients et aucun déploiement Render effectués dans cette intervention.

## Parcours à confirmer après déploiement

1. Admin et commercial : menu mobile, ouverture d'un dossier, changement de statut, validation du CA.
2. Fiche client : ouverture du formulaire depuis « Modifier », enregistrement, cotation, documents et demande de modification.
3. Revenus : afficher les commissions, préparer un relevé, télécharger le PDF et Excel.
4. Admin : demandes en attente, alertes de doublons, gestion des utilisateurs et taux par commercial.
