# Migration des champs certificat vers CN séparés et DN complets

Guide d'implémentation pour un agent GPT-5.2-luna medium travaillant dans Plum Island.

Ce document décrit l'implémentation et la migration. Le code est présent dans la
branche courante ; la migration de production n'a pas été exécutée. Ne pas lancer
la migration de production sans sauvegardes et validation sur une copie.

## 1. Objectif et contrat final

Conserver le JSON brut et la sortie publique de `parse_json()` sans modification.
Enrichir uniquement la copie préparée pour l'indexation Kvrocks. Cette copie
conserve les valeurs actuelles de commonName dans deux nouveaux champs et donne
aux noms historiques le sens de DN complet :

| Champ après migration | Contenu |
| --- | --- |
| `x509_issuer_cn` | Dans la copie Kvrocks : valeur de `issuer.commonName`, sans préfixe `CN=` |
| `x509_subject_cn` | Dans la copie Kvrocks : valeur de `subject.commonName`, sans préfixe `CN=` |
| `x509_issuer` | Dans la copie Kvrocks : tous les attributs disponibles dans le dictionnaire Nmap `issuer`, sérialisés selon le contrat ci-dessous |
| `x509_subject` | Dans la copie Kvrocks : tous les attributs disponibles dans le dictionnaire Nmap `subject`, sérialisés selon le même contrat |

Exemple d'entrée du script `ssl-cert` :

```json
{
  "issuer": {
    "commonName": "Dahua Device NVR CA",
    "organizationName": "Zhejiang Dahua Technology Co.,Ltd.",
    "countryName": "CN"
  },
  "subject": {"commonName": "192.168.2.70", "countryName": "CN"}
}
```

Valeurs en sortie de `parse_json()` : les champs historiques restent des commonName
et aucun nouveau champ n'est ajouté :

```json
{
  "x509_issuer": ["Dahua Device NVR CA"],
  "x509_subject": ["192.168.2.70"]
}
```

Après `prepare_kvrocks_document(raw_doc, parsed_doc)`, la copie envoyée à
Kvrocks contient en plus :

```json
{
  "x509_issuer_cn": ["Dahua Device NVR CA"],
  "x509_issuer": ["CN=Dahua Device NVR CA, O=Zhejiang Dahua Technology Co.\\,Ltd., C=CN"],
  "x509_subject_cn": ["192.168.2.70"],
  "x509_subject": ["CN=192.168.2.70, C=CN"]
}
```

Ne pas modifier les UID, le format des résultats agents, les SAN, les empreintes,
les dates d'observation ou l'extraction des domaines à l'occasion de cette migration.
Ne pas ajouter les règles C2 Nuclei dans cette livraison : elles pourront utiliser
le nouveau contrat après sa validation.

## 2. Constats vérifiés dans le dépôt

Lire `AGENT.md` avant toute implémentation et vérifier l'état Git. Préserver les
modifications préexistantes de l'utilisateur.

- `webapp/app/utils/result_parser.py`, fonction `get_ssl_info()` : aujourd'hui
  `x509_issuer` et `x509_subject` ne reçoivent que `commonName`. Cette sortie
  publique doit rester inchangée ; l'enrichissement appartient à la frontière
  Kvrocks, dans `prepare_kvrocks_document()`.
- `nse/ssl-cert.nse`, fonctions `name_to_table()` et `output_tab()` : la sortie
  structurée contient les dictionnaires issuer/subject et le PEM. L'affichage
  textuel `output` n'est pas la source à utiliser pour fabriquer les DN.
- `parse_json()` transforme les valeurs en listes via `fuse_dicts()`.
- `KVrocksIndexer.add_documents_batch()` met les valeurs en minuscules pour
  l'indexation ; le parseur conserve la casse originale.
- `tools/tag_mgmt.py`, `iter_kvrocks_document_batches()` et
  `_reindex_tags_unlocked()` : le reindex des tags relit Kvrocks, pas les certificats
  bruts. Il ne peut pas reconstruire les attributs actuellement absents.
- `tools/index_kvrocks.py`, `parse_meili_document()` : le rebuild depuis
  Meilisearch appelle réellement le parseur sur les documents sources.
- `rebuild_kvrocks()` supprime les index connus, mais conserve les hashes
  `doc:{uid}` pour fusionner les intervalles first_seen/last_seen.
- Les règles actives utilisées à l'exécution proviennent de SQLite. Modifier un
  YAML ne modifie pas automatiquement la règle chargée en base.
- Les rapports stockent eux aussi une requête structurée dans `reports.query`.

Au moment de l'analyse : 861 YAML, dont 20 fichiers contenant les anciens champs.
14 fichiers utilisent issuer et 11 subject, avec des recouvrements. Recalculer ces
chiffres au démarrage ; ne pas coder une liste de 20 fichiers en dur.

```bash
rg --files webapp/tags -g '*.yaml' | wc -l
rg -l 'x509_(issuer|subject)' webapp/tags
rg -n 'x509_(issuer|subject)|REINDEX_FIELDS|INDEX_FIELDS' webapp tools test documentation readme.md
```

## 3. Contrat de normalisation à implémenter

Créer une fonction pure commune, par exemple `serialize_certificate_name()` dans
`result_parser.py` ou un petit module dédié si cela facilite les tests.

### 3.1 Source et limites

Utiliser les dictionnaires structurés Nmap. Pour cette version, « complet » veut
dire tous les attributs disponibles dans ces dictionnaires. Ils ne permettent pas
nécessairement de retrouver l'ordre ASN.1, les groupes RDN multivalués ou les
occurrences perdues avant leur construction. Ne pas présenter la sortie comme une
reproduction exacte du DN original ni comme une identité cryptographique.

Ne pas introduire un deuxième parseur PEM dans cette version. Si un document ne
contient que le PEM, signaler cette limitation dans l'audit de couverture ; ne pas
fabriquer de DN à partir d'un CN indexé ou de l'affichage HTML.

### 3.2 Ordre et noms d'attributs

Utiliser cet ordre fixe pour les attributs connus :

| Clé Nmap | Nom sérialisé |
| --- | --- |
| `commonName` | `CN` |
| `organizationalUnitName` | `OU` |
| `organizationName` | `O` |
| `localityName` | `L` |
| `stateOrProvinceName` | `ST` |
| `countryName` | `C` |

Ajouter ensuite les attributs restants dans l'ordre lexical de leur nom, en
conservant leur nom/OID : par exemple `postalCode=3540`. Ne pas perdre les attributs
inconnus et ne pas ajouter une liste fermée qui empêcherait leur recherche.
Séparer les paires par `, ` et le nom de sa valeur par `=`.

### 3.3 Valeurs et échappements

- Conserver casse et Unicode d'origine ; ne pas réduire les espaces internes ou
  remplacer les espaces insécables. L'indexeur applique déjà sa minuscule habituelle.
- Échapper les caractères `\\`, `,`, `+`, `"`, `<`, `>`, `;`, `=` dans les valeurs
  par un backslash, ainsi que le `#` initial et les espaces initiaux/finaux.
- Représenter les caractères de contrôle par des échappements hexadécimaux
  déterministes, sans injecter de saut de ligne dans le DN.
- Ne pas décoder aveuglément les séquences textuelles `\\xNN` venant des agents :
  elles peuvent être des caractères littéraux. Documenter le comportement choisi.
- Ignorer les attributs absents, `null`, ou de valeur chaîne vide. Préserver une
  valeur composée d'espaces en l'échappant ; ne pas appeler `strip()` sur les CN.
- Si une liste de valeurs est disponible, émettre plusieurs paires du même nom,
  triées de façon déterministe. Ne pas prétendre reconstruire leurs groupes RDN.
- Pour les formes inattendues (dictionnaire imbriqué, type non pris en charge),
  éviter un crash global et rendre l'anomalie visible aux diagnostics/tests.
- Un certificat sans commonName doit pouvoir produire un DN contenant `O`, `OU`,
  etc. Un champ CN absent doit rester absent/vide selon le contrat du parseur.

Les champs `_cn` doivent conserver strictement le comportement antérieur pour les
entrées normales : aucune décoration, aucun échappement DN ajouté à la valeur CN.

### 3.4 Compatibilité des requêtes

Le moteur utilise `shlex` pour lire les requêtes ; YAML ajoute une couche
d'échappement. Tester le chemin YAML → parseur de requête → matcher → recherche
Kvrocks avec une valeur contenant une virgule échappée et un backslash. Ne pas
valider uniquement la chaîne construite par la fonction de sérialisation.

Les chaînes Nuclei ne sont pas automatiquement interchangeables avec cette
représentation : ordre et échappements peuvent différer. Les adaptations futures
devront utiliser les champs CN ou les attributs réellement sérialisés et préserver
les conditions AND/OR originales (notamment les deux critères de Sliver en AND).

## 4. Étapes de modification du code

### A. Établir le comportement de référence

1. Lire les fichiers ci-dessous et chercher toutes les listes de champs.
2. Capturer les règles YAML/SQLite concernées et les résultats attendus sur des
   fixtures brutes avant changement.
3. Identifier les défauts préexistants séparément. Par exemple, certains tests
   fournissent `CN: ...` alors que l'ancien parseur ne produit pas ce préfixe.
   Ne pas considérer ces tests artificiels comme preuve de détection réelle.

### B. Parseur et consommateurs

| Fichier / zone | Modification attendue |
| --- | --- |
| `webapp/app/utils/result_parser.py` | Sérialisation DN, nouveaux champs CN, gestion d'absence et valeurs inattendues |
| `webapp/app/utils/kvrocks.py` | Deux nouveaux champs dans les index inverses et les ensembles par UID ; vérifier remplacement et suppression des anciennes valeurs |
| `webapp/app/views.py` | Autoriser les nouveaux champs dans `KVSearchView.parse_query_group()` |
| `tools/tag_mgmt.py` | Ajouter les CN à `REINDEX_FIELDS` pour le reindex des tags depuis Kvrocks |
| `tools/index_kvrocks.py` | Ajouter les CN à `INDEX_FIELDS` et vérifier le nettoyage des quatre familles de clés lors du rebuild |
| `tools/dump_object.py` | Exposer les nouveaux champs |
| `webapp/app/templates/search_kvrocks.html` | Aide : distinguer CN et DN complet |
| `documentation/search.md`, `documentation/kvrocks_objects.md`, `documentation/tagging.md` | Contrat, syntaxe, exemples et migration |
| `documentation/tools.md`, `documentation/recovery-tools.md`, `documentation/migration.md` | Procédure complète et limites opérationnelles |
| `readme.md`, `release_note.md` | Annoncer le changement de sens et le rebuild requis |

Vérifier aussi les outils de réimport et le scheduler par recherche de références.
Ne pas refactorer leur orchestration si leur appel au parseur partagé suffit.
Le rendu du certificat dans `ip_detail.html` utilise déjà les données brutes :
vérifier son fonctionnement, sans le convertir inutilement au format DN indexé.

### C. Migration des YAML

Parcourir tous les YAML, lire leur `query`, et remplacer seulement les clés des
termes de recherche :

```text
x509_issuer       → x509_issuer_cn
x509_subject      → x509_subject_cn
x509_issuer.bg    → x509_issuer_cn.bg
x509_subject.like → x509_subject_cn.like
```

Préserver tous les modificateurs supportés, les valeurs, les guillemets, les AND/OR,
les noms de fichiers et les tags. Ne pas remplacer une occurrence dans une valeur
comme `banner.lk:"x509_issuer:example"`. Ne pas produire `_cn_cn`.

Implémenter une transformation consciente des tokens et des guillemets ; éviter un
remplacement global de texte. Garder un diff minimal et incrémenter la version UTC
de chaque YAML modifié, strictement au-delà de sa version précédente.

Compiler l'ensemble des règles avant/après. Signaler les erreurs déjà présentes
séparément ; ne pas élargir silencieusement cette livraison à leur réparation.
Préserver la sémantique historique des critères CN, même si une amélioration de
détection pourrait ensuite être utile sur les DN complets.

### D. Migration SQLite

Utiliser [tools/migrate_full_cert.py](tools/migrate_full_cert.py) avec l'interface :

```bash
.venv/bin/python tools/migrate_full_cert.py --db webapp/app.db --dry-run

.venv/bin/python tools/migrate_full_cert.py --db webapp/app.db --apply
```

Exigences :

- Utiliser SQLite directement sans démarrer Flask ni le scheduler.
- Traiter `tagrules.query` et `reports.query`, actifs et inactifs, y compris les
  règles personnalisées absentes des YAML.
- Réutiliser la même transformation de termes que pour les YAML.
- Préserver ID, nom, tags, activation, périodicité des rapports et contenu local.
  Préserver les timestamps métier pour cette conversion mécanique ; journaliser
  la migration séparément. Ne pas écraser une règle locale avec son YAML source.
- Exécuter les modifications et le marqueur de migration dans une transaction.
- Enregistrer un marqueur durable, par exemple une entrée unique
  `full_cert_fields_v1` dans une table dédiée de suivi des migrations. Définir sa
  création et sa vérification dans les tests.
- Si le marqueur existe, ne plus renommer aucune requête : les nouvelles règles
  DN pourront légitimement utiliser `x509_issuer` après migration. La simple absence
  de `_cn_cn` ne suffit donc pas à garantir l'idempotence.
- En dry-run, annoncer explicitement les tables/ID/requêtes concernés et les
  anomalies de syntaxe, sans créer de table ni modifier la base.
- Refuser une migration partielle en présence d'une requête ambiguë/non migrable ;
  produire un diagnostic et laisser la transaction intacte.
- Tester l'absence de tables sur une base inattendue ; ne pas présenter comme
  réussie une migration qui n'a pas trouvé la base attendue.

Ne pas utiliser `import --all` comme remplacement de cette migration : la politique
de versions peut ignorer les personnalisations récentes ou écraser des versions
locales plus anciennes. En production existante, la conversion SQLite suffit pour
les règles déjà présentes. Les YAML mis à jour servent aussi aux installations neuves.

Les anciennes URL de recherche et requêtes externes devront être adaptées par leurs
utilisateurs. Ne pas ajouter d'alias qui rendrait `x509_issuer` ambigu entre CN et DN.

## 5. Tests requis avant livraison

Les tests doivent prouver le comportement à partir de résultats Nmap bruts et des
vraies requêtes YAML compilées. Ne pas se limiter à dupliquer la règle dans une
constante de test ou à appeler `py_compile`.

| Domaine | Cas à couvrir |
| --- | --- |
| Extraction | Certificat complet ; CN seul ; sans CN mais avec O/OU ; issuer/subject absents ou vides ; absence de `ssl-cert` |
| Normalisation | Ordre des clés différent donnant le même DN ; Unicode et espace insécable ; virgule, backslash, `+`, `=`, guillemet, espace de bord, contrôle ; attribut inconnu/OID ; valeurs répétées disponibles |
| Rétrocompatibilité | Nouvelles valeurs `_cn` égales aux anciennes valeurs ; SAN, empreintes, fqdn/host/domain/tld et UID inchangés |
| Query/matching | Exact, préfixe, sous-chaîne, négation existante, casse ; échappement YAML et shlex ; AND/OR conservés |
| Indexation | Index aller `field:value` et retour `fields:uid` pour les quatre champs ; ancien CN retiré de `x509_issuer` ; réindexer deux fois n'ajoute pas de valeurs résiduelles |
| Dates | `first_seen` minimum et `last_seen` maximum préservés lors du remplacement/rebuild |
| Règles YAML | Tous les fichiers chargés ; seuls les termes visés changent ; versions augmentées ; valeur contenant un nom de champ inchangée |
| SQLite | Règles et rapports personnalisés/inactifs ; rollback sur erreur ; dry-run sans écriture ; marqueur transactionnel ; seconde exécution sans effet |
| Après migration | Une nouvelle règle DN créée après le premier passage n'est pas convertie lors d'une relance de migration |
| Bouton reindex | Lecture des nouveaux CN via `REINDEX_FIELDS` ; tags identiques à ceux produits pendant le parsing |
| Chaîne complète | Ancien index + anciennes règles → migration + rebuild → recherches CN/DN et tags attendus |

Étendre notamment `test/test_result_parser_tls_certificate_names.py`. Ajouter des
tests de sérialisation et de migration dédiés, avec SQLite temporaire et backend
Kvrocks simulé pour les tests unitaires. Sur une instance jetable, vérifier également
les recherches Kvrocks réelles et le parcours de rebuild depuis Meilisearch.

Inclure une fixture issuer sans CN avec `organizationName=Mythic` : le DN doit être
recherchable par `x509_issuer.lk:"O=Mythic"` et aucun CN ne doit être inventé.
Inclure un sujet avec `postalCode=3540` pour vérifier les attributs supplémentaires.

Pour les documents regroupant plusieurs certificats, conserver le comportement
d'agrégation actuel. Ne pas prétendre que deux critères sur des champs agrégés
appartiennent forcément au même certificat ; une association par certificat est
une évolution distincte.

Contrôles imposés par `AGENT.md` :

```bash
.venv/bin/python test/run_all.py
git diff --check
```

Exécuter aussi Black, `py_compile` et Pylint sur la liste explicite des fichiers
Python modifiés, conformément à `AGENT.md`. Si l'environnement ou une dépendance
manque, le dire et ne pas annoncer que la compilation seule valide les tests.

## 6. Migration de production

### 6.1 Préparer et mesurer

1. Valider toute la procédure sur une copie représentative.
2. Relever la révision Git, les endpoints et les noms d'index effectivement utilisés
   par les outils. Les outils de récupération lisent `webapp/config.py` alors que
   le rebuild utilise `tools/config.yaml` : vérifier qu'ils ciblent les mêmes données.
3. Sauvegarder SQLite, Kvrocks, Meilisearch, configurations et JSON bruts avec une
   méthode cohérente adaptée aux services. Conserver la révision logicielle précédente.
4. Conserver un inventaire des UID et dates, les comptes, des exemples de tags et
   les requêtes de référence. Ne pas se contenter de comparer les nombres d'UID.
5. Estimer la durée du rebuild et l'espace disponible avec la copie de validation.

### 6.2 Geler les écritures et vérifier la source

Arrêter l'application et ses workers/scheduler, les outils d'indexation/reindexation
et les rapports planifiés. Suspendre les agents ou leur réception selon le mode
d'exploitation. Attendre la fin des tâches Meilisearch déjà soumises : arrêter le
client ne les annule pas. Garder Meilisearch et Kvrocks accessibles aux outils.

La source doit contenir tous les UID à préserver, avec `body.ports[].scripts[]` et
les dictionnaires des certificats. Une égalité de compte ne prouve pas cette couverture.

Commande existante, en lecture seule sur les backends :

```bash
.venv/bin/python tools/reintegrate_missing_meili.py \
  --report /tmp/full-cert-missing-meili.csv
```

Si des UID sont récupérables, suivre `documentation/recovery-tools.md` pour les
réintégrer depuis les JSON bruts, puis refaire le contrôle. Garder le rapport et
attendre la réussite des tâches Meilisearch. Si des UID restent irrécupérables,
ne pas déclencher le rebuild destructif sans décision explicite sur leur conservation.

Un document Meilisearch présent mais sans dictionnaire certificat doit également
être comptabilisé ; le contrôle des UID manquants ne détecte pas ce cas. Ne pas
annoncer un DN historique complet si les attributs sources sont absents.

### 6.3 Déployer et convertir les requêtes

1. Déployer la version validée, sans redémarrer les processus qui indexent.
2. Exécuter le dry-run de `tools/migrate_full_cert.py`.
3. Vérifier les conversions puis exécuter `--apply` sur la bonne base SQLite.
4. Vérifier le marqueur et compiler toutes les requêtes actives migrées. Le rebuild
   avec `--retag` charge les règles SQLite, pas directement les YAML.
5. Ne pas démarrer de nouvelles règles DN pendant que l'index contient encore les
   anciennes valeurs CN sous les noms `x509_issuer` et `x509_subject`.

### 6.4 Reconstruire les champs et les tags

Commande existante, à exécuter seulement avec le nouveau code et les règles migrées :

```bash
.venv/bin/python tools/index_kvrocks.py --rebuild-from-meili --retag
```

Alternative depuis un dump complet au format attendu :

```bash
.venv/bin/python tools/index_kvrocks.py \
  --rebuild --input-dir tools/meili_dump --retag
```

`--input-dir` attend les documents exportés pour cet outil ; ne pas lui passer
directement le répertoire des JSON de jobs agents sans conversion validée.

Cette opération supprime puis reconstruit les index connus. Le service de recherche
doit rester en maintenance jusqu'à validation. Les hashes `doc:{uid}` conservent
les dates pour les UID qui sont effectivement reconstruits. Meilisearch n'a pas
besoin d'être réindexé si ses documents bruts sont complets.

Ne pas remplacer cette commande par :

```bash
.venv/bin/python tools/tag_mgmt.py reindex --allrules
```

Cette dernière commande, comme le bouton GUI, ne recalcule que les tags à partir
des champs Kvrocks déjà disponibles ; elle sera utilisable après le rebuild.

### 6.5 Interruption et erreurs

Le rebuild n'est pas une bascule atomique et ne possède pas le mécanisme de reprise
par curseur du reindex des tags. Après interruption, considérer l'index comme partiel.
Ne pas rouvrir la recherche ou les rapports. Conserver les logs, corriger la cause
et reprendre par un rebuild complet depuis la source inchangée, ou restaurer les
sauvegardes. Garder les hashes de dates et les sauvegardes pendant cette opération.

Vérifier le compteur d'erreurs final, les UID et les données, même si le processus
retourne un code de sortie nul : la seule fin du programme n'est pas un critère
de migration réussie.

### 6.6 Validation et reprise

- Comparer les ensembles d'UID à l'inventaire initial et expliquer chaque écart.
- Comparer les dates d'observation pour les UID conservés.
- Vérifier que les CN historiques se trouvent sous `_cn` et que les champs complets
  contiennent des paires attribut=valeur ; aucune ancienne valeur CN résiduelle.
- Vérifier les recherches exactes, `.bg`, `.lk`, les tags et des rapports représentatifs.
- Vérifier un certificat sans CN et des DN contenant des caractères échappés.
- Vérifier un petit reindex de tags après rebuild et l'indexation d'un nouveau résultat.
- Redémarrer les processus avec le nouveau code et les règles rechargées, puis
  surveiller les erreurs d'indexation et les résultats des rapports.

Les règles personnalisées doivent conserver leur contenu et leur activation, avec
uniquement la conversion prévue des champs de requête.

## 7. Retour arrière

Si la validation échoue et qu'une reprise n'est pas possible dans la fenêtre :

1. Maintenir tous les producteurs/consommateurs concernés à l'arrêt.
2. Restaurer ensemble l'ancienne révision, la sauvegarde SQLite et la sauvegarde
   Kvrocks cohérentes. Restaurer les configurations si elles ont changé.
3. Meilisearch n'est pas modifié par le rebuild ; une restauration n'est nécessaire
   que si d'autres opérations ont altéré sa source et exigent un retour cohérent.
4. Vérifier les anciennes requêtes et les dates avant redémarrage.

Ne pas revenir au seul ancien code contre un index DN nouveau. Ne pas convertir
aveuglément tous les champs vers les anciens noms : des règles DN créées après la
migration ne pourraient pas être interprétées correctement par l'ancien parseur.
Un rollback après reprise des acquisitions demande aussi un traitement explicite
des nouvelles observations ; privilégier la validation avant réouverture.

## 8. Critères de livraison à l'agent suivant

La livraison doit contenir le code, les YAML migrés, l'outil SQLite transactionnel,
les tests et la documentation opérationnelle. Rapporter les résultats réels des
tests, le nombre de fichiers concernés, les limites des données historiques et
les commandes effectivement exécutées. Distinguer clairement « code prêt » et
« production migrée ».

La migration est terminée seulement lorsque les règles chargées, les champs
indexés, la recherche et les rapports partagent tous le nouveau contrat. Une
simple compilation Python ou un push Git ne démontre pas ce résultat.
