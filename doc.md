
## Les grandes fonctionnalités

Pour chaque grande fonctionnalité, il faut créer une nouvelle branche qui nomme la fonctionnalité à réaliser.

Pour créer la branche et faire la switch, il suffit d'utiliser:

```
  git branch nom
  git checkout nom
```

Chaque réalisation de fonctionnalité doit contenir les **testes** qui doivent vérifier tous les aspects de la fonctionnalité.

> Nous povons faire merge d'une fonctionnallité après une stricte verification! (Dans l'avenir nous alons ajouter CI/CD)

## Les petites fonctionnalités

Comme dans la situation de grandes fonc's., il est strictement recommandé de créer une nouvelle branche!
Il faut nommer les branches comme "f_nom" et pendant un pull request, il faut indiquer quelle fonctionnalité a été réalisé. En plus, dans la même façon il faut couvrir le code avec les tests.

## Les commits

Une commite ne peut pas contenir les modifications différentes!
Par exemple : "J'ai supprimé le code inutile et j'ai ajouté deux nouveaux features" - Ici je vais être obligé de couper tous les modifications en 3 commits différents.

Pour couper les modifications en commits différents
```
  git add ficher.rs -p
```
et après il faut choisir:

    y - stage this hunk
    n - do not stage this hunk
    q - quit; do not stage this hunk or any of the remaining ones
    a - stage this hunk and all later hunks in the file
    d - do not stage this hunk or any of the later hunks in the file
    s - split the current hunk into smaller hunks
    e - manually edit the current hunk
