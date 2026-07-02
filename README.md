# Multithreaded TCP Port Scanner (C++)

Scanner de ports TCP simple en **C++17**, utilisant `std::thread`, `std::atomic` et des sockets POSIX non bloquants avec `select()` pour un timeout par connexion.
 
 
L'idée c'est de montrer la maîtrise du réseau bas niveau, du multithreading, et des bonnes pratiques C++ modernes.

## Fonctionnalités

- Scan TCP connect() multi-threadé (pool de threads configurable)
- Résolution DNS (hostname ou IP)
- Timeout par socket via `select()` (non bloquant)
- Détection basique de services connus (ssh, http, https, mysql, ...)
- Sortie triée et résumé final avec durée

## Utilisation

make dans le dossier /build pour compiler l'application ./port_scanner

```bash
./port_scanner <host> [start_port=1] [end_port=1024] [threads=100]
```

Exemples :

```bash
./port_scanner 127.0.0.1
./port_scanner scanme.nmap.org 1 1024 200 (plage de ports)
```