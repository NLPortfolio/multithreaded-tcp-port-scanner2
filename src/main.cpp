//Test de scan de ports TCP en C++ avec multithreading
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

static std::mutex g_cout_mutex;
static std::atomic<int> g_next_port{0};
static std::atomic<int> g_open_count{0};
static int g_end_port = 0;
static std::string g_ip;

// Fonction de résolution du nom d'hôte en adresse IP. Retourne true si la résolution a réussi, false sinon.
static bool resolve_host(const std::string& host, std::string& out_ip) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) {
        return false;
    }

    char buf[INET_ADDRSTRLEN]{};
    auto* addr = reinterpret_cast<sockaddr_in*>(res->ai_addr);
    inet_ntop(AF_INET, &addr->sin_addr, buf, sizeof(buf));
    out_ip = buf;
    freeaddrinfo(res);
    return true;
}

// Tentative de connexion à un port TCP sur l'adresse IP spécifiée. Utilise un timeout pour éviter les blocages. Retourne true si le port est ouvert, false sinon.
// On utilise un booléen "open" true si le port est ouvert, false sinon
static bool scan_port(const std::string& ip, int port, int timeout_ms = 800) {
    int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    //Non-blocking socket très utile pour éviter les blocages lors de la connexion à un port fermé ou filtré. On utilise fcntl pour définir le socket en mode non-bloquant
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    bool open = false;
    int rc = ::connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (rc == 0) {
        open = true;
    } else if (errno == EINPROGRESS) {
        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(sock, &wset);
        timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
        if (::select(sock + 1, nullptr, &wset, nullptr, &tv) > 0) {
            int err = 0;
            socklen_t len = sizeof(err);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
            open = (err == 0);
        }
    }

    ::close(sock);
    return open;
}

// On associe le numéro de port au nom du service associé à un port TCP connu. Retourne "unknown" si le port n'est pas dans la liste des ports connus.
static const char* guess_service(int port) {
    switch (port) {
        case 21:   return "ftp";
        case 22:   return "ssh";
        case 23:   return "telnet";
        case 25:   return "smtp";
        case 53:   return "dns";
        case 80:   return "http";
        case 110:  return "pop3";
        case 143:  return "imap";
        case 443:  return "https";
        case 3306: return "mysql";
        case 3389: return "rdp";
        case 5432: return "postgres";
        case 6379: return "redis";
        case 8080: return "http-alt";
        default:   return "unknown";
    }
}

//La fonction worker est exécutée par chaque thread. Elle récupère le prochain port à scanner de manière atomique, puis tente de se connecter à ce port. Si le port est ouvert, elle incrémente le compteur de ports ouverts et affiche le résultat.
static void worker() {
    //Ici, on utilise une boucle infinie pour que chaque thread continue à scanner les ports jusqu'à ce qu'il n'y ait plus de ports à scanner. On utilise g_next_port.fetch_add(1) pour obtenir le prochain port à scanner de manière atomique, ce qui évite les conditions de course entre les threads.
    while (true) {
        int port = g_next_port.fetch_add(1);
        if (port > g_end_port) 
        break;
        
        //Ici, on appelle la fonction scan_port pour tenter de se connecter au port. Si le port est ouvert, on incrémente le compteur de ports ouverts et on affiche le résultat. On utilise un mutex pour protéger l'accès à std::cout, afin d'éviter que plusieurs threads n'écrivent en même temps dans la console.
        if (scan_port(g_ip, port)) {
            g_open_count.fetch_add(1);
            std::lock_guard<std::mutex> lock(g_cout_mutex);
            std::cout << "[+] " << port << "/tcp\topen\t"
                      << guess_service(port) << "\n";
        }
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0]
                  << " <host> [start_port=1] [end_port=1024] [threads=100]\n";
        return 1;
    }

    std::string host=argv[1];

    int start_port= (argc > 2) ? std::stoi(argv[2]) : 1;

    g_end_port= (argc > 3) ? std::stoi(argv[3]) : 1024;
    
    int thread_count= (argc > 4) ? std::stoi(argv[4]) : 100;

//Verificaion de la validité des ports
    if (start_port < 1 || g_end_port > 65535 || start_port > g_end_port) {
        std::cerr << "Invalid port range.\n";
        return 1;
    }
//On appelle la fonction resolve_host pour obtenir l'adresse IP de l'hôte. Si la résolution échoue, on affiche un message d'erreur et on quitte le programme.
    if (!resolve_host(host, g_ip)) {
        std::cerr << "Could not resolve host: " << host << "\n";
        return 1;
    }
//On affiche les informations sur le scan en cours, y compris l'hôte, l'adresse IP, la plage de ports et le nombre de threads utilisés. On utilise std::chrono pour mesurer le temps écoulé pendant le scan.
    std::cout << "Scanning " << host << " (" << g_ip << ") "
              << "ports " << start_port << "-" << g_end_port
              << " with " << thread_count << " threads\n";
    std::cout << "----------------------------------------\n";
//Ici, on initialise g_next_port avec le port de départ et on enregistre l'heure de début du scan. Ensuite, on crée un vecteur de threads et on lance chaque thread en appelant la fonction worker. 
//Après avoir lancé tous les threads, on attend qu'ils se terminent en appelant join() sur chacun d'eux. Enfin, on calcule le temps écoulé depuis le début du scan et on affiche le nombre de ports ouverts trouvés ainsi que le temps total écoulé.
    g_next_port.store(start_port);
    auto t0 = std::chrono::steady_clock::now();

//On utilise un vecteur de threads pour gérer le pool de threads. On réserve la taille du vecteur pour éviter les reallocations, puis on utilise emplace_back pour créer chaque thread en appelant la fonction worker.
    std::vector<std::thread> pool;
    pool.reserve(thread_count);
    for (int i = 0; i < thread_count; ++i) pool.emplace_back(worker);
    for (auto& t : pool) t.join();

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now() - t0)
                       .count();

    std::cout << "----------------------------------------\n";
    std::cout << "Done. " << g_open_count.load() << " open port(s) in "
              << elapsed << " ms\n";
    return 0;
}
